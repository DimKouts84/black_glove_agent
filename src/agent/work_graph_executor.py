"""
Deterministic work-graph execution kernel with optional parallel scheduling.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from agent.audit import write_audit
from agent.engagement_store import EngagementStore
from agent.execution_context import ExecutionContext
from agent.llm_factory import LLMClientFactory, create_llm_factory
from agent.models import ConfigModel
from agent.plan_validator import PlanValidationError, validate_scan_plan
from agent.plugin_manager import PluginManager
from agent.policy_engine import PolicyEngine
from agent.reducer import AnalysisReducer
from agent.tool_result import ToolResultEnvelope
from agent.tool_risk import (
    check_exploit_gate,
    get_tool_risk,
    phase_allows_tool,
    requires_approval,
)
from agent.worker_models import FanInBatch, WorkerKind, WorkerResult, WorkerTask
from agent.worker_pool import BoundedWorkerPool
from agent.work_graph import (
    Engagement,
    EngagementBudget,
    EngagementStatus,
    FailurePolicy,
    PHASE_ORDER,
    StepStatus,
    WorkGraph,
    WorkPhase,
    WorkStep,
)

logger = logging.getLogger("black_glove.work_graph_executor")

ApprovalCallback = Callable[[str, Dict[str, Any]], Awaitable[bool]]
ActivityCallback = Callable[[Dict[str, Any]], None]

TERMINAL = {
    StepStatus.COMPLETED,
    StepStatus.FAILED,
    StepStatus.SKIPPED,
    StepStatus.BLOCKED,
    StepStatus.CANCELLED,
}


class WorkGraphExecutor:
    """Execute persisted work graphs with governance."""

    def __init__(
        self,
        plugin_manager: PluginManager,
        policy_engine: PolicyEngine,
        store: Optional[EngagementStore] = None,
        *,
        require_approval: bool = False,
        safe_tools: Optional[Set[str]] = None,
        enable_exploit_adapters: bool = False,
        require_lab_mode_for_exploits: bool = True,
        enable_parallel_workers: bool = False,
        config: Optional[ConfigModel] = None,
    ):
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.store = store or EngagementStore()
        self.require_approval = require_approval
        self.safe_tools = safe_tools or set()
        self.enable_exploit_adapters = enable_exploit_adapters
        self.require_lab_mode_for_exploits = require_lab_mode_for_exploits
        self.enable_parallel_workers = enable_parallel_workers
        self.config = config
        self._cancel_events: Dict[str, asyncio.Event] = {}

    def cancel(self, graph_id: str) -> None:
        self.store.mark_cancelled(graph_id)
        event = self._cancel_events.get(graph_id)
        if event:
            event.set()

    def _cancel_event(self, graph_id: str) -> asyncio.Event:
        if graph_id not in self._cancel_events:
            self._cancel_events[graph_id] = asyncio.Event()
        return self._cancel_events[graph_id]

    def _step_map(self, graph: WorkGraph) -> Dict[str, WorkStep]:
        return {s.id: s for s in graph.steps}

    def _dependencies_met(self, step: WorkStep, graph: WorkGraph) -> bool:
        if not step.depends_on:
            return True
        steps = self._step_map(graph)
        return all(steps[dep].status == StepStatus.COMPLETED for dep in step.depends_on)

    def _propagate_failures(self, graph: WorkGraph) -> None:
        steps = self._step_map(graph)
        changed = True
        while changed:
            changed = False
            for step in graph.steps:
                if step.status != StepStatus.PENDING:
                    continue
                for dep_id in step.depends_on:
                    dep = steps[dep_id]
                    if dep.status in {StepStatus.FAILED, StepStatus.BLOCKED, StepStatus.CANCELLED}:
                        if not step.continue_on_failure:
                            step.status = StepStatus.BLOCKED
                            step.error = f"dependency_failed:{dep_id}"
                            changed = True
                            break

    def _ready_steps(self, graph: WorkGraph) -> List[WorkStep]:
        ready: List[WorkStep] = []
        for step in graph.steps:
            if step.status != StepStatus.PENDING:
                continue
            if step.phase != graph.current_phase:
                continue
            if graph.strict_sequential and ready:
                break
            if self._dependencies_met(step, graph):
                ready.append(step)
        ready.sort(key=lambda s: (s.plan_index, s.id))
        return ready

    def _phase_complete(self, graph: WorkGraph) -> bool:
        phase_steps = [s for s in graph.steps if s.phase == graph.current_phase]
        if not phase_steps:
            return True
        return all(s.status in TERMINAL for s in phase_steps)

    def _advance_phase(self, graph: WorkGraph) -> bool:
        try:
            idx = PHASE_ORDER.index(graph.current_phase)
        except ValueError:
            return False
        if idx + 1 >= len(PHASE_ORDER):
            return False
        graph.current_phase = PHASE_ORDER[idx + 1]
        return True

    async def execute_step(
        self,
        step: WorkStep,
        engagement: Engagement,
        ctx: ExecutionContext,
    ) -> ToolResultEnvelope:
        params = dict(step.parameters)
        if step.target and "target" not in params:
            params["target"] = step.target
        if step.target and "domain" not in params:
            params.setdefault("domain", step.target)

        exploit_err = check_exploit_gate(
            step.tool,
            enable_exploit_adapters=self.enable_exploit_adapters,
            require_lab_mode_for_exploits=self.require_lab_mode_for_exploits,
            lab_mode=engagement.lab_mode,
        )
        if exploit_err:
            write_audit("policy_block", {"tool": step.tool, "target": step.target, "reason": exploit_err})
            return ToolResultEnvelope(
                status="blocked", tool_name=step.tool, summary=exploit_err, error=exploit_err, retryable=False
            )

        if not phase_allows_tool(step.phase.value, step.tool):
            msg = f"Phase '{step.phase.value}' does not allow tool '{step.tool}'."
            write_audit("phase_block", {"tool": step.tool, "phase": step.phase.value, "reason": msg})
            return ToolResultEnvelope(status="blocked", tool_name=step.tool, summary=msg, error=msg)

        if self.require_approval and requires_approval(step.tool, self.safe_tools):
            if not ctx.approval_callback:
                return ToolResultEnvelope(
                    status="blocked",
                    tool_name=step.tool,
                    summary=f"Approval required for {step.tool}",
                    error="approval_denied",
                )
            ctx.emit("approval_request", f"Approve {step.tool}?", params=params)
            approved = await ctx.approval_callback(step.tool, params)
            if not approved:
                return ToolResultEnvelope(
                    status="blocked",
                    tool_name=step.tool,
                    summary=f"Approval denied for {step.tool}",
                    error="approval_denied",
                )

        write_audit(
            "tool_attempt",
            {
                "tool": step.tool,
                "target": step.target,
                "params": params,
                "engagement_id": engagement.id,
                "run_id": ctx.run_id,
                "step_id": step.id,
            },
        )
        ctx.emit("tool_call", step.tool, step_id=step.id, params=params)

        try:
            from agent.tools.adapter_wrapper import AdapterToolWrapper

            wrapper = AdapterToolWrapper(step.tool, self.plugin_manager)
            raw = await asyncio.to_thread(wrapper.execute, params)
            envelope = ToolResultEnvelope.from_raw(step.tool, raw)
            write_audit(
                "tool_result",
                {
                    "tool": step.tool,
                    "target": step.target,
                    "status": envelope.status,
                    "summary": envelope.summary,
                    "engagement_id": engagement.id,
                    "run_id": ctx.run_id,
                    "step_id": step.id,
                },
            )
            ctx.emit(
                "tool_result",
                envelope.summary[:500],
                step_id=step.id,
                params={"tool": step.tool, "status": envelope.status},
            )
            return envelope
        except Exception as exc:
            logger.error("Step %s failed: %s", step.name, exc)
            write_audit("tool_error", {"tool": step.tool, "target": step.target, "error": str(exc), "step_id": step.id})
            return ToolResultEnvelope(
                status="error", tool_name=step.tool, summary=str(exc), error=str(exc), retryable=True
            )

    def _apply_worker_result(self, step: WorkStep, graph: WorkGraph, result: WorkerResult) -> None:
        step.finished_at = datetime.now().isoformat()
        step.result_digest = result.envelope.summary[:2000]
        step.error = result.error
        step.evidence_paths = result.evidence_paths
        step.finding_ids = result.finding_ids

        if result.status == "success":
            step.status = StepStatus.COMPLETED
            if step.id not in graph.completed_step_ids:
                graph.completed_step_ids.append(step.id)
        elif result.status == "blocked":
            step.status = StepStatus.BLOCKED
        elif result.status == "cancelled":
            step.status = StepStatus.CANCELLED
        else:
            step.status = StepStatus.FAILED
            if step.retry_count < step.max_retries and result.envelope.retryable:
                step.retry_count += 1
                step.status = StepStatus.PENDING
                step.error = None

    def _apply_envelope(self, step: WorkStep, graph: WorkGraph, envelope: ToolResultEnvelope) -> None:
        step.finished_at = datetime.now().isoformat()
        step.result_digest = envelope.summary[:2000]
        step.error = envelope.error
        step.evidence_paths = envelope.evidence_paths
        step.finding_ids = envelope.finding_ids

        if envelope.status == "success":
            step.status = StepStatus.COMPLETED
            if step.id not in graph.completed_step_ids:
                graph.completed_step_ids.append(step.id)
        elif envelope.status == "blocked":
            step.status = StepStatus.BLOCKED
        else:
            step.status = StepStatus.FAILED
            if step.retry_count < step.max_retries and envelope.retryable:
                step.retry_count += 1
                step.status = StepStatus.PENDING

    async def _run_parallel(
        self,
        graph: WorkGraph,
        engagement: Engagement,
        ctx: ExecutionContext,
        budget: EngagementBudget,
        start: float,
    ) -> None:
        llm_factory = create_llm_factory(self.config) if self.config else None
        pool = BoundedWorkerPool(
            self.plugin_manager,
            limits=graph.concurrency_limits,
            require_approval=self.require_approval,
            safe_tools=self.safe_tools,
            llm_factory=llm_factory,
            enable_exploit_adapters=self.enable_exploit_adapters,
            require_lab_mode_for_exploits=self.require_lab_mode_for_exploits,
        )
        reducer = AnalysisReducer(llm_factory=llm_factory)
        in_flight: Dict[asyncio.Task, WorkStep] = {}
        graph_lock = asyncio.Lock()

        while True:
            if graph.cancelled or ctx.is_cancelled():
                graph.status = EngagementStatus.CANCELLED
                break

            budget.wall_seconds = time.monotonic() - start
            if not budget.within_limits(engagement):
                graph.status = EngagementStatus.PAUSED
                break

            self._propagate_failures(graph)

            if self._phase_complete(graph):
                if not self._advance_phase(graph):
                    break
                continue

            ready = self._ready_steps(graph)
            if not ready and not in_flight:
                pending = [s for s in graph.steps if s.status == StepStatus.PENDING]
                if pending:
                    raise RuntimeError("Work graph deadlock: pending steps with empty ready set")
                break

            while ready and len(in_flight) < graph.concurrency_limits.max_concurrent_global:
                step = ready.pop(0)
                step.status = StepStatus.RUNNING
                step.started_at = datetime.now().isoformat()
                kind = WorkerKind(step.worker_kind) if step.worker_kind in WorkerKind._value2member_map_ else WorkerKind.ADAPTER
                task = WorkerTask(
                    graph_id=graph.id,
                    step_id=step.id,
                    engagement_id=engagement.id,
                    run_id=ctx.run_id,
                    session_id=ctx.session_id,
                    kind=kind,
                    tool_name=step.tool,
                    target=step.target,
                    parameters=dict(step.parameters),
                    phase=step.phase.value,
                    parallel_group=step.parallel_group,
                    shard_key=step.analysis_shard_key,
                    attempt=step.retry_count + 1,
                    max_wall_seconds=step.timeout_seconds,
                    rationale=step.rationale,
                )
                worker_coro = pool.execute_task(task, ctx, lab_mode=engagement.lab_mode)
                in_flight[asyncio.create_task(worker_coro)] = step
                if graph.strict_sequential:
                    break

            if not in_flight:
                await asyncio.sleep(0.05)
                continue

            done, _pending = await asyncio.wait(in_flight.keys(), return_when=asyncio.FIRST_COMPLETED)
            async with graph_lock:
                for finished in done:
                    step = in_flight.pop(finished)
                    try:
                        result: WorkerResult = finished.result()
                    except Exception as exc:
                        result = WorkerResult(
                            task_id=step.id,
                            step_id=step.id,
                            status="error",
                            envelope=ToolResultEnvelope(
                                status="error",
                                tool_name=step.tool,
                                summary=str(exc),
                                error=str(exc),
                                retryable=True,
                            ),
                            error=str(exc),
                        )
                    self._apply_worker_result(step, graph, result)
                    budget.steps_executed += 1
                    if ctx.session_id:
                        self.store.save_step_summary(
                            session_id=ctx.session_id,
                            run_id=ctx.run_id,
                            tool_name=step.tool,
                            target=step.target,
                            status=step.status.value,
                            summary=result.envelope.summary,
                            evidence_paths=result.evidence_paths,
                            finding_ids=result.finding_ids,
                        )
                    rev = graph.revision
                    try:
                        self.store.save_work_graph_cas(graph, rev)
                    except ValueError:
                        graph = self.store.get_work_graph(graph.id) or graph

            if graph.failure_policy == FailurePolicy.FAIL_FAST:
                failed = [s for s in graph.steps if s.status == StepStatus.FAILED]
                if failed:
                    break

        for task in list(in_flight.keys()):
            task.cancel()
        if in_flight:
            await asyncio.gather(*in_flight.keys(), return_exceptions=True)

        analysis_steps = [s for s in graph.steps if s.phase == WorkPhase.ANALYSIS and s.status == StepStatus.PENDING]
        if analysis_steps and not graph.cancelled:
            batch = FanInBatch(graph_id=graph.id, shard_key="default")
            await reducer.reduce(batch)

    async def _run_sequential(
        self,
        graph: WorkGraph,
        engagement: Engagement,
        ctx: ExecutionContext,
        budget: EngagementBudget,
        start: float,
    ) -> None:
        while True:
            progressed = False
            for step in graph.steps:
                if graph.cancelled or ctx.is_cancelled():
                    graph.status = EngagementStatus.CANCELLED
                    return

                budget.wall_seconds = time.monotonic() - start
                if not budget.within_limits(engagement):
                    graph.status = EngagementStatus.PAUSED
                    return

                if step.status in TERMINAL:
                    continue
                if not self._dependencies_met(step, graph):
                    continue

                step.status = StepStatus.RUNNING
                step.started_at = datetime.now().isoformat()
                self.store.save_work_graph(graph)

                envelope = await self.execute_step(step, engagement, ctx)
                self._apply_envelope(step, graph, envelope)
                budget.steps_executed += 1
                self.store.save_work_graph(graph)
                progressed = True

                if ctx.session_id:
                    self.store.save_step_summary(
                        session_id=ctx.session_id,
                        run_id=ctx.run_id,
                        tool_name=step.tool,
                        target=step.target,
                        status=step.status.value,
                        summary=envelope.summary,
                        evidence_paths=envelope.evidence_paths,
                        finding_ids=envelope.finding_ids,
                    )

            if not progressed:
                break

    async def run_graph(
        self,
        graph: WorkGraph,
        engagement: Engagement,
        *,
        run_id: Optional[str] = None,
        session_id: Optional[str] = None,
        on_activity: Optional[ActivityCallback] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ) -> WorkGraph:
        budget = EngagementBudget(started_at=datetime.now().isoformat())
        start = time.monotonic()
        graph.status = EngagementStatus.RUNNING
        engagement.status = EngagementStatus.RUNNING
        self.store.save_engagement(engagement)
        self.store.save_work_graph(graph)

        cancel_event = self._cancel_event(graph.id)
        if graph.cancelled:
            cancel_event.set()

        ctx = ExecutionContext(
            session_id=session_id or graph.session_id or "",
            run_id=run_id or graph.run_id or "",
            on_activity=on_activity,
            approval_callback=approval_callback,
            engagement_id=engagement.id,
            graph_id=graph.id,
            cancel_event=cancel_event,
        )

        write_audit(
            "work_graph_start",
            {
                "graph_id": graph.id,
                "engagement_id": engagement.id,
                "goal": graph.goal,
                "step_count": len(graph.steps),
                "parallel": self.enable_parallel_workers,
            },
        )

        if self.enable_parallel_workers and not graph.strict_sequential:
            await self._run_parallel(graph, engagement, ctx, budget, start)
        else:
            await self._run_sequential(graph, engagement, ctx, budget, start)

        budget.wall_seconds = time.monotonic() - start
        pending = [s for s in graph.steps if s.status == StepStatus.PENDING]
        blocked = [s for s in graph.steps if s.status == StepStatus.BLOCKED]
        failed = [s for s in graph.steps if s.status == StepStatus.FAILED]

        if graph.status not in {EngagementStatus.CANCELLED, EngagementStatus.PAUSED}:
            if blocked or failed:
                graph.status = EngagementStatus.FAILED
            elif pending:
                graph.status = EngagementStatus.PAUSED
            else:
                graph.status = EngagementStatus.COMPLETED

        engagement.status = graph.status
        self.store.save_work_graph(graph)
        self.store.save_engagement(engagement)

        write_audit(
            "work_graph_complete",
            {
                "graph_id": graph.id,
                "status": graph.status.value,
                "completed": len(graph.completed_step_ids),
                "failed": len(failed),
                "blocked": len(blocked),
            },
        )
        self._cancel_events.pop(graph.id, None)
        return graph

    async def resume_graph(
        self,
        graph_id: str,
        *,
        run_id: Optional[str] = None,
        session_id: Optional[str] = None,
        on_activity: Optional[ActivityCallback] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ) -> WorkGraph:
        graph = self.store.get_work_graph(graph_id)
        if not graph:
            raise ValueError(f"Work graph not found: {graph_id}")
        engagement = self.store.get_engagement(graph.engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {graph.engagement_id}")
        for step in graph.steps:
            if step.status == StepStatus.RUNNING:
                step.status = StepStatus.PENDING
        return await self.run_graph(
            graph,
            engagement,
            run_id=run_id,
            session_id=session_id,
            on_activity=on_activity,
            approval_callback=approval_callback,
        )

    @staticmethod
    def from_scan_plan(
        scan_plan: Dict[str, Any],
        engagement_id: str,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        engagement_targets: Optional[List[str]] = None,
    ) -> WorkGraph:
        """Materialize a validated planner ScanPlan into a WorkGraph."""
        graph, _steps = validate_scan_plan(
            scan_plan,
            engagement_targets=engagement_targets or [
                s.get("target") for s in scan_plan.get("steps", []) if s.get("target")
            ],
        )
        graph.engagement_id = engagement_id
        graph.session_id = session_id
        graph.run_id = run_id
        return graph
