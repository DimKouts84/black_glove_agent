"""
Deterministic work-graph execution kernel.

LLMs propose plans; this module schedules and executes adapter steps with
policy, approval, budgets, checkpointing, and audit guarantees.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from agent.audit import write_audit
from agent.engagement_store import EngagementStore
from agent.plugin_manager import PluginManager
from agent.policy_engine import PolicyEngine
from agent.tool_result import ToolResultEnvelope
from agent.tool_risk import (
    check_exploit_gate,
    get_tool_risk,
    phase_allows_tool,
    requires_approval,
)
from agent.work_graph import (
    Engagement,
    EngagementBudget,
    EngagementStatus,
    StepStatus,
    WorkGraph,
    WorkPhase,
    WorkStep,
)

logger = logging.getLogger("black_glove.work_graph_executor")

ApprovalCallback = Callable[[str, Dict[str, Any]], Awaitable[bool]]
ActivityCallback = Callable[[Dict[str, Any]], None]


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
        approval_callback: Optional[ApprovalCallback] = None,
        on_activity: Optional[ActivityCallback] = None,
        enable_exploit_adapters: bool = False,
        require_lab_mode_for_exploits: bool = True,
    ):
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.store = store or EngagementStore()
        self.require_approval = require_approval
        self.safe_tools = safe_tools or set()
        self.approval_callback = approval_callback
        self.on_activity = on_activity
        self.enable_exploit_adapters = enable_exploit_adapters
        self.require_lab_mode_for_exploits = require_lab_mode_for_exploits
        self._cancelled: Set[str] = set()

    def _emit(self, event_type: str, content: Any, **kwargs) -> None:
        if self.on_activity:
            self.on_activity(
                {"type": event_type, "content": content, "agent": "work_graph", **kwargs}
            )

    def cancel(self, graph_id: str) -> None:
        self._cancelled.add(graph_id)

    def _dependencies_met(self, step: WorkStep, graph: WorkGraph) -> bool:
        if not step.depends_on:
            return True
        completed = set(graph.completed_step_ids)
        return all(dep in completed for dep in step.depends_on)

    async def _request_approval(self, tool_name: str, params: Dict[str, Any]) -> bool:
        if not self.require_approval:
            return True
        if not requires_approval(tool_name, self.safe_tools):
            return True
        if not self.approval_callback:
            return False
        self._emit("approval_request", f"Approve {tool_name}?", tool=tool_name, params=params)
        approved = await self.approval_callback(tool_name, params)
        self._emit(
            "approval_resolved",
            "approved" if approved else "rejected",
            tool=tool_name,
            approved=approved,
        )
        write_audit(
            "approval_decision",
            {"tool": tool_name, "params": params, "approved": approved},
        )
        return approved

    async def execute_step(
        self,
        step: WorkStep,
        engagement: Engagement,
        *,
        run_id: Optional[str] = None,
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
            write_audit(
                "policy_block",
                {"tool": step.tool, "target": step.target, "reason": exploit_err},
            )
            return ToolResultEnvelope(
                status="blocked",
                tool_name=step.tool,
                summary=exploit_err,
                error=exploit_err,
                retryable=False,
            )

        if not phase_allows_tool(step.phase.value, step.tool):
            msg = f"Phase '{step.phase.value}' does not allow tool '{step.tool}'."
            write_audit(
                "phase_block",
                {"tool": step.tool, "phase": step.phase.value, "reason": msg},
            )
            return ToolResultEnvelope(
                status="blocked",
                tool_name=step.tool,
                summary=msg,
                error=msg,
            )

        if not await self._request_approval(step.tool, params):
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
                "run_id": run_id,
                "step_id": step.id,
            },
        )
        self._emit("tool_call", step.tool, params=params)

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
                    "run_id": run_id,
                    "step_id": step.id,
                },
            )
            self._emit(
                "tool_result",
                envelope.summary[:500],
                tool=step.tool,
                status=envelope.status,
                evidence_paths=envelope.evidence_paths,
            )
            return envelope
        except Exception as exc:
            logger.error("Step %s failed: %s", step.name, exc)
            write_audit(
                "tool_error",
                {
                    "tool": step.tool,
                    "target": step.target,
                    "error": str(exc),
                    "step_id": step.id,
                },
            )
            return ToolResultEnvelope(
                status="error",
                tool_name=step.tool,
                summary=str(exc),
                error=str(exc),
                retryable=True,
            )

    async def run_graph(
        self,
        graph: WorkGraph,
        engagement: Engagement,
        *,
        run_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> WorkGraph:
        budget = EngagementBudget(started_at=datetime.now().isoformat())
        start = time.monotonic()
        graph.status = EngagementStatus.RUNNING
        engagement.status = EngagementStatus.RUNNING
        self.store.save_engagement(engagement)
        self.store.save_work_graph(graph)

        write_audit(
            "work_graph_start",
            {
                "graph_id": graph.id,
                "engagement_id": engagement.id,
                "goal": graph.goal,
                "step_count": len(graph.steps),
            },
        )

        for step in graph.steps:
            if graph.id in self._cancelled:
                graph.status = EngagementStatus.CANCELLED
                break

            budget.wall_seconds = time.monotonic() - start
            if not budget.within_limits(engagement):
                logger.warning("Budget exceeded for engagement %s", engagement.id)
                graph.status = EngagementStatus.PAUSED
                break

            if step.status in {StepStatus.COMPLETED, StepStatus.SKIPPED}:
                continue
            if not self._dependencies_met(step, graph):
                step.status = StepStatus.SKIPPED
                step.error = "Unmet dependencies"
                continue

            step.status = StepStatus.RUNNING
            step.started_at = datetime.now().isoformat()
            self.store.save_work_graph(graph)

            envelope = await self.execute_step(step, engagement, run_id=run_id)
            step.finished_at = datetime.now().isoformat()
            step.result_digest = envelope.summary[:2000]
            step.error = envelope.error

            if envelope.status in {"success"}:
                step.status = StepStatus.COMPLETED
                graph.completed_step_ids.append(step.id)
            elif envelope.status == "blocked":
                step.status = StepStatus.BLOCKED
            else:
                step.status = StepStatus.FAILED
                if step.retry_count < step.max_retries and envelope.retryable:
                    step.retry_count += 1
                    step.status = StepStatus.PENDING

            budget.steps_executed += 1
            self.store.save_work_graph(graph)

            if session_id:
                self.store.save_step_summary(
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=step.tool,
                    target=step.target,
                    status=step.status.value,
                    summary=envelope.summary,
                    evidence_paths=envelope.evidence_paths,
                    finding_ids=envelope.finding_ids,
                )

        budget.wall_seconds = time.monotonic() - start
        pending = [s for s in graph.steps if s.status == StepStatus.PENDING]
        blocked = [s for s in graph.steps if s.status == StepStatus.BLOCKED]
        failed = [s for s in graph.steps if s.status == StepStatus.FAILED]

        if graph.status != EngagementStatus.CANCELLED:
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
        """Resume a paused or partially completed work graph."""
        graph = self.store.get_work_graph(graph_id)
        if not graph:
            raise ValueError(f"Work graph not found: {graph_id}")
        engagement = self.store.get_engagement(graph.engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {graph.engagement_id}")
        if on_activity:
            self.on_activity = on_activity
        if approval_callback:
            self.approval_callback = approval_callback
        return await self.run_graph(
            graph,
            engagement,
            run_id=run_id,
            session_id=session_id,
        )

    @staticmethod
    def from_scan_plan(
        scan_plan: Dict[str, Any],
        engagement_id: str,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> WorkGraph:
        """Materialize a planner ScanPlan into a WorkGraph."""
        steps: List[WorkStep] = []
        risk_to_phase = {
            "passive": WorkPhase.PASSIVE,
            "active": WorkPhase.ACTIVE,
            "credential": WorkPhase.CREDENTIAL,
            "exploit": WorkPhase.EXPLOIT,
            "safe": WorkPhase.PASSIVE,
            "report": WorkPhase.REPORT,
            "agent": WorkPhase.ANALYSIS,
        }
        for idx, raw in enumerate(scan_plan.get("steps", [])):
            tool = raw.get("tool", "")
            risk = get_tool_risk(tool)
            phase = risk_to_phase.get(risk.value, WorkPhase.ACTIVE)

            steps.append(
                WorkStep(
                    name=f"{tool}_{raw.get('target', 'target')}_{idx}",
                    tool=tool,
                    target=raw.get("target", ""),
                    parameters=raw.get("parameters", {}),
                    phase=phase,
                    rationale=raw.get("rationale", ""),
                    risk_class=risk.value,
                )
            )
        return WorkGraph(
            engagement_id=engagement_id,
            session_id=session_id,
            run_id=run_id,
            goal=scan_plan.get("goal", "scan"),
            steps=steps,
        )
