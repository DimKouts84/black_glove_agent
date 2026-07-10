"""
Bounded worker pool for parallel work-graph execution.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Optional, Set

from agent.audit import write_audit
from agent.execution_context import ExecutionContext, WorkerContext
from agent.llm_factory import LLMClientFactory
from agent.plugin_manager import PluginManager
from agent.subagent_tool import create_researcher_worker, create_analyst_worker
from agent.target_scope import strip_host
from agent.tool_result import ToolResultEnvelope
from agent.tools.adapter_wrapper import AdapterToolWrapper
from agent.tool_risk import requires_approval
from agent.worker_models import WorkerKind, WorkerResult, WorkerTask
from agent.work_graph import ConcurrencyLimits, WorkPhase

logger = logging.getLogger("black_glove.worker_pool")

ApprovalCallback = Callable[[str, Dict[str, Any]], Awaitable[bool]]


class BoundedWorkerPool:
    """Dispatch worker tasks with phase, target, LLM, and approval controls."""

    def __init__(
        self,
        plugin_manager: PluginManager,
        *,
        limits: ConcurrencyLimits,
        require_approval: bool = False,
        safe_tools: Optional[Set[str]] = None,
        llm_factory: Optional[LLMClientFactory] = None,
        enable_exploit_adapters: bool = False,
        require_lab_mode_for_exploits: bool = True,
    ):
        self.plugin_manager = plugin_manager
        self.limits = limits
        self.require_approval = require_approval
        self.safe_tools = safe_tools or set()
        self.llm_factory = llm_factory
        self.enable_exploit_adapters = enable_exploit_adapters
        self.require_lab_mode_for_exploits = require_lab_mode_for_exploits

        self._global_sem = asyncio.Semaphore(limits.max_concurrent_global)
        self._phase_sems: Dict[str, asyncio.Semaphore] = {
            WorkPhase.PASSIVE.value: asyncio.Semaphore(limits.max_concurrent_passive),
            WorkPhase.ACTIVE.value: asyncio.Semaphore(limits.max_concurrent_active),
            WorkPhase.CREDENTIAL.value: asyncio.Semaphore(limits.max_concurrent_credential),
            WorkPhase.EXPLOIT.value: asyncio.Semaphore(limits.max_concurrent_exploit),
            WorkPhase.ANALYSIS.value: asyncio.Semaphore(limits.max_concurrent_llm_workers),
            WorkPhase.REPORT.value: asyncio.Semaphore(1),
        }
        self._target_sems: Dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(limits.max_concurrent_active_per_target)
        )
        self._approval_lock = asyncio.Lock()
        self._adapter_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @asynccontextmanager
    async def _acquire_slots(self, task: WorkerTask):
        await self._global_sem.acquire()
        phase_sem = self._phase_sems.get(task.phase, self._phase_sems[WorkPhase.ACTIVE.value])
        await phase_sem.acquire()
        target_sem = None
        if task.phase in {WorkPhase.ACTIVE.value, WorkPhase.CREDENTIAL.value, WorkPhase.EXPLOIT.value}:
            key = strip_host(task.target) if task.target else "_none_"
            target_sem = self._target_sems[key]
            await target_sem.acquire()
        try:
            yield
        finally:
            if target_sem:
                target_sem.release()
            phase_sem.release()
            self._global_sem.release()

    async def _request_approval(
        self,
        ctx: ExecutionContext,
        tool_name: str,
        params: Dict[str, Any],
    ) -> bool:
        if not self.require_approval:
            return True
        if not requires_approval(tool_name, self.safe_tools):
            return True
        if not ctx.approval_callback:
            return False
        async with self._approval_lock:
            ctx.emit("approval_request", f"Approve {tool_name}?", params=params)
            approved = await ctx.approval_callback(tool_name, params)
            ctx.emit(
                "approval_resolved",
                "approved" if approved else "rejected",
                params={"tool": tool_name, "approved": approved},
            )
            write_audit(
                "approval_decision",
                {"tool": tool_name, "params": params, "approved": approved},
            )
            return approved

    async def execute_task(
        self,
        task: WorkerTask,
        ctx: ExecutionContext,
        *,
        lab_mode: bool = False,
    ) -> WorkerResult:
        worker_ctx = WorkerContext.create(
            ctx,
            step_id=task.step_id,
            parallel_group=task.parallel_group,
            shard_key=task.shard_key,
            attempt=task.attempt,
        )
        started = datetime.now().isoformat()
        worker_ctx.emit("worker_start", task.tool_name, params=task.parameters)

        if ctx.is_cancelled():
            return WorkerResult(
                task_id=task.task_id,
                step_id=task.step_id,
                status="cancelled",
                envelope=ToolResultEnvelope(
                    status="blocked",
                    tool_name=task.tool_name,
                    summary="Cancelled",
                    error="cancelled",
                ),
                error="cancelled",
                started_at=started,
                finished_at=datetime.now().isoformat(),
                worker_instance_id=worker_ctx.worker_instance_id,
            )

        if not await self._request_approval(ctx, task.tool_name, task.parameters):
            return WorkerResult(
                task_id=task.task_id,
                step_id=task.step_id,
                status="blocked",
                envelope=ToolResultEnvelope(
                    status="blocked",
                    tool_name=task.tool_name,
                    summary="Approval denied",
                    error="approval_denied",
                ),
                error="approval_denied",
                started_at=started,
                finished_at=datetime.now().isoformat(),
                worker_instance_id=worker_ctx.worker_instance_id,
            )

        async with self._acquire_slots(task):
            try:
                envelope, structured = await asyncio.wait_for(
                    self._run_worker(task, worker_ctx, lab_mode=lab_mode),
                    timeout=task.max_wall_seconds,
                )
                status = "success" if envelope.status == "success" else "error"
                if envelope.status == "blocked":
                    status = "blocked"
                result = WorkerResult(
                    task_id=task.task_id,
                    step_id=task.step_id,
                    status=status,
                    envelope=envelope,
                    structured_output=structured,
                    evidence_paths=envelope.evidence_paths,
                    finding_ids=envelope.finding_ids,
                    error=envelope.error,
                    started_at=started,
                    finished_at=datetime.now().isoformat(),
                    worker_instance_id=worker_ctx.worker_instance_id,
                )
                worker_ctx.emit("worker_complete", envelope.summary[:500], status=status)
                return result
            except asyncio.TimeoutError:
                worker_ctx.emit("worker_timeout", task.tool_name)
                return WorkerResult(
                    task_id=task.task_id,
                    step_id=task.step_id,
                    status="timeout",
                    envelope=ToolResultEnvelope(
                        status="error",
                        tool_name=task.tool_name,
                        summary="Worker timeout",
                        error="timeout",
                        retryable=True,
                    ),
                    error="timeout",
                    started_at=started,
                    finished_at=datetime.now().isoformat(),
                    worker_instance_id=worker_ctx.worker_instance_id,
                )
            except asyncio.CancelledError:
                return WorkerResult(
                    task_id=task.task_id,
                    step_id=task.step_id,
                    status="cancelled",
                    envelope=ToolResultEnvelope(
                        status="blocked",
                        tool_name=task.tool_name,
                        summary="Cancelled",
                        error="cancelled",
                    ),
                    error="cancelled",
                    started_at=started,
                    finished_at=datetime.now().isoformat(),
                    worker_instance_id=worker_ctx.worker_instance_id,
                )

    async def _run_worker(
        self,
        task: WorkerTask,
        worker_ctx: WorkerContext,
        *,
        lab_mode: bool,
    ) -> tuple[ToolResultEnvelope, Optional[Dict[str, Any]]]:
        if task.kind == WorkerKind.RESEARCHER and self.llm_factory:
            return await create_researcher_worker(
                self.llm_factory,
                task,
                worker_ctx,
                require_approval=self.require_approval,
                safe_tools=self.safe_tools,
            )
        if task.kind == WorkerKind.ANALYST and self.llm_factory:
            return await create_analyst_worker(
                self.llm_factory,
                task,
                worker_ctx,
            )

        async with self._adapter_locks[task.tool_name]:
            wrapper = AdapterToolWrapper(task.tool_name, self.plugin_manager)
            params = dict(task.parameters)
            if task.target and "target" not in params:
                params["target"] = task.target
            raw = await asyncio.to_thread(wrapper.execute, params)
            envelope = ToolResultEnvelope.from_raw(task.tool_name, raw)
            write_audit(
                "tool_result",
                {
                    "tool": task.tool_name,
                    "target": task.target,
                    "status": envelope.status,
                    "task_id": task.task_id,
                    "step_id": task.step_id,
                    "worker_instance_id": worker_ctx.worker_instance_id,
                },
            )
            return envelope, None
