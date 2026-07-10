"""Tests for parallel agent orchestration."""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent.db import get_db_connection, init_db
from agent.engagement_store import EngagementStore
from agent.execution_context import ExecutionContext
from agent.plan_validator import PlanValidationError, validate_scan_plan
from agent.policy_engine import RateLimiter
from agent.work_graph import ConcurrencyLimits, Engagement, EngagementStatus, StepStatus, WorkGraph, WorkPhase, WorkStep
from agent.work_graph_executor import WorkGraphExecutor


@pytest.fixture
def temp_db(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        monkeypatch.setattr("agent.db.DB_PATH", db_path)
        init_db()
        yield db_path
        import gc

        gc.collect()


def test_validate_scan_plan_resolves_dependencies():
    plan = {
        "goal": "recon",
        "steps": [
            {"step_key": "dns", "tool": "dns_lookup", "target": "example.com", "parameters": {}, "rationale": "dns"},
            {
                "step_key": "scan",
                "tool": "nmap",
                "target": "example.com",
                "parameters": {},
                "rationale": "scan",
                "depends_on": ["dns"],
            },
        ],
    }
    graph, steps = validate_scan_plan(plan, engagement_targets=["example.com"])
    assert len(steps) == 2
    scan = next(s for s in steps if s.step_key == "scan")
    dns = next(s for s in steps if s.step_key == "dns")
    assert scan.depends_on == [dns.id]


def test_validate_scan_plan_rejects_cycle():
    plan = {
        "goal": "bad",
        "steps": [
            {"step_key": "a", "tool": "dns_lookup", "target": "x.com", "parameters": {}, "rationale": "", "depends_on": ["b"]},
            {"step_key": "b", "tool": "whois", "target": "x.com", "parameters": {}, "rationale": "", "depends_on": ["a"]},
        ],
    }
    with pytest.raises(PlanValidationError):
        validate_scan_plan(plan, engagement_targets=["x.com"])


def test_rate_limiter_atomic_acquire():
    limiter = RateLimiter({"window_size": 60, "max_requests": 2, "global_max_requests": 100})
    assert limiter.acquire_and_record("nmap") is True
    assert limiter.acquire_and_record("nmap") is True
    assert limiter.acquire_and_record("nmap") is False


def test_rate_limiter_thread_safe():
    limiter = RateLimiter({"window_size": 60, "max_requests": 50, "global_max_requests": 100})
    results = []

    def worker():
        results.append(limiter.acquire_and_record("tool"))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) <= 50


def test_work_graph_cas_conflict(temp_db):
    store = EngagementStore()
    engagement = Engagement(name="test", targets=["example.com"])
    store.save_engagement(engagement)
    graph = WorkGraph(engagement_id=engagement.id, goal="g", steps=[])
    store.save_work_graph(graph)
    graph.goal = "updated"
    store.save_work_graph_cas(graph, 1)
    with pytest.raises(ValueError):
        store.save_work_graph_cas(graph, 1)


def test_sequential_executor_respects_dependencies(temp_db):
    pm = MagicMock()
    policy = MagicMock()
    store = EngagementStore()
    executor = WorkGraphExecutor(pm, policy, store=store, require_approval=False)

    engagement = Engagement(name="e", targets=["example.com"])
    store.save_engagement(engagement)

    step_a = WorkStep(name="a", tool="dns_lookup", target="example.com", plan_index=0)
    step_b = WorkStep(name="b", tool="whois", target="example.com", plan_index=1, depends_on=[step_a.id])
    graph = WorkGraph(engagement_id=engagement.id, goal="test", steps=[step_b, step_a])

    from agent.tool_result import ToolResultEnvelope

    async def fake_execute(step, engagement, ctx):
        return ToolResultEnvelope(status="success", tool_name=step.tool, summary="ok")

    executor.execute_step = fake_execute  # type: ignore

    result = asyncio.run(
        executor.run_graph(graph, engagement, session_id="sess", run_id="run1")
    )
    assert result.status == EngagementStatus.COMPLETED
    assert len(result.completed_step_ids) == 2


def test_parallel_scheduler_completes_independent_steps(temp_db):
    pm = MagicMock()
    policy = MagicMock()
    store = EngagementStore()
    executor = WorkGraphExecutor(
        pm, policy, store=store, require_approval=False, enable_parallel_workers=True
    )

    engagement = Engagement(name="e", targets=["a.com", "b.com"])
    store.save_engagement(engagement)

    steps = [
        WorkStep(
            name=f"s{i}",
            tool="dns_lookup",
            target=f"{t}.com",
            phase=WorkPhase.PASSIVE,
            plan_index=i,
            parallel_group="recon",
        )
        for i, t in enumerate(["a", "b", "c"])
    ]
    graph = WorkGraph(
        engagement_id=engagement.id,
        goal="parallel",
        steps=steps,
        concurrency_limits=ConcurrencyLimits(max_concurrent_global=3, max_concurrent_passive=3),
    )

    from agent import worker_pool

    call_times: list[float] = []

    from unittest.mock import AsyncMock, patch

    async def slow_execute(self, task, ctx, *, lab_mode=False):
        from agent.worker_models import WorkerResult
        from agent.tool_result import ToolResultEnvelope

        call_times.append(time.monotonic())
        await asyncio.sleep(0.05)
        return WorkerResult(
            task_id=task.task_id,
            step_id=task.step_id,
            status="success",
            envelope=ToolResultEnvelope(status="success", tool_name=task.tool_name, summary="ok"),
        )

    with patch.object(worker_pool.BoundedWorkerPool, "execute_task", new=slow_execute):
        result = asyncio.run(
            executor.run_graph(graph, engagement, session_id="sess", run_id="run2")
        )
        assert result.status == EngagementStatus.COMPLETED
        assert len(result.completed_step_ids) == 3
        if len(call_times) >= 2:
            assert call_times[1] - call_times[0] < 0.15


def test_cancel_scan_marks_graph_cancelled(temp_db):
    store = EngagementStore()
    engagement = Engagement(name="e", targets=["example.com"])
    store.save_engagement(engagement)
    graph = WorkGraph(engagement_id=engagement.id, goal="g", steps=[])
    store.save_work_graph(graph)

    executor = WorkGraphExecutor(MagicMock(), MagicMock(), store=store)
    executor.cancel(graph.id)
    loaded = store.get_work_graph(graph.id)
    assert loaded is not None
    assert loaded.cancelled is True


def test_execution_context_emit():
    events = []

    ctx = ExecutionContext(
        session_id="s1",
        run_id="r1",
        on_activity=lambda e: events.append(e),
    )
    ctx.emit("tool_call", "nmap", agent="work_graph")
    assert events[0]["type"] == "tool_call"
    assert events[0]["run_id"] == "r1"
