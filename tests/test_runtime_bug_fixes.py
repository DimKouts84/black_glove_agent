"""Regression tests for agent-runtime bug fixes (approval, plan handoff, graph)."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from agent.agent_library.analyst import ANALYST_AGENT
from agent.agent_library.planner import PLANNER_AGENT
from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentPromptConfig, AgentToolConfig
from agent.engagement_store import EngagementStore
from agent.execution_provenance import (
    get_turn_approval_callback,
    reset_turn_approval_callback,
    set_turn_approval_callback,
)
from agent.executor import AgentExecutor
from agent.plan_validator import (
    PlanValidationError,
    executable_scan_plan,
    summarize_plan_execution,
    validate_scan_plan,
)
from agent.runtime import warn_planner_completeness
from agent.subagent_tool import SubagentTool
from agent.tool_result import ToolResultEnvelope
from agent.tools.registry import ToolRegistry
from agent.work_graph import (
    ConcurrencyLimits,
    Engagement,
    EngagementStatus,
    FailurePolicy,
    StepStatus,
    WorkGraph,
    WorkPhase,
    WorkStep,
)
from agent.work_graph_executor import WorkGraphExecutor
from agent.db import init_db
from pydantic import BaseModel


@pytest.fixture
def temp_db(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        monkeypatch.setattr("agent.db.DB_PATH", db_path)
        init_db()
        yield db_path
        import gc

        gc.collect()


class FinalAnswer(BaseModel):
    answer: str


def _simple_agent(name: str = "test", tools=None, output_name="final_answer", schema=FinalAnswer):
    return AgentDefinition(
        name=name,
        description="test",
        input_config={"q": AgentInput(description="q")},
        output_config=AgentOutput(output_name=output_name, description="out", schema_model=schema),
        tool_config=AgentToolConfig(tools=tools or []),
        prompt_config=AgentPromptConfig(
            system_prompt="You are a test agent.",
            initial_query_template="Query: ${q} Context: ${context}",
        ),
    )


class TestTurnApprovalContext:
    def test_nested_executor_uses_turn_callback(self):
        calls = []

        async def approve(tool_name, params):
            calls.append(tool_name)
            return True

        token = set_turn_approval_callback(approve)
        try:
            registry = ToolRegistry()

            class DummyTool:
                name = "nmap"

                def get_info(self):
                    return {"name": "nmap", "description": "scan", "parameters": {}}

                async def execute(self, params):
                    return {"ok": True}

            registry.register(DummyTool())
            agent = _simple_agent(tools=["nmap"])
            llm = Mock()
            llm.generate = Mock(
                side_effect=[
                    Mock(
                        content=json.dumps(
                            {
                                "tool": "nmap",
                                "parameters": {"target": "example.com"},
                                "rationale": "scan",
                            }
                        )
                    ),
                    Mock(
                        content=json.dumps(
                            {
                                "tool": "complete_task",
                                "parameters": {"final_answer": {"answer": "done"}},
                                "rationale": "done",
                            }
                        )
                    ),
                ]
            )
            executor = AgentExecutor(
                agent_definition=agent,
                llm_client=llm,
                tool_registry=registry,
                require_approval=True,
                safe_tools={"complete_task"},
                approval_callback=None,
            )
            result = asyncio.run(executor.run({"q": "scan"}))
            assert "final_answer" in result
            assert calls == ["nmap"]
            assert get_turn_approval_callback() is approve
        finally:
            reset_turn_approval_callback(token)


class TestPlanHandoff:
    def test_planner_result_runs_plan_runner(self):
        plan = {
            "goal": "scan example.com",
            "reasoning": "test",
            "steps": [{"tool": "whois", "target": "example.com", "parameters": {}}],
        }
        runner = AsyncMock(
            return_value=summarize_plan_execution(
                {
                    "status": "completed",
                    "steps": [{"tool": "whois", "status": "completed"}],
                }
            )
        )
        registry = ToolRegistry()
        sub = SubagentTool(PLANNER_AGENT, Mock(), registry, require_approval=False)
        sub.execute = AsyncMock(return_value={"scan_plan": plan})
        registry.register(sub)

        class RootOut(BaseModel):
            answer: str

        root = _simple_agent(name="root", tools=["planner_agent"], schema=RootOut)
        llm = Mock()
        llm.generate = Mock(
            side_effect=[
                Mock(
                    content=json.dumps(
                        {
                            "tool": "planner_agent",
                            "parameters": {"goal": "scan"},
                            "rationale": "plan",
                        }
                    )
                ),
                Mock(
                    content=json.dumps(
                        {
                            "tool": "complete_task",
                            "parameters": {"final_answer": {"answer": "ok"}},
                            "rationale": "done",
                        }
                    )
                ),
            ]
        )
        executor = AgentExecutor(
            agent_definition=root,
            llm_client=llm,
            tool_registry=registry,
            require_approval=False,
        )
        executor.plan_runner = runner
        result = asyncio.run(executor.run({"q": "full scan"}))
        assert "final_answer" in result
        runner.assert_awaited_once()
        assert runner.await_args.args[0]["steps"][0]["tool"] == "whois"

    def test_executable_scan_plan_drops_report_and_agents(self):
        plan = {
            "goal": "g",
            "steps": [
                {"tool": "nmap", "target": "t"},
                {"tool": "generate_report", "target": "t"},
                {"tool": "analyst_agent", "target": "t"},
            ],
        }
        filtered = executable_scan_plan(plan)
        assert [s["tool"] for s in filtered["steps"]] == ["nmap"]

    def test_summarize_marks_already_executed(self):
        summary = summarize_plan_execution(
            {
                "status": "completed",
                "steps": [
                    {"tool": "nmap", "status": "completed"},
                    {"tool": "ssl_check", "status": "failed"},
                ],
            }
        )
        assert summary["already_executed"] is True
        assert "nmap" in summary["completed_tools"]
        assert "ssl_check" in summary["failed_tools"]


class TestAnalystContext:
    def test_query_maps_to_context_and_strips_placeholders(self):
        agent = ANALYST_AGENT
        llm = Mock()
        captured = {}

        def capture_generate(messages, **kwargs):
            captured["messages"] = messages
            return Mock(
                content=json.dumps(
                    {
                        "tool": "complete_task",
                        "parameters": {
                            "analysis": {
                                "summary": "ok",
                                "findings": [],
                            }
                        },
                        "rationale": "done",
                    }
                )
            )

        llm.generate = Mock(side_effect=capture_generate)
        registry = ToolRegistry()
        sub = SubagentTool(agent, llm, registry, require_approval=False)
        result = asyncio.run(
            sub.execute({"raw_data": "nmap out", "query": "look for open ports"})
        )
        assert "analysis" in result
        user_msgs = [m.content for m in captured["messages"] if m.role == "user"]
        assert user_msgs
        assert "look for open ports" in user_msgs[0]
        assert "${context}" not in user_msgs[0]

    def test_analysis_body_in_envelope(self):
        data = {
            "analysis": {
                "summary": "Critical issues found",
                "findings": [
                    {"title": "Open RDP", "severity": "high", "description": "x", "remediation": "y"}
                ],
            }
        }
        envelope = ToolResultEnvelope.from_raw("analyst_agent", data)
        assert "Critical issues found" in envelope.summary
        assert "Open RDP" in envelope.summary
        assert "Open RDP" in envelope.raw_digest
        assert "...[digest_truncated]" not in (envelope.raw_digest or "")


class TestPlanRules:
    def test_web_tools_auto_wire_after_nmap(self):
        plan = {
            "goal": "website assessment",
            "steps": [
                {
                    "step_key": "ssl",
                    "tool": "ssl_check",
                    "target": "example.com",
                    "parameters": {},
                    "rationale": "ssl",
                },
                {
                    "step_key": "scan",
                    "tool": "nmap",
                    "target": "example.com",
                    "parameters": {},
                    "rationale": "ports",
                },
            ],
        }
        graph, steps = validate_scan_plan(plan, engagement_targets=["example.com"])
        ssl = next(s for s in steps if s.step_key == "ssl")
        nmap = next(s for s in steps if s.step_key == "scan")
        assert nmap.id in ssl.depends_on
        assert ssl.phase == nmap.phase

    def test_rejects_earlier_phase_depending_on_later(self):
        plan = {
            "goal": "bad",
            "steps": [
                {
                    "step_key": "passive",
                    "tool": "dns_lookup",
                    "target": "x.com",
                    "phase": "passive",
                    "depends_on": ["active"],
                },
                {
                    "step_key": "active",
                    "tool": "nmap",
                    "target": "x.com",
                    "phase": "active",
                },
            ],
        }
        with pytest.raises(PlanValidationError, match="earlier than"):
            validate_scan_plan(plan, engagement_targets=["x.com"])

    def test_website_goal_warns_missing_gobuster(self):
        warnings = warn_planner_completeness(
            {
                "goal": "Website assessment of example.com",
                "steps": [{"tool": "nmap", "target": "example.com"}],
            }
        )
        assert any("checklist tools missing" in w for w in warnings)
        assert any("gobuster" in w for w in warnings)

    def test_planner_max_turns_skips_report(self, monkeypatch):
        agent = PLANNER_AGENT
        llm = Mock()
        llm.generate = Mock(
            return_value=Mock(
                content=json.dumps(
                    {"tool": "complete_task", "parameters": {"answer": "bad"}, "rationale": "x"}
                )
            )
        )
        report_calls = []

        class FakeReport:
            def execute(self, params):
                report_calls.append(params)
                return {"report_path": "/tmp/x.md", "summary": "nope"}

        monkeypatch.setattr("agent.tools.report_tool.ReportTool", FakeReport)
        executor = AgentExecutor(
            agent_definition=agent,
            llm_client=llm,
            tool_registry=ToolRegistry(),
            require_approval=False,
            max_turns=2,
        )
        result = asyncio.run(executor.run({"goal": "scan"}))
        assert report_calls == []
        assert "scan_plan" in result
        assert "error" in result["scan_plan"]


class TestGraphScheduling:
    def test_partial_and_not_applicable_complete_dependents(self, temp_db):
        pm = MagicMock()
        store = EngagementStore()
        executor = WorkGraphExecutor(pm, store=store, require_approval=False)
        engagement = Engagement(name="e", targets=["example.com"])
        store.save_engagement(engagement)

        step_a = WorkStep(
            name="a",
            tool="sqli_scanner",
            target="https://example.com",
            phase=WorkPhase.EXPLOIT,
            plan_index=0,
        )
        step_b = WorkStep(
            name="b",
            tool="whois",
            target="example.com",
            phase=WorkPhase.PASSIVE,
            plan_index=1,
            depends_on=[step_a.id],
        )
        # Force same phase so dependency, not phase, is under test for B
        step_b.phase = WorkPhase.EXPLOIT
        graph = WorkGraph(
            engagement_id=engagement.id,
            goal="t",
            steps=[step_a, step_b],
            current_phase=WorkPhase.EXPLOIT,
        )

        from agent.tool_result import ToolResultEnvelope

        async def fake_execute(step, engagement, ctx):
            if step.id == step_a.id:
                return ToolResultEnvelope(
                    status="not_applicable",
                    tool_name=step.tool,
                    summary="no params",
                )
            return ToolResultEnvelope(status="success", tool_name=step.tool, summary="ok")

        executor.execute_step = fake_execute  # type: ignore
        result = asyncio.run(executor.run_graph(graph, engagement, session_id="s", run_id="r"))
        assert result.status == EngagementStatus.COMPLETED
        assert set(result.completed_step_ids) == {step_a.id, step_b.id}
        assert next(s for s in result.steps if s.id == step_a.id).outcome == "not_applicable"

    def test_sequential_honors_phase_order(self, temp_db):
        pm = MagicMock()
        store = EngagementStore()
        executor = WorkGraphExecutor(pm, store=store, require_approval=False)
        engagement = Engagement(name="e", targets=["example.com"])
        store.save_engagement(engagement)

        active = WorkStep(
            name="nmap",
            tool="nmap",
            target="example.com",
            phase=WorkPhase.ACTIVE,
            plan_index=0,
        )
        passive = WorkStep(
            name="dns",
            tool="dns_lookup",
            target="example.com",
            phase=WorkPhase.PASSIVE,
            plan_index=1,
        )
        graph = WorkGraph(
            engagement_id=engagement.id,
            goal="phase",
            steps=[active, passive],
            current_phase=WorkPhase.PASSIVE,
        )
        order = []

        from agent.tool_result import ToolResultEnvelope

        async def fake_execute(step, engagement, ctx):
            order.append(step.tool)
            return ToolResultEnvelope(status="success", tool_name=step.tool, summary="ok")

        executor.execute_step = fake_execute  # type: ignore
        result = asyncio.run(executor.run_graph(graph, engagement, session_id="s", run_id="r"))
        assert result.status == EngagementStatus.COMPLETED
        assert order == ["dns_lookup", "nmap"]

    def test_unreachable_steps_block_without_deadlock(self, temp_db):
        pm = MagicMock()
        store = EngagementStore()
        executor = WorkGraphExecutor(
            pm, store=store, require_approval=False, enable_parallel_workers=True
        )
        engagement = Engagement(name="e", targets=["example.com"])
        store.save_engagement(engagement)

        parent = WorkStep(
            name="parent",
            tool="nmap",
            target="example.com",
            phase=WorkPhase.ACTIVE,
            plan_index=0,
        )
        child = WorkStep(
            name="child",
            tool="gobuster",
            target="example.com",
            phase=WorkPhase.ACTIVE,
            plan_index=1,
            depends_on=[parent.id],
            continue_on_failure=False,
        )
        graph = WorkGraph(
            engagement_id=engagement.id,
            goal="dead",
            steps=[parent, child],
            current_phase=WorkPhase.ACTIVE,
            failure_policy=FailurePolicy.BLOCK_DOWNSTREAM,
        )

        from agent.tool_result import ToolResultEnvelope
        from agent.worker_models import WorkerResult
        from agent import worker_pool

        async def fail_parent(self, task, ctx):
            if task.step_id == parent.id:
                return WorkerResult(
                    task_id=task.task_id,
                    step_id=task.step_id,
                    status="error",
                    envelope=ToolResultEnvelope(
                        status="error", tool_name=task.tool_name, summary="boom", error="boom"
                    ),
                    error="boom",
                )
            return WorkerResult(
                task_id=task.task_id,
                step_id=task.step_id,
                status="success",
                envelope=ToolResultEnvelope(
                    status="success", tool_name=task.tool_name, summary="ok"
                ),
            )

        from unittest.mock import patch

        with patch.object(worker_pool.BoundedWorkerPool, "execute_task", new=fail_parent):
            result = asyncio.run(
                executor.run_graph(graph, engagement, session_id="s", run_id="r")
            )
        assert result.status == EngagementStatus.FAILED
        child_step = next(s for s in result.steps if s.id == child.id)
        assert child_step.status == StepStatus.BLOCKED

    def test_parallel_budget_applies_inflight_before_pause(self, temp_db):
        pm = MagicMock()
        store = EngagementStore()
        executor = WorkGraphExecutor(
            pm, store=store, require_approval=False, enable_parallel_workers=True
        )
        engagement = Engagement(
            name="e",
            targets=["a.com", "b.com"],
            budget={"max_steps": 1, "max_wall_seconds": 3600},
        )
        store.save_engagement(engagement)
        steps = [
            WorkStep(
                name=f"s{i}",
                tool="dns_lookup",
                target=f"{t}.com",
                phase=WorkPhase.PASSIVE,
                plan_index=i,
            )
            for i, t in enumerate(["a", "b"])
        ]
        graph = WorkGraph(
            engagement_id=engagement.id,
            goal="budget",
            steps=steps,
            concurrency_limits=ConcurrencyLimits(max_concurrent_global=2, max_concurrent_passive=2),
        )

        from agent.tool_result import ToolResultEnvelope
        from agent.worker_models import WorkerResult
        from agent import worker_pool
        from unittest.mock import patch

        async def slow_ok(self, task, ctx):
            await asyncio.sleep(0.05)
            return WorkerResult(
                task_id=task.task_id,
                step_id=task.step_id,
                status="success",
                envelope=ToolResultEnvelope(
                    status="success", tool_name=task.tool_name, summary="ok"
                ),
            )

        with patch.object(worker_pool.BoundedWorkerPool, "execute_task", new=slow_ok):
            result = asyncio.run(
                executor.run_graph(graph, engagement, session_id="s", run_id="r")
            )
        assert result.status == EngagementStatus.PAUSED
        assert all(s.status != StepStatus.RUNNING for s in result.steps)
        completed = [s for s in result.steps if s.status == StepStatus.COMPLETED]
        assert len(completed) >= 1


class TestCliReconHelper:
    def test_execute_recon_plan_forwards_approval(self):
        from agent.cli import execute_recon_plan

        runtime = MagicMock()
        runtime.execute_scan_plan = AsyncMock(return_value={"status": "completed"})
        approve = AsyncMock(return_value=True)
        plan = {"goal": "r", "steps": [{"tool": "nmap", "target": "x"}]}
        result = asyncio.run(execute_recon_plan(runtime, plan, approve, session_id="t"))
        assert result["status"] == "completed"
        runtime.execute_scan_plan.assert_awaited_once()
        kwargs = runtime.execute_scan_plan.await_args.kwargs
        assert kwargs["approval_callback"] is approve
        assert kwargs["session_id"] == "t"
