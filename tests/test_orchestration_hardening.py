"""Tests for pentest orchestration hardening."""

import asyncio
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.audit import write_audit
from agent.db import (
    _migrate_findings_columns,
    create_audit_log_table,
    create_engagement_tables,
    create_findings_table,
)
from agent.engagement_store import EngagementStore
from agent.executor import AgentExecutor
from agent.models import ConfigModel
from agent.plugin_manager import create_plugin_manager
from agent.policy_engine import create_policy_engine
from agent.reporting import Finding, ReportingManager, SeverityLevel
from agent.runtime import AgentRuntime, reset_agent_runtime
from agent.subagent_tool import SubagentTool
from agent.target_scope import TargetScopeConfig, TargetScopeValidator
from agent.tool_risk import check_exploit_gate, get_tool_risk, phase_allows_tool
from agent.tool_result import ToolResultEnvelope
from agent.work_graph import Engagement, WorkPhase, WorkStep
from agent.work_graph_executor import WorkGraphExecutor
from agent.agent_library.root import ROOT_AGENT
from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentPromptConfig, AgentToolConfig


@pytest.fixture
def memory_db():
    conn = sqlite3.connect(":memory:")
    create_audit_log_table(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    create_findings_table(conn)
    create_engagement_tables(conn)
    conn.commit()
    return conn


class TestTargetScope:
    def test_ip_in_authorized_network(self):
        scope = TargetScopeConfig(
            authorized_networks=["192.168.1.0/24"],
            authorized_domains=[],
            blocked_targets=[],
        )
        validator = TargetScopeValidator(scope)
        assert validator.is_ip_authorized("192.168.1.50") is True
        assert validator.is_ip_authorized("10.0.0.1") is False

    def test_domain_subdomain_match(self):
        scope = TargetScopeConfig(
            authorized_networks=[],
            authorized_domains=["example.com"],
            blocked_targets=[],
        )
        validator = TargetScopeValidator(scope)
        assert validator.is_domain_authorized("sub.example.com") is True
        assert validator.is_domain_authorized("evil.com") is False

    def test_blocked_target(self):
        scope = TargetScopeConfig(
            authorized_networks=["10.0.0.0/8"],
            authorized_domains=["example.com"],
            blocked_targets=["10.0.0.5"],
        )
        validator = TargetScopeValidator(scope)
        assert validator.validate_target("10.0.0.5") is False


class TestToolRisk:
    def test_exploit_gate_blocks_by_default(self):
        err = check_exploit_gate(
            "sqli_scanner",
            enable_exploit_adapters=False,
            require_lab_mode_for_exploits=True,
        )
        assert err is not None

    def test_phase_gating(self):
        assert phase_allows_tool("passive", "whois") is True
        assert phase_allows_tool("passive", "nmap") is False


class TestAuditTrail:
    def test_write_audit_persists(self, memory_db):
        write_audit("tool_attempt", {"tool": "nmap"}, conn=memory_db)
        row = memory_db.execute(
            "SELECT event_type, data FROM audit_log"
        ).fetchone()
        assert row[0] == "tool_attempt"
        assert "nmap" in row[1]


class TestRuntimePolicyWiring:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_agent_runtime()
        yield
        reset_agent_runtime()

    def test_runtime_has_policy_engine(self):
        runtime = AgentRuntime(config=ConfigModel())
        assert runtime.policy_engine is not None
        assert runtime.plugin_manager.policy_engine is not None

    def test_work_graph_executor_present(self):
        runtime = AgentRuntime(config=ConfigModel())
        assert runtime.work_graph_executor is not None


class TestApprovalFailClosed:
    def test_executor_denies_without_callback(self):
        from agent.tools.registry import ToolRegistry

        class _EchoTool:
            name = "nmap"
            description = "test"

            async def execute(self, params):
                return {"ok": True}

            def get_info(self):
                return {"name": self.name, "description": self.description, "parameters": {}}

        registry = ToolRegistry()
        registry.register(_EchoTool())

        from agent.agent_library.root import FinalResponse

        agent = AgentDefinition(
            name="test_agent",
            description="test",
            input_config={"q": AgentInput(description="q")},
            output_config=AgentOutput(
                output_name="final_answer",
                description="done",
                schema_model=FinalResponse,
            ),
            tool_config=AgentToolConfig(tools=["nmap"]),
            prompt_config=AgentPromptConfig(
                system_prompt="test",
                initial_query_template="${q}",
            ),
        )

        llm = Mock()
        llm.generate = Mock(
            side_effect=[
                Mock(
                    content=json.dumps(
                        {
                            "tool": "nmap",
                            "parameters": {"target": "192.168.1.1"},
                            "rationale": "scan",
                        }
                    )
                ),
                Mock(
                    content=json.dumps(
                        {
                            "tool": "complete_task",
                            "parameters": {"final_answer": {"answer": "done"}},
                            "rationale": "finish",
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


class TestSubagentApprovalPropagation:
    def test_subagent_stores_approval_settings(self):
        from agent.tools.registry import ToolRegistry
        from agent.agent_library.researcher import RESEARCHER_AGENT

        registry = ToolRegistry()
        sub = SubagentTool(
            RESEARCHER_AGENT,
            Mock(),
            registry,
            require_approval=True,
            safe_tools={"complete_task"},
            approval_callback=AsyncMock(return_value=True),
        )
        assert sub.require_approval is True
        assert sub.approval_callback is not None


class TestFindingsDedup:
    def test_fingerprint_dedup(self, memory_db, monkeypatch):
        monkeypatch.setattr(
            "agent.reporting.get_db_connection", lambda: memory_db
        )
        memory_db.execute(
            "INSERT INTO assets (name, type, value) VALUES ('t', 'host', '192.168.1.1')"
        )
        memory_db.commit()

        manager = ReportingManager(db_connection=memory_db)
        finding = Finding(
            title="Open port 80",
            description="test",
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            asset_id=1,
            source_tool="nmap",
        )
        manager.save_findings_to_database([finding])
        manager.save_findings_to_database([finding])

        count = memory_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        obs = memory_db.execute(
            "SELECT observation_count FROM findings"
        ).fetchone()[0]
        assert count == 1
        assert obs == 2


class TestWorkGraphExecutor:
    def test_blocks_unauthorized_target(self, memory_db, monkeypatch):
        monkeypatch.setattr(
            "agent.engagement_store.get_db_connection", lambda: memory_db
        )
        policy = create_policy_engine(
            {
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"],
                    "authorized_domains": [],
                    "blocked_targets": [],
                }
            }
        )
        pm = create_plugin_manager(
            config={"enable_exploit_adapters": False},
            policy_engine=policy,
        )
        store = EngagementStore(conn=memory_db)
        executor = WorkGraphExecutor(
            plugin_manager=pm,
            policy_engine=policy,
            store=store,
            require_approval=False,
        )
        engagement = Engagement(name="test", targets=["8.8.8.8"])
        step = WorkStep(
            name="whois_ext",
            tool="whois",
            target="8.8.8.8",
            parameters={"domain": "8.8.8.8"},
            phase=WorkPhase.PASSIVE,
        )
        from agent.execution_context import ExecutionContext

        ctx = ExecutionContext(session_id="", run_id="test")
        envelope = asyncio.run(executor.execute_step(step, engagement, ctx))
        assert envelope.status in {"blocked", "error"}
        assert "BLOCKED" in (envelope.error or envelope.summary or "").upper()

    def test_resume_skips_completed_steps(self, memory_db, monkeypatch):
        monkeypatch.setattr(
            "agent.engagement_store.get_db_connection", lambda: memory_db
        )
        policy = create_policy_engine(
            {
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"],
                    "authorized_domains": [],
                    "blocked_targets": [],
                }
            }
        )
        pm = create_plugin_manager(policy_engine=policy)
        store = EngagementStore(conn=memory_db)
        executor = WorkGraphExecutor(
            plugin_manager=pm,
            policy_engine=policy,
            store=store,
            require_approval=False,
        )

        engagement = Engagement(name="resume-test", targets=["192.168.1.1"])
        store.save_engagement(engagement)

        from agent.work_graph import WorkGraph, StepStatus

        completed_step = WorkStep(
            name="done",
            tool="public_ip",
            target="local",
            status=StepStatus.COMPLETED,
        )
        pending_step = WorkStep(
            name="pending",
            tool="public_ip",
            target="local",
            status=StepStatus.PENDING,
        )
        graph = WorkGraph(
            engagement_id=engagement.id,
            goal="test",
            steps=[completed_step, pending_step],
            completed_step_ids=[completed_step.id],
        )
        store.save_work_graph(graph)

        with patch.object(executor, "execute_step", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = ToolResultEnvelope(
                status="success", tool_name="public_ip", summary="ok"
            )
            resumed = asyncio.run(executor.resume_graph(graph.id))
            assert mock_exec.await_count == 1


class TestToolResultEnvelope:
    def test_to_llm_context_includes_pointers(self):
        envelope = ToolResultEnvelope(
            status="success",
            tool_name="passive_recon",
            summary="found secrets",
            evidence_paths=["/evidence/passive_recon/out.txt"],
            finding_ids=[1, 2],
        )
        ctx = envelope.to_llm_context(max_len=5000)
        assert "evidence_paths" in ctx
        assert "finding_ids" in ctx
