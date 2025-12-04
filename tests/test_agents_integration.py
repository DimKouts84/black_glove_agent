import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from types import SimpleNamespace
from unittest.mock import Mock

from src.agent.agents.investigator import InvestigatorAgent
from src.agent.agents.researcher import ResearcherAgent
from src.agent.models import WorkflowStep, ScanPlan
from adapters.interface import AdapterResult, AdapterResultStatus

def test_investigator_planner_researcher_analyst_flow():
    """
    Integration-style test that verifies Investigator delegates a planning request
    to Planner, executes steps via Researcher (which uses PluginManager),
    and forwards results to Analyst for interpretation.

    This test uses lightweight stubs/mocks for Planner, PluginManager and Analyst
    to keep it deterministic and offline.
    """

    # Minimal dummy LLM client (not used heavily in this test)
    dummy_llm = SimpleNamespace(conversation_memory=None, generate=lambda *a, **k: SimpleNamespace(content="{}"))

    # Mock plugin manager: simulate adapter execution returning a successful AdapterResult
    plugin_manager = Mock()
    adapter_result = AdapterResult(
        status=AdapterResultStatus.SUCCESS,
        data={"stdout": "22/tcp open ssh\nService: OpenSSH 7.9"},
        metadata={"ports": [22], "evidence_path": "/tmp/evidence/test-nmap.json"}
    )
    plugin_manager.run_adapter.return_value = adapter_result
    plugin_manager.discover_adapters.return_value = ["nmap"]

    # Mock policy engine
    policy_engine = Mock()
    policy_engine.validate_asset.return_value = True
    policy_engine.enforce_rate_limits.return_value = True
    policy_engine.rate_limiter = Mock()


    # Use the real ResearcherAgent but with the mocked plugin manager
    researcher = ResearcherAgent(dummy_llm, plugin_manager, policy_engine, session_id="sess-1")

    # Planner stub: return a simple ScanPlan with one step (nmap)
    step = WorkflowStep(
        tool="nmap",
        target="192.168.1.100",
        parameters={},         # no extra params
        priority=1,
        rationale="Basic TCP fingerprinting"
    )
    plan = ScanPlan(goal="Scan my home router", created_at="2025-12-03T00:00:00Z", steps=[step])
    planner_stub = SimpleNamespace(plan_workflow=lambda goal: plan)

    # Analyst mock: accept whatever the researcher returns and return a short analysis string
    analyst = Mock()
    analyst.analyze_findings.return_value = "Found open SSH port on 192.168.1.100 (port 22)."

    # Investigator using the real researcher but stubbed planner and mocked analyst
    investigator = InvestigatorAgent(dummy_llm, plugin_manager, policy_engine, session_id="sess-1")
    investigator.planner = planner_stub
    investigator.researcher = researcher
    investigator.analyst = analyst

    # Drive the workflow
    events = list(investigator.handle_user_query("Scan my home router"))

    # Basic assertions: the flow includes a tool_call for nmap and a tool_result containing the formatted output
    assert any(e["type"] == "tool_call" and e.get("tool") == "nmap" for e in events), "Expected a tool_call event for nmap"
    assert any(
        e["type"] == "tool_result" and "NMAP" in (e.get("result") or "").upper() and "EXECUTED" in (e.get("result") or "").upper()
        for e in events
    ), "Expected a tool_result event showing NMAP executed successfully"

    # Plugin manager must have been invoked with the expected parameters
    plugin_manager.run_adapter.assert_called_once_with("nmap", {"target": "192.168.1.100"})

    # Analyst must have been called to analyze findings
    analyst.analyze_findings.assert_called()
