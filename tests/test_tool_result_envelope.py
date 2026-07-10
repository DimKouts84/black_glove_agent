"""Tests for ToolResultEnvelope subagent and error propagation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.tool_result import ToolResultEnvelope


class TestToolResultEnvelope:
    def test_subagent_success_uses_summary(self):
        envelope = ToolResultEnvelope.from_raw(
            "researcher_agent",
            {
                "result": {
                    "summary": "Found 2 subdomains",
                    "raw_output": "{}",
                    "success": True,
                }
            },
        )
        assert envelope.status == "success"
        assert envelope.summary == "Found 2 subdomains"

    def test_subagent_failure_marks_error(self):
        envelope = ToolResultEnvelope.from_raw(
            "researcher_agent",
            {
                "result": {
                    "summary": "passive_recon failed",
                    "raw_output": "Error: timeout",
                    "success": False,
                }
            },
        )
        assert envelope.status == "error"
        assert envelope.summary == "passive_recon failed"
        assert envelope.error == "passive_recon failed"

    def test_planner_scan_plan_uses_goal(self):
        envelope = ToolResultEnvelope.from_raw(
            "planner_agent",
            {
                "scan_plan": {
                    "goal": "Scan example.com",
                    "reasoning": "passive first",
                    "steps": [],
                }
            },
        )
        assert envelope.status == "success"
        assert envelope.summary == "Scan example.com"

    def test_string_error_passthrough(self):
        envelope = ToolResultEnvelope.from_raw(
            "passive_recon",
            "Error: crt.sh: timeout",
        )
        assert envelope.status == "error"
        assert "timeout" in envelope.summary
