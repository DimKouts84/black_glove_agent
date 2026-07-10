"""Regression tests for session 7fc41845 remediation."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from adapters.interface import AdapterResult, AdapterResultStatus
from agent.tools.adapter_wrapper import AdapterToolWrapper
from agent.reporting import Finding, SeverityLevel


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "homepentest.db"
    monkeypatch.setattr("src.agent.db.DB_PATH", path)
    monkeypatch.setattr("agent.db.DB_PATH", path)
    return path


class TestConflictedPeerResave:
    def test_unrelated_tool_does_not_resave_conflicted_peer(self, isolated_db):
        pm = MagicMock()
        pm.run_adapter.return_value = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "not_applicable": True,
                "coverage": {"untested": True},
                "interpretation": "no params",
            },
            metadata={},
        )
        pm.get_adapter_info.return_value = {}
        pm.load_adapter.return_value = MagicMock(interpret_result=lambda r: "n/a")

        wrapper = AdapterToolWrapper("web_vuln_scanner", pm)
        wrapper._resolve_asset = MagicMock(
            return_value=MagicMock(id=1, name="dimkouts.dev", value="dimkouts.dev")
        )

        conflicted_peer = Finding(
            id=99,
            title="Missing Strict-Transport-Security",
            severity=SeverityLevel.INFO,
            asset_id=1,
            source_tool="web_server_scanner",
            verification_state="conflicted",
            run_id="run-1",
        )
        wrapper.reporting_manager.get_findings_for_asset = MagicMock(
            return_value=[conflicted_peer]
        )
        wrapper.reporting_manager.findings_normalizer.normalize_tool_output = MagicMock(
            return_value=[]
        )
        wrapper.reporting_manager.save_findings_to_database = MagicMock()

        with patch(
            "agent.tools.adapter_wrapper.get_run_context",
            return_value={"run_id": "run-1", "step_id": "step-2"},
        ):
            wrapper.execute({"target_url": "http://dimkouts.dev"})

        wrapper.reporting_manager.save_findings_to_database.assert_not_called()
