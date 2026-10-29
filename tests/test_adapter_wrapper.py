import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from unittest.mock import MagicMock

from src.adapters.interface import AdapterResult, AdapterResultStatus
from agent.tools.adapter_wrapper import AdapterToolWrapper, SESSION_ASSET_NAME
from src.agent.reporting import Finding
from src.agent.models import SeverityLevel


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "homepentest.db"
    monkeypatch.setattr("src.agent.db.DB_PATH", path)
    monkeypatch.setattr("agent.db.DB_PATH", path)
    return path


class TestAdapterToolWrapper:
    @pytest.fixture
    def mock_result(self):
        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"ipv4": "203.0.113.1", "services_used": ["api.ipify.org"]},
            metadata={"adapter": "public_ip"},
        )

    def test_public_ip_persists_findings_via_session_asset(self, mock_result, isolated_db):
        pm = MagicMock()
        pm.run_adapter.return_value = mock_result
        pm.get_adapter_info.return_value = {"description": "Public IP detection"}
        pm.load_adapter.return_value = MagicMock(
            interpret_result=lambda r: "IPv4: 203.0.113.1"
        )

        wrapper = AdapterToolWrapper("public_ip", pm)

        finding = Finding(
            title="Public IP addresses detected",
            description="IPv4: 203.0.113.1",
            severity=SeverityLevel.LOW,
            confidence=0.95,
            asset_id=1,
            asset_name=SESSION_ASSET_NAME,
        )
        wrapper.reporting_manager.save_findings_to_database = MagicMock()
        wrapper.reporting_manager.findings_normalizer.normalize_tool_output = MagicMock(
            return_value=[finding]
        )

        result = wrapper.execute({})

        assert result["ipv4"] == "203.0.113.1"
        wrapper.reporting_manager.save_findings_to_database.assert_called_once()
        saved = wrapper.reporting_manager.save_findings_to_database.call_args[0][0]
        assert saved[0].asset_name == SESSION_ASSET_NAME

    def test_partial_result_persists(self, isolated_db):
        partial = AdapterResult(
            status=AdapterResultStatus.PARTIAL,
            data={"host": "example.com", "open_ports": [], "errors": ["bad response"]},
            metadata={},
        )

        pm = MagicMock()
        pm.run_adapter.return_value = partial
        pm.get_adapter_info.return_value = {}
        pm.load_adapter.return_value = MagicMock(interpret_result=lambda r: "partial")

        wrapper = AdapterToolWrapper("viewdns", pm)
        wrapper.reporting_manager.save_findings_to_database = MagicMock()
        wrapper.reporting_manager.findings_normalizer.normalize_tool_output = MagicMock(return_value=[])

        out = wrapper.execute({"host": "example.com"})
        assert out["errors"] == ["bad response"]

    def test_failure_result_returns_actionable_error(self, isolated_db):
        failure = AdapterResult(
            status=AdapterResultStatus.FAILURE,
            data={"errors": {"crt_sh": "timeout", "wayback": "blocked"}},
            metadata={},
            error_message="crt.sh: timeout; wayback: blocked",
        )

        pm = MagicMock()
        pm.run_adapter.return_value = failure
        pm.get_adapter_info.return_value = {}

        wrapper = AdapterToolWrapper("passive_recon", pm)
        out = wrapper.execute({"domain": "example.com"})
        assert out.startswith("Error:")
        assert "crt.sh" in out
        assert "None" not in out

    def test_string_result_keeps_metadata(self, isolated_db):
        stored = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data="Asset 'lab' already registered",
            metadata={"action": "exists", "asset_id": 9},
        )
        pm = MagicMock()
        pm.run_adapter.return_value = stored
        pm.get_adapter_info.return_value = {}
        pm.load_adapter.return_value = MagicMock(interpret_result=lambda r: "already registered")

        wrapper = AdapterToolWrapper("asset_manager", pm)
        out = wrapper.execute({})

        assert out["value"] == "Asset 'lab' already registered"
        assert out["action"] == "exists"
        assert out["asset_id"] == 9

    def test_conflicted_finding_is_noted_on_interpretation(self, isolated_db):
        stored = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"ipv4": "203.0.113.1"},
            metadata={},
        )
        pm = MagicMock()
        pm.run_adapter.return_value = stored
        pm.get_adapter_info.return_value = {}
        pm.load_adapter.return_value = MagicMock(interpret_result=lambda r: "IPv4 detected")

        wrapper = AdapterToolWrapper("public_ip", pm)
        finding = Finding(
            title="Missing Strict-Transport-Security",
            description="header absent",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            asset_id=1,
            asset_name=SESSION_ASSET_NAME,
        )

        def reconcile(findings, **kwargs):
            for item in findings:
                item.verification_state = "conflicted"
            return []

        wrapper.reporting_manager.findings_normalizer.normalize_tool_output = MagicMock(
            return_value=[finding]
        )
        wrapper.reporting_manager.findings_normalizer.reconcile_cross_tool_conflicts = reconcile
        wrapper.reporting_manager.save_findings_to_database = MagicMock()
        wrapper.reporting_manager.get_findings_for_asset = MagicMock(return_value=[])

        out = wrapper.execute({})

        assert "Reconciled observations" in out["interpretation"]
        assert "Missing Strict-Transport-Security" in out["interpretation"]

    def test_normalization_failure_is_warned_and_result_still_returns(self, isolated_db, caplog):
        stored = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"ipv4": "203.0.113.1"},
            metadata={"adapter": "public_ip"},
        )
        pm = MagicMock()
        pm.run_adapter.return_value = stored
        pm.get_adapter_info.return_value = {}
        pm.load_adapter.return_value = MagicMock(interpret_result=lambda r: "IPv4 detected")

        wrapper = AdapterToolWrapper("public_ip", pm)
        wrapper.reporting_manager.findings_normalizer.normalize_tool_output = MagicMock(
            side_effect=RuntimeError("db locked")
        )

        with caplog.at_level(logging.WARNING):
            out = wrapper.execute({})

        assert out["ipv4"] == "203.0.113.1"
        assert "Finding normalization/persistence failed" in caplog.text
        assert "db locked" in caplog.text
