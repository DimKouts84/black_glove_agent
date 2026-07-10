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
