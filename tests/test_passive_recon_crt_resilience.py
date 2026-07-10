"""Tests for passive_recon degraded crt.sh handling."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from adapters.passive_recon import PassiveReconAdapter
from adapters.interface import AdapterResultStatus
from agent.tool_result import ToolResultEnvelope


class TestPassiveReconCrtResilience:
    @patch.object(PassiveReconAdapter, "_fetch_crt_sh_entries")
    @patch.object(PassiveReconAdapter, "_http_get")
    def test_crt_sh_502_wayback_ok_is_partial(self, mock_wb_get, mock_crt):
        mock_crt.return_value = ([], "HTTPError 502 for https://crt.sh/")
        mock_wb_get.return_value = (
            '[["timestamp","original","mime","statuscode","length","digest"],'
            '["20200101","http://example.com/","text/html","200","1234","XYZ"]]'
        )

        adapter = PassiveReconAdapter({})
        result = adapter.execute({"domain": "example.com"})

        assert result.status == AdapterResultStatus.PARTIAL
        assert result.data["errors"]["crt_sh"]
        assert result.data["coverage"]["wayback_ok"] is True

        envelope = ToolResultEnvelope.from_adapter_result(
            "passive_recon", result, dict(result.data)
        )
        assert envelope.status == "partial"

    @patch.object(PassiveReconAdapter, "_fetch_crt_sh_entries")
    @patch.object(PassiveReconAdapter, "_http_get")
    def test_crt_ok_wayback_empty_is_partial(self, mock_wb_get, mock_crt):
        mock_crt.return_value = (
            [{"name_value": "www.example.com\napi.example.com", "id": 1}],
            None,
        )
        mock_wb_get.return_value = '[["timestamp","original","mime","statuscode","length","digest"]]'

        adapter = PassiveReconAdapter({})
        result = adapter.execute({"domain": "example.com"})

        assert result.status == AdapterResultStatus.PARTIAL
        assert result.data["coverage"]["crt_sh_ok"] is True
        assert result.data["coverage"]["wayback_ok"] is False
        assert any("wayback" in w for w in result.data["warnings"])

        envelope = ToolResultEnvelope.from_adapter_result(
            "passive_recon", result, dict(result.data)
        )
        assert envelope.status == "partial"

    @patch.object(PassiveReconAdapter, "_fetch_crt_sh_entries")
    @patch.object(PassiveReconAdapter, "_http_get")
    def test_both_sources_fail_is_partial_not_error(self, mock_wb_get, mock_crt):
        mock_crt.return_value = ([], "HTTPError 502")
        mock_wb_get.side_effect = RuntimeError("wayback down")

        adapter = PassiveReconAdapter({})
        result = adapter.execute({"domain": "example.com"})

        assert result.status == AdapterResultStatus.PARTIAL
        envelope = ToolResultEnvelope.from_adapter_result(
            "passive_recon", result, dict(result.data)
        )
        assert envelope.status == "partial"
