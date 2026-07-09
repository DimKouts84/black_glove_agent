import pytest
from unittest.mock import MagicMock, patch

from src.adapters.viewdns import ViewDnsAdapter
from src.adapters.interface import AdapterResultStatus


class TestViewDnsAdapter:
    def test_validate_host_from_target(self):
        adapter = ViewDnsAdapter({"viewdns_api_key": "test-key"})
        params = {"target": "example.com"}
        adapter.validate_params(params)
        assert params["host"] == "example.com"

    @patch("src.adapters.viewdns.requests.get")
    def test_execute_parses_ports_and_evidence_newlines(self, mock_get, tmp_path):
        adapter = ViewDnsAdapter({"viewdns_api_key": "test-key"})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "response": {
                "port": [
                    {"number": 80, "service": "http", "status": "open"},
                    {"number": 443, "service": "https", "status": "closed"},
                ]
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = adapter.execute({"host": "example.com"})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["count"] == 1
        assert result.data["open_ports"][0]["port"] == 80

    @patch("src.adapters.viewdns.requests.get")
    def test_api_error_returns_partial(self, mock_get, tmp_path):
        adapter = ViewDnsAdapter({"viewdns_api_key": "test-key"})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"error": "Invalid API key"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = adapter.execute({"host": "example.com"})

        assert result.status == AdapterResultStatus.PARTIAL
        assert result.data["errors"]
        assert adapter.interpret_result(result).startswith("ViewDNS scan partial")
