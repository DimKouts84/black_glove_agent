import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from src.adapters.whois import WhoisAdapter
from src.adapters.interface import AdapterResultStatus


class TestWhoisAdapter:
    @patch("src.adapters.whois.whois.whois")
    def test_execute_and_interpret(self, mock_whois):
        info = MagicMock()
        info.registrar = "Test Registrar"
        info.creation_date = datetime(2020, 1, 1)
        info.expiration_date = datetime(2030, 1, 1)
        info.name_servers = ["ns1.example.com"]
        info.emails = ["admin@example.com"]
        info.org = "Example Org"
        mock_whois.return_value = info

        adapter = WhoisAdapter({})
        result = adapter.execute({"domain": "example.com"})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["domain"] == "example.com"
        text = adapter.interpret_result(result)
        assert "example.com" in text
        assert "Test Registrar" in text

    def test_target_alias_in_validate(self):
        adapter = WhoisAdapter({})
        params = {"target": "example.com"}
        adapter.validate_params(params)
        assert params["domain"] == "example.com"

    @patch("src.adapters.whois.whois.whois")
    def test_execute_whois_error_returns_failure(self, mock_whois):
        import whois

        mock_whois.side_effect = whois.WhoisError("domain not found")

        adapter = WhoisAdapter({})
        result = adapter.execute({"domain": "missing.example"})

        assert result.status == AdapterResultStatus.FAILURE
        assert "WHOIS lookup failed" in result.error_message
        assert "PywhoisError" not in result.error_message
