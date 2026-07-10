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

    @patch("src.adapters.whois.whois.whois")
    def test_execute_timezone_aware_expiration(self, mock_whois):
        """Regression: offset-aware expiration must not crash expires_in_days."""
        from datetime import datetime, timezone

        info = MagicMock()
        info.registrar = "Test Registrar"
        info.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        info.expiration_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        info.name_servers = ["ns1.example.com"]
        info.emails = None
        info.org = None
        mock_whois.return_value = info

        adapter = WhoisAdapter({})
        result = adapter.execute({"domain": "example.com"})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["expires_in_days"] is not None
        assert result.data["expires_in_days"] > 0

    def test_target_alias_in_validate(self):
        adapter = WhoisAdapter({})
        params = {"target": "example.com"}
        adapter.validate_params(params)
        assert params["domain"] == "example.com"

    @patch("src.adapters.whois.fetch_rdap_domain")
    @patch("src.adapters.whois.whois.whois")
    def test_execute_whois_error_returns_partial(self, mock_whois, mock_fetch_rdap):
        import whois

        mock_whois.side_effect = whois.WhoisError("domain not found")
        mock_fetch_rdap.return_value = (None, ["RDAP HTTP 404"])

        adapter = WhoisAdapter({})
        result = adapter.execute({"domain": "missing.example"})

        assert result.status == AdapterResultStatus.PARTIAL
        assert result.data["registrar"] is None
        assert any("WHOIS" in w for w in result.data["warnings"])
        text = adapter.interpret_result(result)
        assert "no registration data" in text.lower()

    @patch("src.adapters.whois.fetch_rdap_domain")
    def test_execute_rdap_first_for_dev_tld(self, mock_fetch_rdap):
        mock_fetch_rdap.return_value = (
            {
                "registrar": "Porkbun LLC",
                "creation_date": datetime(2026, 4, 5),
                "expiration_date": datetime(2027, 4, 5),
                "name_servers": ["cloe.ns.cloudflare.com"],
                "status": ["client delete prohibited"],
                "rdap_url": "https://pubapi.registry.google/rdap/domain/dimkouts.dev",
            },
            [],
        )

        adapter = WhoisAdapter({})
        result = adapter.execute({"domain": "dimkouts.dev"})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["registrar"] == "Porkbun LLC"
        assert result.data["rdap_used"] is True
        text = adapter.interpret_result(result)
        assert "Porkbun LLC" in text
        assert "Source: RDAP" in text

    @patch("src.adapters.whois.fetch_rdap_domain")
    @patch("src.adapters.whois.whois.whois")
    def test_execute_partial_when_rdap_empty(self, mock_whois, mock_fetch_rdap):
        info = MagicMock()
        info.registrar = None
        info.creation_date = None
        info.expiration_date = None
        info.name_servers = None
        info.emails = None
        info.org = None
        mock_whois.return_value = info
        mock_fetch_rdap.return_value = (None, ["RDAP HTTP 503"])

        adapter = WhoisAdapter({})
        result = adapter.execute({"domain": "example.com"})

        assert result.status == AdapterResultStatus.PARTIAL
        assert result.data["registrar"] is None
        text = adapter.interpret_result(result)
        assert "no registration data" in text.lower()
        assert "503" in text
