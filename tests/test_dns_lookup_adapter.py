import pytest
from unittest.mock import MagicMock, patch

import dns.resolver

from src.adapters.dns_lookup import DnsLookupAdapter
from src.adapters.interface import AdapterResultStatus


class TestDnsLookupAdapter:
    def test_target_alias_resolves_domain(self):
        adapter = DnsLookupAdapter({})
        params = {"target": "example.com"}
        adapter.validate_params(params)
        assert params["domain"] == "example.com"

    @patch("src.adapters.dns_lookup.dns.resolver.Resolver")
    def test_execute_parses_a_records(self, mock_resolver_cls, tmp_path):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        answer = MagicMock()
        answer.__iter__ = lambda self: iter([MagicMock(__str__=lambda s: "93.184.216.34")])
        mock_resolver.resolve.return_value = answer

        adapter = DnsLookupAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        result = adapter.execute({"domain": "example.com", "record_types": ["A"]})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["records"]["A"]["records"] == ["93.184.216.34"]

    @patch("src.adapters.dns_lookup.dns.resolver.Resolver")
    def test_execute_nxdomain(self, mock_resolver_cls, tmp_path):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        adapter = DnsLookupAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        result = adapter.execute({"domain": "missing.example.com", "record_types": ["A"]})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["records"]["A"]["error"] == "Domain does not exist"
