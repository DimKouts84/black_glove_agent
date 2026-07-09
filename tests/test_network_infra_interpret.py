import pytest
from datetime import datetime, timedelta

from src.adapters.whois import WhoisAdapter
from src.adapters.dns_recon import DNSReconAdapter
from src.adapters.ssl_check import SslCheckAdapter
from src.adapters.interface import AdapterResult, AdapterResultStatus


class TestWhoisInterpret:
    def test_interpret_uses_domain_key(self):
        adapter = WhoisAdapter({})
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "domain": "example.com",
                "registrar": "Example Registrar",
                "creation_date": datetime(2020, 1, 1),
                "expiration_date": datetime(2030, 1, 1),
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "example.com" in text
        assert "None" not in text.split("\n")[0]


class TestDnsReconInterpret:
    def test_brute_force_strings_in_summary(self):
        adapter = DNSReconAdapter()
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "zone_transfer": {},
                "brute_force": ["www.example.com", "api.example.com"],
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "www.example.com" in text
        assert "api.example.com" in text


class TestSslCheckInterpret:
    def test_expired_cert_metadata_wording(self):
        adapter = SslCheckAdapter({})
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "subject": {"commonName": "expired.example.com"},
                "issuer": {"commonName": "Test CA"},
                "not_after": "Jan 01 00:00:00 2020 GMT",
                "is_expired": True,
                "subject_alt_names": [],
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "EXPIRED" in text
        assert "trust not validated" in text

    def test_valid_metadata_not_claims_trusted(self):
        adapter = SslCheckAdapter({})
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "subject": {"commonName": "ok.example.com"},
                "issuer": {"commonName": "Test CA"},
                "not_after": "Jan 01 00:00:00 2030 GMT",
                "is_expired": False,
                "expires_in_days": 365,
                "subject_alt_names": [],
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "trust not validated" in text
        assert "Status: Valid" not in text
