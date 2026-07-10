"""WHOIS findings normalization tests."""

import pytest
from src.agent.reporting import FindingsNormalizer
from src.agent.models import AssetModel, AssetType


class TestWhoisFindingsNormalizer:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")

    def test_empty_whois_creates_incomplete_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        output = {
            "domain": "dimkouts.dev",
            "registrar": None,
            "warnings": ["RDAP HTTP 503"],
        }
        findings = normalizer.normalize_tool_output("whois", output, asset)
        assert len(findings) == 1
        assert "incomplete" in findings[0].title.lower()
        assert "503" in findings[0].description

    def test_populated_whois_creates_registration_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        output = {
            "domain": "dimkouts.dev",
            "registrar": "Porkbun LLC",
            "expiration_date": "2027-04-05",
        }
        findings = normalizer.normalize_tool_output("whois", output, asset)
        assert len(findings) == 1
        assert "registration" in findings[0].title.lower()
        assert "Porkbun" in findings[0].description
