import pytest
from src.agent.reporting import FindingsNormalizer
from src.agent.models import AssetModel, AssetType, SeverityLevel


class TestFindingsNormalizerWebWrappers:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="https://example.com")

    def test_gobuster_entries_sensitive_path(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "mode": "dir",
            "entries": [
                {"path": "/.env", "status": 200, "severity": "critical"},
                {"path": "/public", "status": 200},
            ],
        }

        findings = normalizer.normalize_tool_output("gobuster", output, asset)
        assert any("/.env" in f.title for f in findings)
        assert any(f.severity == SeverityLevel.CRITICAL for f in findings)

    def test_wappalyzer_confidence_threshold(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "technologies": [
                {"name": "nginx", "confidence": 100, "categories": ["Web servers"]},
                {"name": "MaybeCDN", "confidence": 10, "categories": []},
            ],
        }

        findings = normalizer.normalize_tool_output("wappalyzer", output, asset)
        assert len(findings) == 1
        assert "nginx" in findings[0].title

    def test_sublist3r_parent_zone_and_sensitive(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "domain": "example.com",
            "subdomains": [
                "www.example.com",
                "dev.example.com",
                "evil-other.com",
            ],
        }

        findings = normalizer.normalize_tool_output("sublist3r", output, asset)
        titles = [f.title for f in findings]
        assert any("www.example.com" in t for t in titles)
        assert any("dev.example.com" in t for t in titles)
        assert not any("evil-other.com" in t for t in titles)
        dev_finding = next(f for f in findings if "dev.example.com" in f.title)
        assert dev_finding.severity == SeverityLevel.MEDIUM
