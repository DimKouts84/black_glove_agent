import pytest
from src.agent.reporting import FindingsNormalizer
from src.agent.models import AssetModel, AssetType, SeverityLevel


class TestFindingsNormalizerWebScanners:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")

    def test_web_vuln_scanner_per_issue_findings(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(
            normalizer.evidence_storage, "storage_path", tmp_path
        )

        output = {
            "target_url": "http://example.com?q=1",
            "vulnerabilities": [
                {
                    "type": "xss_reflected",
                    "parameter": "q",
                    "url": "http://example.com?q=xss",
                    "severity": "high",
                    "confidence": 0.85,
                    "evidence": "reflected",
                },
                {
                    "type": "path_traversal",
                    "parameter": "file",
                    "url": "http://example.com?file=../",
                    "severity": "high",
                    "confidence": 0.8,
                    "evidence": "marker found",
                },
            ],
        }

        findings = normalizer.normalize_tool_output("web_vuln_scanner", output, asset)

        assert len(findings) == 2
        assert all(f.severity == SeverityLevel.HIGH for f in findings)
        assert any("xss_reflected" in f.title for f in findings)

    def test_sqli_scanner_severity_mapping(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(
            normalizer.evidence_storage, "storage_path", tmp_path
        )

        output = {
            "vulnerabilities": [{
                "type": "error_based",
                "parameter": "id",
                "severity": "critical",
                "confidence": 0.9,
                "evidence": "SQL error",
            }],
        }

        findings = normalizer.normalize_tool_output("sqli_scanner", output, asset)

        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL

    def test_web_server_scanner_skips_info_findings(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(
            normalizer.evidence_storage, "storage_path", tmp_path
        )

        output = {
            "findings": [
                {"title": "Missing CSP", "detail": "desc", "severity": "HIGH"},
                {"title": "robots", "detail": "info", "severity": "INFO"},
            ],
        }

        findings = normalizer.normalize_tool_output("web_server_scanner", output, asset)

        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH

    def test_untested_scan_produces_no_findings(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(
            normalizer.evidence_storage, "storage_path", tmp_path
        )

        output = {
            "not_applicable": True,
            "coverage": {"scanned_params": 0, "untested": True},
            "interpretation": "no parameters",
        }

        findings = normalizer.normalize_tool_output("web_vuln_scanner", output, asset)
        assert findings == []

    def test_empty_vulnerabilities_creates_low_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(
            normalizer.evidence_storage, "storage_path", tmp_path
        )

        output = {
            "vulnerabilities": [],
            "scanned_params": ["q"],
            "coverage": {"scanned_params": 1, "untested": False},
            "interpretation": "No issues found",
        }

        findings = normalizer.normalize_tool_output("web_vuln_scanner", output, asset)

        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.LOW
        assert "No issues found" in findings[0].description
