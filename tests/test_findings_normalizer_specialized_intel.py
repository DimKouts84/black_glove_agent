import pytest
from src.agent.reporting import FindingsNormalizer
from src.agent.models import AssetModel, AssetType, SeverityLevel


class TestFindingsNormalizerSpecializedIntel:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")

    def test_passive_recon_secret_severity(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "potential_secrets": [
                {
                    "type": "sensitive_extension",
                    "match": ".env",
                    "url": "http://example.com/.env",
                    "severity": "high",
                    "confidence": 0.75,
                },
                {
                    "type": "sensitive_keyword",
                    "match": "key=",
                    "url": "http://example.com/?key=abc",
                    "severity": "low",
                    "confidence": 0.45,
                },
            ],
        }

        findings = normalizer.normalize_tool_output("passive_recon", output, asset)
        assert len(findings) == 2
        assert findings[0].severity == SeverityLevel.HIGH
        assert findings[1].severity == SeverityLevel.LOW

    def test_credential_tester_critical(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "valid_credentials": [{"username": "admin", "password": "admin"}],
            "protocol": "ssh",
            "target": "192.168.1.1",
            "port": 22,
        }

        findings = normalizer.normalize_tool_output("credential_tester", output, asset)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL

    def test_camera_security_parses_string_findings(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "findings": [
                "⚠️ RTSP VULNERABILITY: Anonymous stream",
                "✓ Default credentials tested - none successful",
            ],
            "vulnerabilities_detected": True,
        }

        findings = normalizer.normalize_tool_output("camera_security", output, asset)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH

    def test_osint_harvester_emails_and_subdomains(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "emails": ["admin@example.com"],
            "subdomains": ["www.example.com", "api.example.com"],
        }

        findings = normalizer.normalize_tool_output("osint_harvester", output, asset)
        assert len(findings) == 2

    def test_passive_recon_crt_subdomains_no_scan_completed(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "crt_sh": {
                "certificates": [
                    {"name_value": ["www.example.com", "api.example.com"]},
                ],
                "count": 1,
            },
            "coverage": {"crt_sh_ok": True, "wayback_ok": False},
        }

        findings = normalizer.normalize_tool_output("passive_recon", output, asset)
        assert len(findings) == 1
        assert "Subdomains discovered" in findings[0].title
        assert all("scan completed" not in f.title for f in findings)
