import pytest
from src.agent.reporting import FindingsNormalizer
from src.agent.models import AssetModel, AssetType, SeverityLevel


class TestFindingsNormalizerNetworkInfra:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")

    def test_nmap_hosts_ports_produce_findings(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "hosts": [
                {
                    "address": "192.168.1.1",
                    "ports": [
                        {"port": 3389, "state": "open", "service": "ms-wbt-server"},
                        {"port": 80, "state": "open", "service": "http"},
                    ],
                }
            ],
            "summary": {"open_ports": 2},
        }

        findings = normalizer.normalize_tool_output("nmap", output, asset)
        assert len(findings) >= 1
        assert any("3389" in f.title for f in findings)

    def test_viewdns_open_ports(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "host": "example.com",
            "open_ports": [{"port": 22, "service": "ssh", "protocol": "tcp"}],
        }

        findings = normalizer.normalize_tool_output("viewdns", output, asset)
        assert any("22" in f.title for f in findings)

    def test_dns_recon_zone_transfer_critical(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "zone_transfer": {
                "ns1.example.com": {"status": "success", "records": ["www IN A 1.2.3.4"]},
            },
            "brute_force": [],
        }

        findings = normalizer.normalize_tool_output("dns_recon", output, asset)
        assert any(f.severity == SeverityLevel.CRITICAL for f in findings)

    def test_ssl_check_expired_high(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "subject": {"commonName": "example.com"},
            "is_expired": True,
            "not_after": "Jan 01 00:00:00 2020 GMT",
        }

        findings = normalizer.normalize_tool_output("ssl_check", output, asset)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH

    def test_public_ip_info_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {"ipv4": "203.0.113.1", "services_used": ["api.ipify.org"]}

        findings = normalizer.normalize_tool_output("public_ip", output, asset)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.LOW
        assert "203.0.113.1" in findings[0].description
        assert "api.ipify.org" in findings[0].description

    def test_dns_lookup_a_records(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "domain": "example.com",
            "records": {
                "A": {"records": ["93.184.216.34"], "count": 1},
            },
        }

        findings = normalizer.normalize_tool_output("dns_lookup", output, asset)
        assert any("DNS A records" in f.title for f in findings)

    def test_whois_registration_info(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "domain": "example.com",
            "registrar": "Example Registrar",
            "expiration_date": "2030-01-01",
            "expires_in_days": 365,
        }

        findings = normalizer.normalize_tool_output("whois", output, asset)
        assert len(findings) == 1
        assert "WHOIS registration" in findings[0].title
        assert findings[0].severity == SeverityLevel.LOW
