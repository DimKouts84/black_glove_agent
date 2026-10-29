"""Targeted tests for agent bug-fix and behavior remediation."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.asset_validator import AssetValidator, ValidationStatus
from agent.models import AssetModel, AssetType, ConfigModel, DatabaseManager
from agent.reporting import FindingsNormalizer, ReportGenerator, Finding, SeverityLevel
from agent.runtime import warn_planner_completeness
from agent.tools.adapter_wrapper import AdapterToolWrapper


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "homepentest.db"
    monkeypatch.setattr("src.agent.db.DB_PATH", path)
    monkeypatch.setattr("agent.db.DB_PATH", path)
    from agent.db import init_db

    init_db()
    return path


def _mock_evidence(normalizer):
    return patch.object(
        normalizer.evidence_storage,
        "store_evidence",
        return_value={"path": "/test/evidence.txt", "hash": "abc123"},
    )


def _sample_asset():
    return AssetModel(id=1, name="test_host", type=AssetType.HOST, value="213.149.180.110")


class TestNormalizerRemediation:
    def test_web_scan_connection_failure_not_high_severity(self):
        normalizer = FindingsNormalizer()
        asset = _sample_asset()
        output = {
            "findings": [
                {
                    "title": "Connection failed",
                    "detail": "Could not connect to http://213.149.180.110:80",
                    "severity": "ERROR",
                    "confidence": 0.9,
                }
            ]
        }
        with _mock_evidence(normalizer):
            findings = normalizer.normalize_tool_output(
                "web_server_scanner", output, asset
            )
        assert not any("Connection failed" in f.title for f in findings)

    def test_camera_security_negative_result_no_finding(self):
        normalizer = FindingsNormalizer()
        asset = _sample_asset()
        output = {
            "findings": ["No common camera ports are open"],
            "vulnerabilities_detected": False,
        }
        with _mock_evidence(normalizer):
            findings = normalizer._normalize_specialized_intel_output(
                "camera_security", output, asset, {"path": "/t", "hash": "h"}
            )
        assert findings == []

    def test_camera_open_web_ports_are_not_findings(self):
        normalizer = FindingsNormalizer()
        asset = _sample_asset()
        output = {
            "findings": [
                "Open ports detected: 80 (HTTP), 443 (HTTPS), 8080 (HTTP-Alt), 8443 (HTTPS-Alt)"
            ],
            "vulnerabilities_detected": False,
        }
        with _mock_evidence(normalizer):
            findings = normalizer.normalize_tool_output("camera_security", output, asset)
        assert findings == []

    def test_port53_dns_not_high_risk_finding(self):
        normalizer = FindingsNormalizer()
        asset = _sample_asset()
        output = {"ports": [{"port": 53, "state": "open", "service": "dns"}]}
        with _mock_evidence(normalizer):
            findings = normalizer.normalize_tool_output("nmap", output, asset)
        assert not any("High-risk service detected on port 53" in f.title for f in findings)
        assert any("Open ports discovered" in f.title for f in findings)

    def test_public_ip_finding_is_informational(self):
        normalizer = FindingsNormalizer()
        asset = _sample_asset()
        output = {"ipv4": "213.149.180.110", "services_used": ["api.ipify.org"]}
        with _mock_evidence(normalizer):
            findings = normalizer.normalize_tool_output("public_ip", output, asset)
        ip_findings = [f for f in findings if "Public IP" in f.title]
        assert len(ip_findings) == 1
        assert ip_findings[0].verification_state == "informational"
        assert ip_findings[0].severity == SeverityLevel.INFO

    def test_report_risk_score_excludes_connection_errors(self):
        asset = _sample_asset()
        connection_error = Finding(
            title="Connection failed",
            description="Could not connect",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            asset_id=asset.id,
            asset_name=asset.name,
            verification_state="informational",
        )
        port_note = Finding(
            title="Open ports discovered (1)",
            description="53/dns",
            severity=SeverityLevel.INFO,
            confidence=0.95,
            asset_id=asset.id,
            asset_name=asset.name,
            verification_state="informational",
        )
        generator = ReportGenerator()
        md = generator._generate_markdown_report_v2(
            [connection_error, port_note],
            [asset],
            {},
        )
        assert "Risk Score: 10.0/10" in md


class TestAdapterWrapperRemediation:
    def test_adapter_wrapper_reuses_registered_asset_for_ip(self, isolated_db):
        db = DatabaseManager()
        existing_id = db.add_asset(
            AssetModel(
                name="Local_Network_Gateway",
                type=AssetType.HOST,
                value="213.149.180.110",
            )
        )

        pm = MagicMock()
        wrapper = AdapterToolWrapper("nmap", pm)
        asset = wrapper._resolve_asset({"target": "213.149.180.110"})

        assert asset is not None
        assert asset.id == existing_id
        assert asset.type == AssetType.HOST
        assert asset.value == "213.149.180.110"
        assert len(db.list_assets()) == 1


class TestConfigScopeRemediation:
    def test_config_loads_authorized_networks(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            """
authorized_networks:
  - 192.168.0.0/16
blocked_targets:
  - 10.0.0.1
require_lab_mode_for_exploits: false
default_rate_limit: 15
max_rate_limit: 40
""",
            encoding="utf-8",
        )
        from agent.config_service import ConfigService

        service = ConfigService(config_path=config_path)
        config = service.load()
        assert config.authorized_networks == ["192.168.0.0/16"]
        assert config.blocked_targets == ["10.0.0.1"]
        assert config.require_lab_mode_for_exploits is False
        assert config.default_rate_limit == 15
        assert config.max_rate_limit == 40

    def test_out_of_scope_target_emits_warning_not_block(self, isolated_db):
        config = ConfigModel(authorized_networks=["192.168.0.0/16"])
        validator = AssetValidator(config)

        with patch("agent.audit.write_audit") as mock_audit:
            warning = validator.warn_scope_if_needed(
                "213.149.180.110",
                adapter="nmap",
                params={"target": "213.149.180.110"},
            )

        assert warning is not None
        assert "outside authorized_networks" in warning
        mock_audit.assert_called_once()
        assert mock_audit.call_args[0][0] == "scope_warning"

        result = validator.validate_ip("213.149.180.110")
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
        assert result.scope_warning is not None


class TestPlannerCompleteness:
    def test_warns_when_comprehensive_plan_missing_recon_tools(self):
        warnings = warn_planner_completeness(
            {
                "goal": "Comprehensive scan of example.com",
                "steps": [{"tool": "nmap", "target": "example.com"}],
            }
        )
        assert any("recommended recon tools missing" in w for w in warnings)

    def test_warns_when_web_tools_without_nmap(self):
        warnings = warn_planner_completeness(
            {
                "goal": "Scan example.com",
                "steps": [
                    {"tool": "web_server_scanner", "target": "https://example.com"},
                ],
            }
        )
        assert any("without nmap port discovery" in w for w in warnings)
