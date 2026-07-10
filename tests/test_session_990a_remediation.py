"""Regression tests for session 990a1a0b follow-up remediation."""

import hashlib
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.web_server_scanner import WebServerScannerAdapter
from agent.agent_library.planner import PLANNER_AGENT
from agent.db import create_assets_table, create_findings_table, create_finding_observations_table
from agent.models import AssetModel, AssetType, SeverityLevel
from agent.reporting import FindingsNormalizer, ReportingManager, Finding, ReportGenerator, ReportFormat
from agent.tool_result import ToolResultEnvelope
from agent.tools.report_tool import ReportTool, _build_report_summary


def _memory_db():
    conn = sqlite3.connect(":memory:")
    create_assets_table(conn)
    create_findings_table(conn)
    create_finding_observations_table(conn)
    conn.execute(
        "INSERT INTO assets (id, name, type, value) VALUES (1, 'dimkouts_dev', 'domain', 'dimkouts.dev')"
    )
    conn.commit()
    return conn


class TestHeaderFingerprint:
    def test_header_fingerprint_ignores_description(self):
        f1 = Finding(
            title="Missing Strict-Transport-Security",
            description="raw scanner text",
            asset_id=1,
            source_tool="web_server_scanner",
        )
        f2 = Finding(
            title="Missing Strict-Transport-Security",
            description="reconciled different text",
            asset_id=1,
            source_tool="web_server_scanner",
        )
        assert ReportingManager._finding_fingerprint(f1) == ReportingManager._finding_fingerprint(f2)


class TestSubdomainDedup:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")

    def test_passive_and_osint_subdomains_merge_to_one_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        conn = _memory_db()
        manager = ReportingManager(conn)

        passive_out = {
            "crt_sh": {
                "certificates": [
                    {"name_value": ["*.dimkouts.dev", "*.www.dimkouts.dev"]},
                ],
            },
            "coverage": {"crt_sh_ok": True, "wayback_ok": False},
        }
        osint_out = {
            "subdomains": ["dimkouts.dev", "www.dimkouts.dev"],
        }

        passive_findings = normalizer.normalize_tool_output("passive_recon", passive_out, asset)
        osint_findings = normalizer.normalize_tool_output("osint_harvester", osint_out, asset)

        assert len(passive_findings) == 1
        assert passive_findings[0].title.startswith("Subdomains discovered")
        assert len(osint_findings) == 1

        for f in passive_findings + osint_findings:
            f.run_id = "run-sub"
        manager.save_findings_to_database(passive_findings)
        manager.save_findings_to_database(osint_findings)

        rows = manager.get_findings_from_database(run_id="run-sub")
        subdomain_rows = [r for r in rows if r.title.startswith("Subdomains discovered")]
        assert len(subdomain_rows) == 1


class TestHstsHttpContext:
    def test_adapter_downgrades_hsts_on_http(self):
        adapter = WebServerScannerAdapter({})
        mock_resp = MagicMock()
        mock_resp.url = "http://example.com"
        mock_resp.status_code = 200
        mock_resp.headers = {}
        adapter._request = MagicMock(return_value=mock_resp)

        findings = adapter._check_security_headers("http://example.com")
        hsts = next(f for f in findings if "Strict-Transport-Security" in f["title"])
        assert hsts["severity"] == "INFO"
        assert hsts.get("context") == "http_scan"

    def test_normalizer_marks_http_hsts_informational(self, tmp_path, monkeypatch):
        normalizer = FindingsNormalizer()
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        asset = AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")
        output = {
            "findings": [
                {
                    "title": "Missing Strict-Transport-Security",
                    "detail": "Enforces HTTPS",
                    "severity": "HIGH",
                    "response_url": "http://example.com",
                    "note": "Direct HTTP response lacked HSTS header.",
                }
            ]
        }
        findings = normalizer.normalize_tool_output("web_server_scanner", output, asset)
        assert findings[0].severity == SeverityLevel.INFO
        assert findings[0].verification_state == "informational"

    def test_http_hsts_excluded_from_key_findings(self):
        findings = [
            Finding(
                title="Missing Strict-Transport-Security",
                severity=SeverityLevel.INFO,
                asset_id=1,
                asset_name="example.com",
                source_tool="web_server_scanner",
                verification_state="informational",
            ),
            Finding(
                title="Missing Content-Security-Policy",
                severity=SeverityLevel.HIGH,
                asset_id=1,
                asset_name="example.com",
                source_tool="web_server_scanner",
            ),
        ]
        assets = [AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")]
        report = ReportGenerator().generate_report(
            findings, assets, {"primary_target": "example.com"}, ReportFormat.MARKDOWN
        )
        assert "### Key Findings" in report
        key_section = report.split("### Key Findings", 1)[1].split("###", 1)[0]
        assert "Missing Content-Security-Policy" in key_section
        assert "Missing Strict-Transport-Security" not in key_section


class TestReportPersistence:
    def test_build_report_summary(self):
        content = "# Pentest Report\n\n**Target:** dimkouts.dev\n\nFound 24 issues.\n\n### Risk Score: 4.0/10"
        summary = _build_report_summary(content)
        assert "dimkouts.dev" in summary
        assert "24" in summary

    def test_tool_result_envelope_report_path_in_trace(self):
        payload = {
            "report_path": "/tmp/reports/run-1.md",
            "summary": "Pentest report for dimkouts.dev — 24 issues (risk 4.0/10)",
            "report_preview": "# Pentest Report",
        }
        envelope = ToolResultEnvelope.from_raw("generate_report", payload)
        assert envelope.report_path == "/tmp/reports/run-1.md"
        assert envelope.evidence_paths == ["/tmp/reports/run-1.md"]
        trace = envelope.to_trace_details()
        assert trace["report_path"] == "/tmp/reports/run-1.md"
        assert trace["result_digest"] == "/tmp/reports/run-1.md"

    def test_generate_report_writes_file(self, tmp_path, monkeypatch):
        reports_dir = tmp_path / "reports"
        monkeypatch.setattr("agent.tools.report_tool._reports_dir", lambda: reports_dir)
        tool = ReportTool()
        tool.reporting_manager.generate_assessment_report = MagicMock(
            return_value="# Pentest Report\n\n**Target:** dimkouts.dev\n\nFound 2 issues.\n\n### Risk Score: 8.0/10"
        )
        with patch("agent.tools.report_tool.get_run_context", return_value={"run_id": "run-abc"}):
            result = tool.execute({"format": "markdown"})
        assert isinstance(result, dict)
        assert Path(result["report_path"]).exists()
        assert "dimkouts.dev" in result["summary"]


class TestPlannerCoverage:
    def test_planner_prompt_includes_ssl_check_checklist(self):
        prompt = PLANNER_AGENT.prompt_config.system_prompt
        assert "ssl_check" in prompt
        assert "WEBSITE FULL-SCAN CHECKLIST" in prompt
        assert "gobuster" in prompt
