"""Regression tests for session e3157642 remediation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.asset_manager import create_asset_manager_adapter
from adapters.interface import AdapterResultStatus
from agent.agent_library.planner import PLANNER_AGENT
from agent.agent_library.root import ROOT_AGENT
from agent.models import AssetModel, AssetType, SeverityLevel
from agent.reporting import FindingsNormalizer, Finding, ReportGenerator, ReportFormat
from agent.tools.report_tool import _build_report_summary


class TestReportSummaryAscii:
    def test_summary_uses_ascii_hyphen(self):
        content = (
            "# Pentest Report\n\n**Target:** dimkouts.dev\n\n"
            "Found 26 issues.\n\n### Risk Score: 4.0/10"
        )
        summary = _build_report_summary(content)
        assert " - 26 issues" in summary
        assert "\u2014" not in summary
        assert "\ufffd" not in summary


class TestAssetTablePopulate:
    def test_asset_report_includes_ips_and_tech_stack(self):
        findings = [
            Finding(
                title="DNS A records for dimkouts.dev",
                description="A: 104.21.61.1, 172.67.197.1",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="dns_lookup",
            ),
            Finding(
                title="Technology detected: Cloudflare",
                description="Cloudflare CDN",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="wappalyzer",
            ),
            Finding(
                title="Technology detected: HSTS",
                description="HSTS enabled",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="wappalyzer",
            ),
            Finding(
                title="High-risk service detected on port 22",
                description="SSH",
                severity=SeverityLevel.HIGH,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="nmap",
            ),
        ]
        assets = [
            AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")
        ]
        report = ReportGenerator().generate_report(
            findings, assets, {"primary_target": "dimkouts.dev"}, ReportFormat.MARKDOWN
        )
        assert "104.21.61.1" in report
        assert "Cloudflare" in report
        assert "HSTS" in report

    def test_aggregate_metadata_helper(self):
        findings = [
            Finding(
                title="DNS AAAA records for example.com",
                description="AAAA: 2606:4700::6815:3d01",
                asset_id=1,
                asset_name="example.com",
                source_tool="dns_lookup",
            ),
            Finding(
                title="Technology detected: nginx",
                asset_id=1,
                asset_name="example.com",
                source_tool="wappalyzer",
            ),
        ]
        meta = ReportGenerator._aggregate_asset_metadata_from_findings(
            findings, AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")
        )
        assert "2606:4700::6815:3d01" in meta["ip_addresses"]
        assert meta["tech_stack"] == ["nginx"]


class TestAssetManagerIdempotent:
    @pytest.fixture
    def adapter(self, tmp_path, monkeypatch):
        db_path = tmp_path / "homepentest.db"
        monkeypatch.setattr("src.adapters.asset_manager.DB_PATH", db_path)

        def _init_db():
            db_path.parent.mkdir(parents=True, exist_ok=True)
            import sqlite3

            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS assets "
                "(id INTEGER PRIMARY KEY, name TEXT, type TEXT, value TEXT, created_at TEXT)"
            )
            conn.commit()
            conn.close()

        monkeypatch.setattr("src.adapters.asset_manager.init_db", _init_db)
        return create_asset_manager_adapter()

    def test_duplicate_add_returns_success_with_existing_id(self, adapter):
        params = {"command": "add", "name": "web", "type": "domain", "value": "dimkouts.dev"}
        first = adapter.execute(params)
        assert first.status == AdapterResultStatus.SUCCESS
        first_id = first.metadata["asset_id"]

        dup = adapter.execute(
            {"command": "add", "name": "other", "type": "domain", "value": "dimkouts.dev"}
        )
        assert dup.status == AdapterResultStatus.SUCCESS
        assert dup.metadata["action"] == "exists"
        assert dup.metadata["asset_id"] == first_id
        assert "already registered" in dup.data


class TestDnsNoiseSuppress:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")

    def test_benign_no_answer_emits_no_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        output = {
            "domain": "dimkouts.dev",
            "records": {
                "MX": {"records": [], "error": "No answer for record type"},
                "TXT": {"records": [], "error": "No answer for record type"},
                "CNAME": {"records": [], "error": "Domain does not exist"},
            },
        }
        findings = normalizer.normalize_tool_output("dns_lookup", output, asset)
        query_issues = [f for f in findings if "query issue" in f.title]
        assert query_issues == []

    def test_real_dns_error_emits_informational_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        output = {
            "domain": "dimkouts.dev",
            "records": {
                "MX": {"records": [], "error": "Timeout after 5 seconds"},
            },
        }
        findings = normalizer.normalize_tool_output("dns_lookup", output, asset)
        assert len(findings) == 1
        assert findings[0].title == "DNS MX query issue"
        assert findings[0].severity == SeverityLevel.INFO
        assert findings[0].verification_state == "informational"


class TestPromptCoverage:
    def test_planner_requires_nmap_gobuster_sublist3r_for_all_tools(self):
        prompt = PLANNER_AGENT.prompt_config.system_prompt
        assert "Required scanning" in prompt
        assert "nmap" in prompt
        assert "gobuster" in prompt
        assert "sublist3r" in prompt
        assert "every tool" in prompt

    def test_root_follows_planner_and_requires_full_coverage(self):
        prompt = ROOT_AGENT.prompt_config.system_prompt
        assert "execute EVERY planned step" in prompt
        assert "sublist3r" in prompt
        assert "nmap" in prompt
        assert "gobuster" in prompt
