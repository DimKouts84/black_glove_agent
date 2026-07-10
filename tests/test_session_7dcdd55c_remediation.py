"""Regression tests for session 7dcdd55c remediation."""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.base import BaseAdapter
from adapters.interface import AdapterResult, AdapterResultStatus
from adapters.transient_errors import is_transient_adapter_error
from agent.db import create_assets_table, create_findings_table, create_finding_observations_table
from agent.models import AssetModel, AssetType, SeverityLevel
from agent.reporting import Finding, FindingsNormalizer, ReportingManager, ReportGenerator, ReportFormat
from agent.tool_result import ToolResultEnvelope


def _memory_db():
    conn = sqlite3.connect(":memory:")
    create_assets_table(conn)
    create_findings_table(conn)
    create_finding_observations_table(conn)
    conn.execute(
        "INSERT INTO assets (id, name, type, value) VALUES (1, 'dimkouts.dev', 'domain', 'dimkouts.dev')"
    )
    conn.commit()
    return conn


class _FlakyAdapter(BaseAdapter):
    def __init__(self, config, failures_before_success: int):
        super().__init__(config)
        self.name = "flaky"
        self.version = "0.0.1"
        self._failures_before_success = failures_before_success
        self._calls = 0

    def _execute_impl(self, params):
        self._calls += 1
        if self._calls <= self._failures_before_success:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={},
                error_message="lookup dimkouts.dev: no such host",
            )
        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"ok": True},
            metadata={},
        )


class TestTransientErrors:
    def test_is_transient_adapter_error_matches_dns(self):
        assert is_transient_adapter_error("lookup dimkouts.dev: no such host")
        assert is_transient_adapter_error("unable to connect: connection refused")
        assert not is_transient_adapter_error("invalid wordlist path")


class TestBaseAdapterRetry:
    def test_base_adapter_retries_transient_dns_error(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
        adapter = _FlakyAdapter({"retries": 3}, failures_before_success=2)
        result = adapter.execute({})
        assert result.status == AdapterResultStatus.SUCCESS
        assert adapter._calls == 3
        assert len(sleeps) == 2


class TestObservationUpsert:
    def test_observation_updates_in_place_same_run(self):
        conn = _memory_db()
        manager = ReportingManager(conn)
        first = Finding(
            title="Subdomains discovered (2)",
            description="Sources: passive_recon; sample: dimkouts.dev",
            severity=SeverityLevel.LOW,
            asset_id=1,
            asset_name="dimkouts.dev",
            source_tool="passive_recon",
            run_id="run-merge",
        )
        second = Finding(
            title="Subdomains discovered (2)",
            description="Sources: osint_harvester; sample: dimkouts.dev",
            severity=SeverityLevel.LOW,
            asset_id=1,
            asset_name="dimkouts.dev",
            source_tool="osint_harvester",
            run_id="run-merge",
        )
        fp = FindingsNormalizer._subdomain_fingerprint(
            1, ["dimkouts.dev", "www.dimkouts.dev"]
        )
        first.fingerprint = fp
        second.fingerprint = fp
        manager.save_findings_to_database([first])
        manager.save_findings_to_database([second])

        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM finding_observations WHERE run_id = ?",
            ("run-merge",),
        )
        assert cur.fetchone()[0] == 1
        cur.execute(
            "SELECT description FROM finding_observations WHERE run_id = ?",
            ("run-merge",),
        )
        description = cur.fetchone()[0]
        assert "passive_recon" in description
        assert "osint_harvester" in description


class TestReportTemplate:
    def test_report_template_includes_open_ports_column(self):
        findings = [
            Finding(
                title="Open ports discovered (3)",
                description="80/http, 443/https, 8080/http",
                severity=SeverityLevel.INFO,
                verification_state="informational",
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="nmap",
            ),
            Finding(
                title="DNS A records for dimkouts.dev",
                description="A: 104.21.61.102",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="dns_lookup",
            ),
        ]
        assets = [
            AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")
        ]
        report = ReportGenerator().generate_report(
            findings,
            assets,
            {"primary_target": "dimkouts.dev"},
            ReportFormat.MARKDOWN,
        )
        assert "| Open Ports |" in report
        assert "80, 443, 8080" in report
        assert "## Scan Coverage" in report
        assert "Open ports discovered (3)" in report
        assert report.index("## Scan Coverage") < report.index("## Detailed Findings")

    def test_informational_finding_restored_as_info_severity(self):
        conn = _memory_db()
        manager = ReportingManager(conn)
        manager.save_findings_to_database([
            Finding(
                title="Open ports discovered (2)",
                description="80/http, 443/https",
                severity=SeverityLevel.INFO,
                verification_state="informational",
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="nmap",
                run_id="run-info",
            )
        ])
        loaded = manager.get_findings_from_database(run_id="run-info")
        assert len(loaded) == 1
        assert loaded[0].severity == SeverityLevel.INFO


class TestToolResultRetryable:
    def test_transient_error_marked_retryable(self):
        envelope = ToolResultEnvelope.from_raw(
            "gobuster",
            "Error: lookup dimkouts.dev: no such host",
        )
        assert envelope.retryable is True
