"""Tests for finding_observations run-scoped ledger."""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.db import create_findings_table, create_assets_table, create_finding_observations_table
from agent.reporting import ReportingManager, Finding, SeverityLevel, ReportFormat


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


def test_two_runs_same_fingerprint_both_retained():
    conn = _memory_db()
    manager = ReportingManager(conn)

    f1 = Finding(
        title="Missing Content-Security-Policy",
        severity=SeverityLevel.HIGH,
        asset_id=1,
        source_tool="web_server_scanner",
        description="first run",
        run_id="run-1",
    )
    manager.save_findings_to_database([f1])

    f2 = Finding(
        title="Missing Content-Security-Policy",
        severity=SeverityLevel.HIGH,
        asset_id=1,
        source_tool="web_server_scanner",
        description="second run",
        run_id="run-2",
    )
    manager.save_findings_to_database([f2])

    run1 = manager.get_findings_from_database(run_id="run-1")
    run2 = manager.get_findings_from_database(run_id="run-2")

    assert len(run1) == 1
    assert len(run2) == 1
    assert run1[0].description == "first run"
    assert run2[0].description == "second run"

    report1 = manager.generate_assessment_report(ReportFormat.MARKDOWN, run_id="run-1")
    assert "1 assets" in report1 or "1 assets." in report1
    assert "0 issues" not in report1
