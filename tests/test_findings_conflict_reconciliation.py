"""Tests for cross-tool finding conflict reconciliation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.reporting import FindingsNormalizer, Finding, SeverityLevel, ReportGenerator, ReportFormat
from agent.models import AssetModel, AssetType


def test_hsts_conflict_downgrades_missing_header():
    normalizer = FindingsNormalizer()
    findings = [
        Finding(
            title="Technology detected: HSTS",
            severity=SeverityLevel.LOW,
            asset_id=1,
            source_tool="wappalyzer",
            run_id="run-a",
            description="confidence: 100%",
        ),
        Finding(
            title="Missing Strict-Transport-Security",
            severity=SeverityLevel.HIGH,
            asset_id=1,
            source_tool="web_server_scanner",
            run_id="run-a",
            description="Enforces HTTPS connections (HSTS)",
        ),
    ]
    mutated = normalizer.reconcile_cross_tool_conflicts(
        findings, run_id="run-a", current_findings=[findings[1]]
    )

    missing = next(f for f in findings if f.title.startswith("Missing Strict"))
    assert missing.severity == SeverityLevel.INFO
    assert missing.verification_state == "conflicted"
    assert "fingerprinting" in missing.description.lower()
    assert mutated == [missing]


def test_reconcile_scoped_to_current_run_only():
    normalizer = FindingsNormalizer()
    stale_hsts = Finding(
        title="Technology detected: HSTS",
        severity=SeverityLevel.LOW,
        asset_id=1,
        source_tool="wappalyzer",
        run_id="old-run",
        description="from prior https scan",
    )
    missing = Finding(
        title="Missing Strict-Transport-Security",
        severity=SeverityLevel.HIGH,
        asset_id=1,
        source_tool="web_server_scanner",
        run_id="new-run",
        description="header absent on http",
    )
    mutated = normalizer.reconcile_cross_tool_conflicts(
        [stale_hsts, missing],
        run_id="new-run",
        current_findings=[missing],
    )
    assert missing.verification_state == "indicator"
    assert missing.severity == SeverityLevel.HIGH
    assert mutated == []


def test_already_conflicted_not_remutated():
    normalizer = FindingsNormalizer()
    conflicted = Finding(
        title="Missing Strict-Transport-Security",
        severity=SeverityLevel.INFO,
        asset_id=1,
        source_tool="web_server_scanner",
        run_id="run-a",
        verification_state="conflicted",
        description="already reconciled",
    )
    wapp = Finding(
        title="Technology detected: HSTS",
        severity=SeverityLevel.LOW,
        asset_id=1,
        source_tool="wappalyzer",
        run_id="run-a",
    )
    mutated = normalizer.reconcile_cross_tool_conflicts(
        [wapp, conflicted], run_id="run-a", current_findings=[]
    )
    assert mutated == []


def test_conflicted_findings_excluded_from_key_findings():
    findings = [
        Finding(
            title="Missing Strict-Transport-Security",
            severity=SeverityLevel.INFO,
            asset_id=1,
            asset_name="dimkouts_dev",
            source_tool="web_server_scanner",
            verification_state="conflicted",
            description="reconciled",
        ),
        Finding(
            title="Missing Content-Security-Policy",
            severity=SeverityLevel.HIGH,
            asset_id=1,
            asset_name="dimkouts_dev",
            source_tool="web_server_scanner",
            description="csp missing",
        ),
    ]
    assets = [
        AssetModel(id=1, name="dimkouts_dev", type=AssetType.DOMAIN, value="dimkouts.dev"),
    ]
    gen = ReportGenerator()
    report = gen.generate_report(
        findings,
        assets,
        {"primary_target": "dimkouts.dev"},
        ReportFormat.MARKDOWN,
    )
    assert "Missing Content-Security-Policy" in report
    assert "Reconciled Observations" in report
    assert report.count("Missing Strict-Transport-Security") >= 1
