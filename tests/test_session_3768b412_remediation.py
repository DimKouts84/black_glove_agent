"""Regression tests for session 3768b412 remediation."""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.gobuster import GobusterAdapter, create_gobuster_adapter
from adapters.interface import AdapterResultStatus
from agent.models import AssetModel, AssetType, SeverityLevel
from agent.reporting import Finding, FindingsNormalizer, ReportGenerator, ReportFormat

DIR_STDOUT = """
/admin (Status: 301) [Size: 0]
/images (Status: 200) [Size: 1243]
""".strip()

SOFT404_STDERR = (
    "Error: the server returns a status code that matches the provided options "
    "for non existing urls. https://dimkouts.dev/256b93f6-abc => 200 (Length: 754). "
    "To continue please exclude the status code or the length"
)


class SequentialRunner:
    def __init__(self, results: List[Dict[str, Any]]):
        self.results = results
        self.calls = 0
        self.specs: List[Dict[str, Any]] = []

    def run(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        self.specs.append(spec)
        idx = min(self.calls, len(self.results) - 1)
        self.calls += 1
        return dict(self.results[idx])


class TestGobusterSoft404:
    def test_parse_soft404_exclude_length(self):
        assert GobusterAdapter._parse_soft404_exclude_length(SOFT404_STDERR) == 754
        assert GobusterAdapter._parse_soft404_exclude_length("") is None

    def test_gobuster_retries_with_exclude_length_on_soft404(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            GobusterAdapter,
            "_probe_soft404_length",
            staticmethod(lambda url: None),
        )

        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = SequentialRunner([
                {
                    "status": "error",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": SOFT404_STDERR,
                },
                {
                    "status": "success",
                    "exit_code": 0,
                    "stdout": DIR_STDOUT,
                    "stderr": "",
                },
            ])
            adapter = create_gobuster_adapter({"_runner": runner})
            result = adapter.execute(
                {
                    "mode": "dir",
                    "url": "https://dimkouts.dev",
                    "wordlist": "/path/to/wordlist.txt",
                }
            )

            assert result.status == AdapterResultStatus.SUCCESS
            assert runner.calls == 2
            retry_args = runner.specs[1]["args"]
            assert "--exclude-length" in retry_args
            assert "754" in retry_args
            assert result.metadata.get("soft_404_excluded_length") == 754
        finally:
            os.chdir(cwd)

    def test_gobuster_soft404_returns_partial_after_retry_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            GobusterAdapter,
            "_probe_soft404_length",
            staticmethod(lambda url: None),
        )

        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = SequentialRunner([
                {
                    "status": "error",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": SOFT404_STDERR,
                },
                {
                    "status": "error",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": SOFT404_STDERR,
                },
            ])
            adapter = create_gobuster_adapter({"_runner": runner})
            result = adapter.execute(
                {
                    "mode": "dir",
                    "url": "https://dimkouts.dev",
                    "wordlist": "/path/to/wordlist.txt",
                }
            )

            assert result.status == AdapterResultStatus.PARTIAL
            assert "SPA catch-all" in (result.error_message or "")
            assert result.metadata.get("soft_404_excluded_length") == 754
        finally:
            os.chdir(cwd)


class TestPassiveReconEmptyPartial:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")

    def test_passive_recon_empty_partial_emits_no_scan_completed_finding(
        self, normalizer, asset, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)

        output = {
            "crt_sh": {"certificates": [], "count": 0},
            "coverage": {"crt_sh_ok": False, "wayback_ok": False},
            "errors": {},
            "interpretation": "Passive recon completed with no external data.",
        }

        findings = normalizer.normalize_tool_output("passive_recon", output, asset)
        assert findings == []
        assert all("scan completed" not in (f.title or "") for f in findings)


class TestReportRegression7dcdd:
    def test_report_still_has_scan_coverage_and_open_ports(self):
        findings = [
            Finding(
                title="Open ports discovered (2)",
                description="80/http, 443/https",
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
        assert "80, 443" in report
        assert "## Scan Coverage" in report
        assert "Open ports discovered (2)" in report
