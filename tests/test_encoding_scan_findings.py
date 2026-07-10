"""Encoding and false scan-completed finding regressions."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from adapters.web_vuln_scanner import WebVulnScannerAdapter
from adapters.interface import AdapterResult, AdapterResultStatus
from agent.reporting import FindingsNormalizer, EvidenceStorage
from agent.models import AssetModel, AssetType
from unittest.mock import patch, MagicMock


def test_web_vuln_interpret_ascii_safe():
    adapter = WebVulnScannerAdapter({})
    result = AdapterResult(
        status=AdapterResultStatus.SUCCESS,
        data={
            "target_url": "http://example.com",
            "not_applicable": True,
            "message": "No URL query parameters available to test",
        },
        metadata={},
    )
    text = adapter.interpret_result(result)
    assert "\u2014" not in text
    assert "not applicable" in text.lower()


def test_zero_param_scan_produces_no_findings():
    asset = AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")
    normalizer = FindingsNormalizer()
    with patch.object(EvidenceStorage, "store_evidence", return_value={"path": "/tmp/x", "hash": "h"}):
        findings = normalizer.normalize_tool_output(
            "web_vuln_scanner",
            {
                "not_applicable": True,
                "coverage": {"untested": True, "reason": "no_query_parameters"},
                "interpretation": "no parameters",
            },
            asset,
        )
    assert findings == []


def test_empty_sublist3r_no_scan_completed_finding():
    asset = AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")
    normalizer = FindingsNormalizer()
    with patch.object(EvidenceStorage, "store_evidence", return_value={"path": "/tmp/x", "hash": "h"}):
        findings = normalizer.normalize_tool_output(
            "sublist3r",
            {
                "subdomains": [],
                "interpretation": "Sublist3r found NO subdomains for example.com.",
            },
            asset,
        )
    assert findings == []
