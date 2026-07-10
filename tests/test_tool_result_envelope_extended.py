"""Extended tests for ToolResultEnvelope semantics."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.tool_result import ToolResultEnvelope


class TestToolResultEnvelopeExtended:
    def test_partial_adapter_status(self):
        envelope = ToolResultEnvelope.from_raw(
            "whois",
            {
                "domain": "dimkouts.dev",
                "registrar": None,
                "adapter_status": "partial",
                "warnings": ["RDAP HTTP 503"],
                "interpretation": "WHOIS/RDAP lookup for dimkouts.dev returned no registration data.",
            },
        )
        assert envelope.status == "partial"
        assert envelope.warnings == ["RDAP HTTP 503"]

    def test_not_applicable_status(self):
        envelope = ToolResultEnvelope.from_raw(
            "web_vuln_scanner",
            {
                "not_applicable": True,
                "coverage": {"scanned_params": 0, "untested": True},
                "interpretation": "no parameters",
            },
        )
        assert envelope.status == "not_applicable"
        assert envelope.coverage.get("untested") is True

    def test_not_applicable_wins_over_adapter_success(self):
        """Regression: adapter_status success must not mask not_applicable scans."""
        envelope = ToolResultEnvelope.from_raw(
            "web_vuln_scanner",
            {
                "adapter_status": "success",
                "not_applicable": True,
                "coverage": {
                    "scanned_params": 0,
                    "untested": True,
                    "reason": "no_query_parameters",
                },
                "interpretation": "no URL query parameters to test",
            },
        )
        assert envelope.status == "not_applicable"

    def test_string_report_content(self):
        report = "# Report\n" + ("line\n" * 200)
        envelope = ToolResultEnvelope.from_raw("generate_report", report)
        assert envelope.status == "success"
        assert envelope.report_content is not None
        assert "Report" in envelope.summary

    def test_to_trace_details(self):
        envelope = ToolResultEnvelope(
            status="partial",
            tool_name="whois",
            summary="partial data",
            warnings=["warn"],
            coverage={"has_core_fields": False},
            evidence_paths=["/tmp/evidence.txt"],
        )
        details = envelope.to_trace_details()
        assert details["tool"] == "whois"
        assert details["status"] == "partial"
        assert details["warnings"] == ["warn"]
        assert details["evidence_paths"] == ["/tmp/evidence.txt"]
