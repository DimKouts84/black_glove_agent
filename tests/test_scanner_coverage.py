"""Tests for zero-parameter scan coverage semantics."""

from src.adapters.web_vuln_scanner import WebVulnScannerAdapter
from src.adapters.sqli_scanner import SQLiScannerAdapter
from src.adapters.interface import AdapterResultStatus


class TestScannerCoverage:
    def test_web_vuln_scanner_no_params_not_applicable(self):
        adapter = WebVulnScannerAdapter()
        result = adapter._execute_impl({"target_url": "https://example.com"})
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["not_applicable"] is True
        assert result.data["coverage"]["untested"] is True
        text = adapter.interpret_result(result)
        assert "not applicable" in text.lower()

    def test_sqli_scanner_no_params_not_applicable(self):
        adapter = SQLiScannerAdapter()
        result = adapter._execute_impl({"target_url": "https://example.com"})
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["not_applicable"] is True
        text = adapter.interpret_result(result)
        assert "not applicable" in text.lower()
