
import pytest
from unittest.mock import MagicMock, patch
from src.adapters.interface import AdapterResultStatus
from src.adapters.web_vuln_scanner import WebVulnScannerAdapter, create_web_vuln_scanner_adapter


class TestWebVulnScannerAdapter:

    @pytest.fixture
    def adapter(self):
        return create_web_vuln_scanner_adapter()

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_xss_detection(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Hello"

        xss_resp = MagicMock()
        xss_resp.text = "Hello <script>console.log('BG_XSS_TEST_80')</script>"

        mock_request.side_effect = [baseline, xss_resp]

        result = adapter.execute({
            "target_url": "http://example.com?q=hello",
            "scans": ["xss"],
        })

        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "xss_reflected"]
        assert len(findings) == 1
        assert findings[0]["parameter"] == "q"
        assert findings[0]["url"]
        assert "BG_XSS_TEST" in findings[0]["payload"]

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_xss_false_positive_baseline_reflection(self, mock_request, adapter):
        payload = "<script>console.log('BG_XSS_TEST_80')</script>"
        baseline = MagicMock()
        baseline.text = f"Hello {payload}"

        injected = MagicMock()
        injected.text = f"Hello {payload}"

        mock_request.side_effect = [baseline, injected]

        result = adapter.execute({
            "target_url": "http://example.com?q=hello",
            "scans": ["xss"],
        })

        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "xss_reflected"]
        assert len(findings) == 0

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_lfi_detection(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "File not found"

        lfi_resp = MagicMock()
        lfi_resp.text = "root:x:0:0:root:/root:/bin/bash"

        mock_request.side_effect = [baseline, lfi_resp]

        result = adapter.execute({
            "target_url": "http://example.com?file=image.jpg",
            "scans": ["lfi"],
        })

        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "path_traversal"]
        assert len(findings) == 1
        assert findings[0]["parameter"] == "file"

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_lfi_false_positive_marker_in_baseline(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Tutorial: root:x:0:0: example"

        mock_request.return_value = baseline

        result = adapter.execute({
            "target_url": "http://example.com?file=image.jpg",
            "scans": ["lfi"],
        })

        assert len(result.data["vulnerabilities"]) == 0

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_ssti_detection(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "User: guest"

        ssti1 = MagicMock()
        ssti1.text = "User: 49"

        ssti2 = MagicMock()
        ssti2.text = "User: 7777777"

        mock_request.side_effect = [baseline, ssti1, ssti2]

        result = adapter.execute({
            "target_url": "http://example.com?name=guest",
            "scans": ["ssti"],
        })

        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "ssti"]
        assert len(findings) == 1
        assert findings[0]["parameter"] == "name"

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_ssti_false_positive_bare_49(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Page 49 of 100"

        injected = MagicMock()
        injected.text = "Page 49 of 100"

        mock_request.side_effect = [baseline, injected, injected]

        result = adapter.execute({
            "target_url": "http://example.com?page=1",
            "scans": ["ssti"],
        })

        assert len(result.data["vulnerabilities"]) == 0

    def test_validate_params_accepts_target_alias(self, adapter):
        adapter.validate_params({"target": "http://valid.com"})

    def test_validate_params(self, adapter):
        with pytest.raises(ValueError):
            adapter.validate_params({})

    def test_interpret_result_includes_url(self, adapter):
        from src.adapters.interface import AdapterResult

        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "vulnerabilities": [{
                    "type": "xss_reflected",
                    "parameter": "q",
                    "url": "http://example.com?q=xss",
                    "payload": "test",
                    "severity": "high",
                }],
                "scanned_params": ["q"],
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "http://example.com?q=xss" in text
        assert "[HIGH]" in text
