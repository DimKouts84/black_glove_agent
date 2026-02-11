
import pytest
from unittest.mock import MagicMock, patch
from src.adapters.interface import AdapterResultStatus
from src.adapters.web_vuln_scanner import WebVulnScannerAdapter, create_web_vuln_scanner_adapter

class TestWebVulnScannerAdapter:

    @pytest.fixture
    def adapter(self):
        return create_web_vuln_scanner_adapter()

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_security_headers(self, mock_request, adapter):
        # Baseline response with limited headers
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/html", "Server": "nginx/1.0"}
        resp.text = "Safe content"
        mock_request.return_value = resp
        
        result = adapter.execute({
            "target_url": "http://example.com",
            "scans": ["headers"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        findings = result.data["vulnerabilities"]
        
        # Expect missing CSP, X-Frame, HSTS, X-Content-Type + Server info
        header_issues = [f for f in findings if f["type"] == "missing_header"]
        info_issues = [f for f in findings if f["type"] == "info_disclosure"]
        
        assert len(header_issues) == 4
        assert len(info_issues) == 1
        assert info_issues[0]["header"] == "Server"

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_xss_detection(self, mock_request, adapter):
        # 1. Baseline
        baseline = MagicMock()
        baseline.text = "Hello"
        
        # 2. XSS Triggered
        xss_resp = MagicMock()
        xss_resp.text = "Hello <script>console.log('BG_XSS_TEST_80')</script>"
        
        mock_request.side_effect = [baseline, xss_resp]
        
        result = adapter.execute({
            "target_url": "http://example.com?q=hello",
            "scans": ["xss"]
        })
        
        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "xss_reflected"]
        assert len(findings) == 1
        assert findings[0]["parameter"] == "q"
        assert "BG_XSS_TEST" in findings[0]["payload"]

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_lfi_detection(self, mock_request, adapter):
        # 1. Baseline
        baseline = MagicMock()
        baseline.text = "File not found"
        
        # 2. LFI Triggered
        lfi_resp = MagicMock()
        lfi_resp.text = "root:x:0:0:root:/root:/bin/bash"
        
        mock_request.side_effect = [baseline, lfi_resp]
        
        result = adapter.execute({
            "target_url": "http://example.com?file=image.jpg",
            "scans": ["lfi"]
        })
        
        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "path_traversal"]
        assert len(findings) == 1
        assert findings[0]["parameter"] == "file"
        assert "passwd" in findings[0]["payload"]

    @patch("src.adapters.web_vuln_scanner.requests.request")
    def test_ssti_detection(self, mock_request, adapter):
        # 1. Baseline
        baseline = MagicMock()
        baseline.text = "User: guest"
        
        # 2. SSTI Triggered (7*7 evaluated to 49)
        ssti_resp = MagicMock()
        ssti_resp.text = "User: 49"
        
        mock_request.side_effect = [baseline, ssti_resp]
        
        result = adapter.execute({
            "target_url": "http://example.com?name=guest",
            "scans": ["ssti"]
        })
        
        findings = [f for f in result.data["vulnerabilities"] if f["type"] == "ssti"]
        assert len(findings) == 1
        assert findings[0]["parameter"] == "name"
        assert "49" in findings[0]["evidence"]

    def test_validate_params(self, adapter):
        with pytest.raises(ValueError):
            adapter.validate_params({})
            
        adapter.validate_params({"target_url": "http://valid.com"})
