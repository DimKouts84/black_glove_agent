import pytest
from unittest.mock import MagicMock, patch
from src.adapters.web_server_scanner import WebServerScannerAdapter, create_web_server_scanner_adapter
from src.adapters.interface import AdapterResultStatus

class TestWebServerScannerAdapter:
    @pytest.fixture
    def adapter(self):
        return create_web_server_scanner_adapter()

    def test_validate_params_valid(self, adapter):
        params = {"target": "example.com", "checks": ["headers"]}
        assert adapter.validate_params(params) is None

    def test_validate_params_missing_target(self, adapter):
        with pytest.raises(ValueError, match="Target URL or hostname is required"):
            adapter.validate_params({})

    def test_validate_params_invalid_check(self, adapter):
        with pytest.raises(ValueError, match="Invalid check"):
            adapter.validate_params({"target": "example.com", "checks": ["invalid_check"]})

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_security_headers_missing(self, mock_request, adapter):
        # Mock response with no security headers
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_request.return_value = mock_response

        findings = adapter._check_security_headers("http://example.com")
        
        # Should find missing headers
        assert any(f["title"] == "Missing X-Frame-Options" for f in findings)
        assert any(f["title"] == "Missing Content-Security-Policy" for f in findings)

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_security_headers_present(self, mock_request, adapter):
        # Mock response with security headers
        mock_response = MagicMock()
        mock_response.headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'"
        }
        mock_request.return_value = mock_response

        findings = adapter._check_security_headers("http://example.com")
        
        # Should report present headers as OK/INFO
        assert any(f["title"] == "X-Frame-Options present" for f in findings)

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_default_files_found(self, mock_request, adapter):
        # Mock finding a phpinfo file
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"phpinfo()"
        mock_request.return_value = mock_response

        # Only run check for one path to keep test fast/simple
        # We can retain the logic but mock the loop or just check results
        # easier: mock the list of paths temporarily or just rely on finding something
        
        # Use a targeted approach:
        # We'll mock the response. The adapter iterates DANGEROUS_PATHS.
        # We just need one to match.
        
        findings = adapter._check_default_files("http://example.com")
        
        # Since we mocked 200 for ALL requests in the loop, it enters "Found" branch
        assert len(findings) > 0
        assert findings[0]["check"] == "files"
        assert findings[0]["severity"] in ["HIGH", "MEDIUM", "CRITICAL", "LOW", "INFO"]

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_http_methods(self, mock_request, adapter):
        # Mock OPTIONS response
        mock_options = MagicMock()
        mock_options.headers = {"Allow": "GET, POST, OPTIONS, TRACE"}
        
        # Mock TRACE response
        mock_trace = MagicMock()
        mock_trace.status_code = 200
        
        # Mock PUT response
        mock_put = MagicMock()
        mock_put.status_code = 405 # Method Not Allowed
        
        # Side effect for sequence of calls: OPTIONS, TRACE, PUT
        mock_request.side_effect = [mock_options, mock_trace, mock_put]

        findings = adapter._check_http_methods("http://example.com")
        
        titles = [f["title"] for f in findings]
        assert "OPTIONS: Advertised methods" in titles
        assert "Dangerous method advertised: TRACE" in titles
        assert "TRACE method is enabled" in titles
        assert "PUT method accepted" not in titles

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_server_version(self, mock_request, adapter):
        mock_response = MagicMock()
        mock_response.headers = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4"}
        mock_request.return_value = mock_response

        findings = adapter._check_server_version("http://example.com")
        
        titles = [f["title"] for f in findings]
        assert "Server version disclosed" in titles
        assert "X-Powered-By header disclosed" in titles

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_execute_success(self, mock_request, adapter):
        # minimal mock for a full run
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.status_code = 404
        mock_request.return_value = mock_response
        
        result = adapter.execute({"target": "example.com", "checks": ["headers"]})
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert "findings" in result.data
        assert result.data["target"] == "http://example.com"
