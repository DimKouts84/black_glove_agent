import pytest
from unittest.mock import MagicMock, patch
from src.adapters.web_server_scanner import WebServerScannerAdapter, create_web_server_scanner_adapter
from src.adapters.interface import AdapterResultStatus


class TestWebServerScannerAdapter:
    @pytest.fixture
    def adapter(self):
        return create_web_server_scanner_adapter()

    def test_validate_params_valid_target(self, adapter):
        adapter.validate_params({"target": "example.com", "checks": ["headers"]})

    def test_validate_params_valid_target_url(self, adapter):
        adapter.validate_params({"target_url": "https://example.com", "checks": ["headers"]})

    def test_validate_params_missing_target(self, adapter):
        with pytest.raises(ValueError, match="target_url or target is required"):
            adapter.validate_params({})

    def test_validate_params_invalid_check(self, adapter):
        with pytest.raises(ValueError, match="Invalid check"):
            adapter.validate_params({"target": "example.com", "checks": ["invalid_check"]})

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_security_headers_missing(self, mock_request, adapter):
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_request.return_value = mock_response

        findings = adapter._check_security_headers("http://example.com")

        assert any(f["title"] == "Missing X-Frame-Options" for f in findings)
        assert not any(f.get("severity") == "OK" for f in findings)

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_default_files_validates_content(self, mock_request, adapter):
        def request_side_effect(method, url, **kwargs):
            if "black_glove_probe_not_found" in url:
                resp = MagicMock()
                resp.status_code = 404
                resp.content = b"Not Found" * 10
                return resp
            if url.endswith("/.env"):
                resp = MagicMock()
                resp.status_code = 200
                resp.content = b"DB_HOST=localhost\nSECRET_KEY=abc"
                return resp
            resp = MagicMock()
            resp.status_code = 404
            resp.content = b"Not Found" * 10
            return resp

        mock_request.side_effect = request_side_effect

        findings = adapter._check_default_files("http://example.com")

        assert any("Found: /.env" in f["title"] for f in findings)

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_default_files_rejects_soft_404(self, mock_request, adapter):
        soft_404 = b"Custom 404 page" * 20

        def request_side_effect(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = soft_404
            return resp

        mock_request.side_effect = request_side_effect

        findings = adapter._check_default_files("http://example.com")
        assert len(findings) == 0

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_default_files_rejects_spa_html_as_env(self, mock_request, adapter):
        spa_html = (
            b"<!DOCTYPE html><html><head><title>App</title></head>"
            b"<body><div id=\"root\" data-version=\"1.0\"></div></body></html>"
        )

        def request_side_effect(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = spa_html
            return resp

        mock_request.side_effect = request_side_effect

        findings = adapter._check_default_files("http://example.com")
        assert not any("Found: /.env" in f["title"] for f in findings)

    @patch("src.adapters.web_server_scanner.requests.request")
    def test_check_http_methods(self, mock_request, adapter):
        mock_options = MagicMock()
        mock_options.headers = {"Allow": "GET, POST, OPTIONS, TRACE"}

        mock_trace = MagicMock()
        mock_trace.status_code = 200

        mock_put = MagicMock()
        mock_put.status_code = 405

        mock_request.side_effect = [mock_options, mock_trace, mock_put]

        findings = adapter._check_http_methods("http://example.com")
        assert any("TRACE" in f["title"] for f in findings)

    def test_interpret_result_excludes_ok_severity(self, adapter):
        from src.adapters.interface import AdapterResult

        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "target": "http://example.com",
                "findings": [
                    {"title": "Missing CSP", "detail": "desc", "severity": "HIGH"},
                    {"title": "X-Frame present", "detail": "ok", "severity": "OK"},
                ],
                "summary": {
                    "total_findings": 1,
                    "severity_counts": {"HIGH": 1},
                },
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "Missing CSP" in text
        assert "X-Frame present" not in text
        assert "1 High/Critical" in text
