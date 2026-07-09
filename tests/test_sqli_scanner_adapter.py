import pytest
from unittest.mock import MagicMock, patch
from src.adapters.interface import AdapterResultStatus
from src.adapters.sqli_scanner import SQLiScannerAdapter, create_sqli_scanner_adapter


class TestSQLiScannerAdapter:
    @pytest.fixture
    def adapter(self):
        return create_sqli_scanner_adapter()

    def test_validate_params_success(self, adapter):
        adapter.validate_params({"target_url": "http://example.com/page?id=1"})
        adapter.validate_params({"target": "http://example.com/page?id=1"})

    def test_validate_params_missing_target(self, adapter):
        with pytest.raises(ValueError, match="target_url or target is required"):
            adapter.validate_params({})

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_error_based_detection(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Normal content"
        baseline.content = b"Normal content"

        error_resp = MagicMock()
        error_resp.text = (
            "You have an error in your SQL syntax; check the manual that corresponds "
            "to your MySQL server version"
        )
        error_resp.content = b"Error..."

        mock_request.side_effect = [baseline, error_resp]

        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["error"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        assert len(result.data["vulnerabilities"]) == 1
        vuln = result.data["vulnerabilities"][0]
        assert vuln["type"] == "error_based"
        assert vuln["severity"] == "critical"
        assert vuln["database"] == "MySQL"

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_error_based_false_positive_baseline_error(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "You have an error in your SQL syntax"
        baseline.content = b"error"

        injected = MagicMock()
        injected.text = "You have an error in your SQL syntax"
        injected.content = b"error"

        mock_request.side_effect = [baseline, injected, injected, injected]

        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["error"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        assert len(result.data["vulnerabilities"]) == 0

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_boolean_blind_detection(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Content A" * 100
        baseline.content = b"Content A" * 100
        baseline.status_code = 200

        true_resp = MagicMock()
        true_resp.text = "Content A" * 100
        true_resp.content = b"Content A" * 100
        true_resp.status_code = 200

        false_resp = MagicMock()
        false_resp.text = "Error"
        false_resp.content = b"Error"
        false_resp.status_code = 200

        mock_request.side_effect = [baseline, true_resp, false_resp]

        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["boolean"],
        })

        assert len(result.data["vulnerabilities"]) == 1
        assert result.data["vulnerabilities"][0]["type"] == "boolean_blind"
        assert result.data["vulnerabilities"][0]["severity"] == "medium"

    @patch("src.adapters.sqli_scanner.requests.request")
    @patch("src.adapters.sqli_scanner.time.time")
    def test_time_blind_detection(self, mock_time, mock_request, adapter):
        mock_time.side_effect = [0.0, 0.0, 0.5, 0.5, 6.0, 6.0, 12.0, 12.0]

        baseline = MagicMock()
        baseline.content = b"Normal"

        sleep_resp = MagicMock()
        sleep_resp.content = b"Normal"

        mock_request.side_effect = [baseline, baseline, sleep_resp, sleep_resp]

        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["time"],
        })

        assert len(result.data["vulnerabilities"]) == 1
        vuln = result.data["vulnerabilities"][0]
        assert vuln["type"] == "time_blind"
        assert vuln["severity"] == "high"

    @patch("src.adapters.sqli_scanner.requests.request")
    @patch("src.adapters.sqli_scanner.time.time")
    def test_time_blind_false_positive_single_slow_request(self, mock_time, mock_request, adapter):
        mock_time.side_effect = [0.0, 0.0, 0.5, 0.5, 6.0, 6.0, 6.5, 6.5]

        baseline = MagicMock()
        baseline.content = b"Normal"

        slow_once = MagicMock()
        slow_once.content = b"Normal"

        fast_confirm = MagicMock()
        fast_confirm.content = b"Normal"

        mock_request.side_effect = [baseline, baseline, slow_once, fast_confirm]

        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["time"],
        })

        assert len(result.data["vulnerabilities"]) == 0

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_no_vulnerabilities(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Safe"
        baseline.content = b"Safe"
        baseline.status_code = 200

        mock_request.return_value = baseline

        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["error", "boolean"],
        })

        assert len(result.data["vulnerabilities"]) == 0

    def test_interpret_result_uses_severity_not_blanket_critical(self, adapter):
        from src.adapters.interface import AdapterResult

        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "vulnerabilities": [{
                    "type": "boolean_blind",
                    "parameter": "id",
                    "url": "http://example.com?id=1",
                    "payload": " AND 1=1",
                    "severity": "medium",
                }],
                "scanned_params": ["id"],
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "[MEDIUM]" in text
        assert "[CRITICAL]" not in text
