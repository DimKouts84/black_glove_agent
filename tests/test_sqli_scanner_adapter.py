import pytest
import time
from unittest.mock import MagicMock, patch
from src.adapters.interface import AdapterResultStatus
from src.adapters.sqli_scanner import SQLiScannerAdapter, create_sqli_scanner_adapter

class TestSQLiScannerAdapter:
    @pytest.fixture
    def adapter(self):
        return create_sqli_scanner_adapter()

    def test_validate_params_success(self, adapter):
        adapter.validate_params({"target_url": "http://example.com/page?id=1"})

    def test_validate_params_missing_target(self, adapter):
        with pytest.raises(ValueError, match="target_url is required"):
            adapter.validate_params({})

    def test_validate_params_invalid_url(self, adapter):
        with pytest.raises(ValueError, match="Invalid target_url"):
            adapter.validate_params({"target_url": "not_a_url"})

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_error_based_detection(self, mock_request, adapter):
        # 1. Baseline response
        baseline = MagicMock()
        baseline.text = "Normal content"
        baseline.content = b"Normal content"
        
        # 2. Injection response with SQL error
        error_resp = MagicMock()
        error_resp.text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        error_resp.content = b"Error..."
        
        mock_request.side_effect = [baseline, error_resp]
        
        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["error"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert len(result.data["vulnerabilities"]) == 1
        vuln = result.data["vulnerabilities"][0]
        assert vuln["type"] == "error_based"
        assert vuln["database"] == "MySQL"
        assert vuln["parameter"] == "id"

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_boolean_blind_detection(self, mock_request, adapter):
        # 1. Baseline
        baseline = MagicMock()
        baseline.text = "Content A" * 100
        baseline.content = b"Content A" * 100 # len 900
        
        # 2. True response (similar to baseline)
        true_resp = MagicMock()
        true_resp.content = b"Content A" * 100 # len 900
        
        # 3. False response (different)
        false_resp = MagicMock()
        false_resp.content = b"Error" # len 5
        
        mock_request.side_effect = [baseline, true_resp, false_resp]
        
        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["boolean"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert len(result.data["vulnerabilities"]) == 1
        vuln = result.data["vulnerabilities"][0]
        assert vuln["type"] == "boolean_blind"
        assert vuln["parameter"] == "id"

    @patch("src.adapters.sqli_scanner.requests.request")
    @patch("src.adapters.sqli_scanner.time.time")
    def test_time_blind_detection(self, mock_time, mock_request, adapter):
        # Manipulate time to simulate sleep
        # Call 1: Baseline (start, end)
        # Call 2: Injection (start, end)
        
        # time.time() called 4 times:
        # 1. BaseAdapter start
        # 2. _check_time_blind start
        # 3. _check_time_blind end (diff = 6.0s > 5s)
        # 4. BaseAdapter end
        mock_time.side_effect = [1000.0, 1100.0, 1106.0, 1200.0]
        
        baseline = MagicMock()
        baseline.content = b"Normal"
        
        sleep_resp = MagicMock()
        sleep_resp.content = b"Normal"
        
        mock_request.side_effect = [baseline, sleep_resp]
        
        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["time"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert len(result.data["vulnerabilities"]) == 1
        vuln = result.data["vulnerabilities"][0]
        assert vuln["type"] == "time_blind"
        assert "sleep(5)" in vuln["evidence"]

    @patch("src.adapters.sqli_scanner.requests.request")
    def test_no_vulnerabilities(self, mock_request, adapter):
        baseline = MagicMock()
        baseline.text = "Safe"
        baseline.content = b"Safe"
        
        # All subsequent requests return safe content
        mock_request.return_value = baseline
        
        result = adapter.execute({
            "target_url": "http://example.com/page.php?id=1",
            "techniques": ["error", "boolean"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert len(result.data["vulnerabilities"]) == 0
