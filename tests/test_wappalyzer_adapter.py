import pytest
from unittest.mock import patch

from src.adapters.wappalyzer import WappalyzerAdapter, CONFIDENCE_THRESHOLD
from src.adapters.interface import AdapterResultStatus


class TestWappalyzerAdapter:
    def test_target_url_alias(self):
        adapter = WappalyzerAdapter({})
        params = {"target_url": "https://example.com"}
        adapter.validate_params(params)
        assert params["url"] == "https://example.com"

    @patch("src.adapters.wappalyzer.wappalyzer.analyze")
    def test_execute_formats_technologies(self, mock_analyze, tmp_path):
        adapter = WappalyzerAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        url = "https://example.com"
        mock_analyze.return_value = {
            url: {
                "nginx": {"version": "1.18", "confidence": 100, "categories": ["Web servers"]},
                "LowConf": {"version": "", "confidence": 10, "categories": []},
            }
        }

        result = adapter.execute({"url": url})
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["count"] == 2

        text = adapter.interpret_result(result)
        assert "nginx" in text
        assert "LowConf" not in text

    def test_interpret_filters_below_threshold(self):
        from src.adapters.interface import AdapterResult, AdapterResultStatus
        adapter = WappalyzerAdapter({})
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "url": "https://example.com",
                "technologies": [
                    {"name": "nginx", "confidence": CONFIDENCE_THRESHOLD},
                    {"name": "noise", "confidence": CONFIDENCE_THRESHOLD - 1},
                ],
            },
            metadata={},
        )
        text = adapter.interpret_result(result)
        assert "nginx" in text
        assert "noise" not in text
