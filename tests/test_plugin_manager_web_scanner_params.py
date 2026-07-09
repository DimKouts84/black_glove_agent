import pytest
from src.agent.plugin_manager import PluginManager


class TestPluginManagerWebScannerParams:
    @pytest.fixture
    def pm(self):
        return PluginManager()

    def test_web_server_scanner_target_url_alias(self, pm):
        params = pm._normalize_params("web_server_scanner", {"target_url": "example.com"})
        assert params["target_url"] == "https://example.com"
        assert params["target"] == "https://example.com"

    def test_sqli_scanner_target_alias(self, pm):
        params = pm._normalize_params("sqli_scanner", {"target": "https://example.com/page?id=1"})
        assert params["target_url"] == "https://example.com/page?id=1"
        assert params["target"] == "https://example.com/page?id=1"

    def test_web_vuln_scanner_preserves_existing_target_url(self, pm):
        params = pm._normalize_params(
            "web_vuln_scanner",
            {"target_url": "https://example.com?q=1"},
        )
        assert params["target_url"] == "https://example.com?q=1"
        assert params["target"] == "https://example.com?q=1"
