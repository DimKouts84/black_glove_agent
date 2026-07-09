import pytest
from src.agent.plugin_manager import PluginManager


class TestPluginManagerWebWrapperParams:
    @pytest.fixture
    def pm(self):
        return PluginManager()

    def test_gobuster_dir_target_url(self, pm):
        params = pm._normalize_params(
            "gobuster",
            {"mode": "dir", "target_url": "example.com", "wordlist": "/tmp/w.txt"},
        )
        assert params["url"] == "https://example.com"

    def test_gobuster_dns_domain_alias(self, pm):
        params = pm._normalize_params(
            "gobuster",
            {"mode": "dns", "target": "example.com", "wordlist": "/tmp/w.txt"},
        )
        assert params["domain"] == "example.com"

    def test_wappalyzer_target_url(self, pm):
        params = pm._normalize_params("wappalyzer", {"target": "example.com"})
        assert params["url"] == "https://example.com"

    def test_sublist3r_target_alias(self, pm):
        params = pm._normalize_params("sublist3r", {"target": "example.com"})
        assert params["domain"] == "example.com"
