import pytest
from src.agent.plugin_manager import PluginManager


class TestPluginManagerSpecializedIntelParams:
    @pytest.fixture
    def pm(self):
        return PluginManager()

    def test_osint_harvester_domain_alias(self, pm):
        params = pm._normalize_params("osint_harvester", {"domain": "example.com"})
        assert params["target"] == "example.com"
        assert params["domain"] == "example.com"

    def test_passive_recon_target_alias(self, pm):
        params = pm._normalize_params("passive_recon", {"target": "example.com"})
        assert params["domain"] == "example.com"
        assert params["target"] == "example.com"

    def test_credential_tester_target_url_alias(self, pm):
        params = pm._normalize_params(
            "credential_tester",
            {"target_url": "http://example.com", "protocol": "http_basic"},
        )
        assert params["target"] == "http://example.com"
        assert params["target_url"] == "http://example.com"
