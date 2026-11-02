import pytest
from src.agent.plugin_manager import PluginManager


class TestPluginManagerNetworkParams:
    @pytest.fixture
    def pm(self):
        return PluginManager()

    def test_ssl_check_target_to_host(self, pm):
        params = pm._normalize_params("ssl_check", {"target": "example.com"})
        assert params["host"] == "example.com"

    def test_viewdns_target_strips_scheme(self, pm):
        params = pm._normalize_params("viewdns", {"target": "https://example.com:443"})
        assert params["host"] == "example.com"

    def test_dns_lookup_target_alias(self, pm):
        params = pm._normalize_params("dns_lookup", {"target": "example.com"})
        assert params["domain"] == "example.com"

    def test_dns_recon_domain_to_target(self, pm):
        params = pm._normalize_params("dns_recon", {"domain": "example.com"})
        assert params["target"] == "example.com"

    def test_nmap_domain_alias(self, pm):
        params = pm._normalize_params("nmap", {"domain": "scanme.nmap.org"})
        assert params["target"] == "scanme.nmap.org"

    def test_nmap_keeps_ipv6_and_copies_port(self, pm):
        params = pm._normalize_params("nmap", {"target": "cam.local:8443"})
        assert params["target"] == "cam.local"
        assert params["ports"] == "8443"
        ipv6 = pm._normalize_params("nmap", {"target": "2001:db8::1"})
        assert ipv6["target"] == "2001:db8::1"
        assert "ports" not in ipv6

    def test_nmap_accepts_target_url(self, pm):
        params = pm._normalize_params("nmap", {"target_url": "https://example.com"})
        assert params["target"] == "example.com"

    def test_ssl_check_uses_embedded_port(self, pm):
        params = pm._normalize_params("ssl_check", {"target": "https://cam.local:8443"})
        assert params["host"] == "cam.local"
        assert params["port"] == 8443

    def test_whois_target_alias(self, pm):
        params = pm._normalize_params("whois", {"target": "example.com"})
        assert params["domain"] == "example.com"
