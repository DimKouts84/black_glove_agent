import pytest
import sys
from pathlib import Path
from typing import Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.plugin_manager import PluginManager
from adapters.dns_lookup import DnsLookupAdapter
from adapters.sublist3r import Sublist3rAdapter
from adapters.wappalyzer import WappalyzerAdapter
from adapters.shodan import ShodanAdapter
from adapters.viewdns import ViewDnsAdapter

class TestNewAdaptersLoading:
    @pytest.fixture
    def plugin_manager(self):
        return PluginManager()

    def test_dns_adapter_loading(self, plugin_manager):
        adapter = plugin_manager.load_adapter("dns_lookup")
        assert isinstance(adapter, DnsLookupAdapter)
        assert adapter.validate_config() is True

    def test_sublist3r_adapter_loading(self, plugin_manager):
        adapter = plugin_manager.load_adapter("sublist3r")
        assert isinstance(adapter, Sublist3rAdapter)
        assert adapter.validate_config() is True

    def test_wappalyzer_adapter_loading(self, plugin_manager):
        adapter = plugin_manager.load_adapter("wappalyzer")
        assert isinstance(adapter, WappalyzerAdapter)
        assert adapter.validate_config() is True

    def test_shodan_adapter_loading(self, plugin_manager):
        # Shodan might warn about missing key but should load
        adapter = plugin_manager.load_adapter("shodan")
        assert isinstance(adapter, ShodanAdapter)
        assert adapter.validate_config() is True

    def test_viewdns_adapter_loading(self, plugin_manager):
        adapter = plugin_manager.load_adapter("viewdns")
        assert isinstance(adapter, ViewDnsAdapter)
        assert adapter.validate_config() is True
