"""
Integration tests for centralized policy enforcement.

Validates that safety policy checks (target validation and rate limiting)
work consistently through the centralized PluginManager enforcement.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile
from unittest.mock import Mock, MagicMock, patch

from src.agent.plugin_manager import PluginManager, create_plugin_manager
from src.agent.policy_engine import PolicyEngine, create_policy_engine
from src.agent.models import Asset
from src.adapters.interface import AdapterResult, AdapterResultStatus


@pytest.fixture
def policy_config():
    """Create a restrictive policy configuration for testing."""
    return {
        "rate_limiting": {
            "window_size": 60,
            "max_requests": 2,  # Low limit for testing
            "global_max_requests": 5
        },
        "target_validation": {
            "authorized_networks": ["192.168.1.0/24"],
            "authorized_domains": ["example.com", "test.local"]
        },
        "allowed_exploits": []
    }


@pytest.fixture
def policy_engine(policy_config):
    """Create a policy engine instance for testing."""
    print(f"DEBUG: Creating policy engine with config: {policy_config}")
    engine = create_policy_engine(policy_config)
    print(f"DEBUG: Created engine authorized domains: {engine.target_validator._authorized_domains}")
    import inspect
    print(f"DEBUG: TargetValidator.__init__ source:\n{inspect.getsource(engine.target_validator.__init__)}")
    print(f"DEBUG: TargetValidator._load_authorized_domains source:\n{inspect.getsource(engine.target_validator._load_authorized_domains)}")
    return engine


@pytest.fixture
def plugin_manager_with_policy(policy_engine):
    """Create a PluginManager with policy enforcement enabled."""
    return create_plugin_manager(policy_engine=policy_engine)


class TestCentralizedPolicyEnforcement:
    """Test that PluginManager enforces policy centrally."""
    
    def test_plugin_manager_has_policy_engine(self, plugin_manager_with_policy, policy_engine):
        """Verify PluginManager stores policy_engine reference."""
        assert hasattr(plugin_manager_with_policy, 'policy_engine')
        assert plugin_manager_with_policy.policy_engine == policy_engine
    
    def test_unauthorized_target_blocked(self, plugin_manager_with_policy):
        """Verify PluginManager blocks unauthorized targets."""
        # Attempt to run adapter with unauthorized target
        params = {"target": "unauthorized.com", "domain": "unauthorized.com"}
        
        # Mock the adapter loading
        mock_adapter = Mock()
        mock_adapter.validate_params = Mock()
        
        with patch.object(plugin_manager_with_policy.adapter_manager, 'list_loaded_adapters', return_value=['whois']):
            with patch.object(plugin_manager_with_policy.adapter_manager, '_loaded_adapters', {'whois': mock_adapter}):
                result = plugin_manager_with_policy.run_adapter("whois", params)
        
        # Should return error result
        assert result.status.value == AdapterResultStatus.ERROR.value
        assert "BLOCKED" in result.error_message
        assert "not authorized" in result.error_message.lower()
    
    def test_authorized_target_allowed(self, plugin_manager_with_policy):
        """Verify PluginManager allows authorized targets."""
        # Attempt to run adapter with authorized target
        params = {"domain": "example.com"}
        
        # Mock successful adapter execution
        mock_adapter = Mock()
        mock_adapter.validate_params = Mock()
        mock_adapter.execute = Mock(return_value=AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"test": "data"},
            metadata={}
        ))
        
        with patch.object(plugin_manager_with_policy.adapter_manager, 'list_loaded_adapters', return_value=['whois']):
            with patch.object(plugin_manager_with_policy.adapter_manager, '_loaded_adapters', {'whois': mock_adapter}):
                print(f"DEBUG: Calling run_adapter with params: {params}")
                print(f"DEBUG: Policy engine is: {plugin_manager_with_policy.policy_engine}")
                import src.agent.plugin_manager
                print(f"DEBUG: PluginManager module path: {src.agent.plugin_manager.__file__}")
                print(f"DEBUG: plugin_manager type: {type(plugin_manager_with_policy)}")
                print(f"DEBUG: run_adapter type: {type(plugin_manager_with_policy.run_adapter)}")
                result = plugin_manager_with_policy.run_adapter("whois", params)
        
        # Should succeed
        assert result.status.value == AdapterResultStatus.SUCCESS.value
    
    def test_rate_limit_enforced(self, plugin_manager_with_policy):
        """Verify PluginManager enforces rate limits."""
        params = {"domain": "example.com"}
        
        # Mock successful adapter execution
        mock_adapter = Mock()
        mock_adapter.validate_params = Mock()
        mock_adapter.execute = Mock(return_value=AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"test": "data"},
            metadata={}
        ))
        
        # Mock target validation to ensure we hit rate limiting logic
        with patch.object(plugin_manager_with_policy.policy_engine.target_validator, 'validate_target', return_value=True):
            with patch.object(plugin_manager_with_policy.adapter_manager, 'list_loaded_adapters', return_value=['whois']):
                with patch.object(plugin_manager_with_policy.adapter_manager, '_loaded_adapters', {'whois': mock_adapter}):
                    # First 2 requests should succeed (max_requests = 2)
                    for i in range(2):
                        result = plugin_manager_with_policy.run_adapter("whois", params)
                        assert result.status.value == AdapterResultStatus.SUCCESS.value, f"Request {i+1} should succeed"
                    
                    # Third request should be rate limited
                    result = plugin_manager_with_policy.run_adapter("whois", params)
                    assert result.status.value == AdapterResultStatus.ERROR.value
                    assert "Rate limit exceeded" in result.error_message
    
    def test_no_policy_engine_allows_execution(self):
        """Verify that PluginManager without policy_engine still works."""
        # Create plugin manager WITHOUT policy engine
        plugin_manager = create_plugin_manager(policy_engine=None)
        
        assert plugin_manager.policy_engine is None
        
        # Should allow execution even with unauthorized target
        params = {"domain": "unauthorized.com"}
        
        mock_adapter = Mock()
        mock_adapter.validate_params = Mock()
        mock_adapter.execute = Mock(return_value=AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"test": "data"},
            metadata={}
        ))
        
        with patch.object(plugin_manager.adapter_manager, 'list_loaded_adapters', return_value=['whois']):
            with patch.object(plugin_manager.adapter_manager, '_loaded_adapters', {'whois': mock_adapter}):
                result = plugin_manager.run_adapter("whois", params)
        
        # Should succeed (no policy enforcement)
        assert result.status.value == AdapterResultStatus.SUCCESS.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

