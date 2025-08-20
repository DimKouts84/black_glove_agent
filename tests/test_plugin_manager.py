"""
Tests for Plugin Manager Implementation

This module contains tests for the plugin manager, adapter manager,
and related plugin system components.
"""

import pytest
import tempfile
import os
from pathlib import Path
from typing import Dict, Any

from src.agent.plugin_manager import (
    PluginManager, AdapterManager, create_plugin_manager, PluginManagerContext
)
from src.adapters.interface import AdapterInterface, AdapterResult, AdapterResultStatus
from src.adapters.example import ExampleAdapter


class TestAdapterManager:
    """Test cases for the AdapterManager implementation."""
    
    def test_adapter_manager_initialization(self):
        """Test AdapterManager initialization."""
        manager = AdapterManager()
        
        assert manager._loaded_adapters == {}
        assert manager._adapter_configs == {}
    
    def test_adapter_manager_load_adapter(self):
        """Test loading adapters."""
        manager = AdapterManager()
        
        # Load example adapter
        adapter = manager.load_adapter("example")
        
        assert isinstance(adapter, ExampleAdapter)
        assert "example" in manager._loaded_adapters
        assert manager._loaded_adapters["example"] == adapter
    
    def test_adapter_manager_load_adapter_with_config(self):
        """Test loading adapter with configuration."""
        manager = AdapterManager()
        config = {"test": "value", "timeout": 30}
        
        adapter = manager.load_adapter("example", config)
        
        assert adapter.config == config
        assert manager._adapter_configs["example"] == config
    
    def test_adapter_manager_load_already_loaded_adapter(self):
        """Test loading already loaded adapter."""
        manager = AdapterManager()
        
        # Load adapter first time
        adapter1 = manager.load_adapter("example")
        
        # Load adapter second time (should return same instance)
        adapter2 = manager.load_adapter("example")
        
        assert adapter1 is adapter2
    
    def test_adapter_manager_unload_adapter(self):
        """Test unloading adapters."""
        manager = AdapterManager()
        
        # Load adapter
        manager.load_adapter("example")
        assert "example" in manager._loaded_adapters
        
        # Unload adapter
        result = manager.unload_adapter("example")
        assert result is True
        assert "example" not in manager._loaded_adapters
        
        # Try to unload non-existent adapter
        result = manager.unload_adapter("nonexistent")
        assert result is False
    
    def test_adapter_manager_validate_adapter(self):
        """Test adapter validation."""
        manager = AdapterManager()
        
        # Load valid adapter
        adapter = manager.load_adapter("example")
        assert manager.validate_adapter(adapter) is True
    
    def test_adapter_manager_get_adapter_info(self):
        """Test getting adapter information."""
        manager = AdapterManager()
        
        # Get info for loaded adapter
        info = manager.get_adapter_info("example")
        assert info is not None
        assert info["name"] == "ExampleAdapter"
        assert "capabilities" in info
    
    def test_adapter_manager_list_loaded_adapters(self):
        """Test listing loaded adapters."""
        manager = AdapterManager()
        
        # Initially empty
        assert manager.list_loaded_adapters() == []
        
        # Load an adapter
        manager.load_adapter("example")
        assert manager.list_loaded_adapters() == ["example"]
    
    def test_adapter_manager_cleanup_all(self):
        """Test cleaning up all adapters."""
        manager = AdapterManager()
        
        # Load some adapters
        manager.load_adapter("example")
        assert len(manager._loaded_adapters) == 1
        
        # Clean up all
        manager.cleanup_all()
        assert len(manager._loaded_adapters) == 0


class TestPluginManager:
    """Test cases for the PluginManager implementation."""
    
    def test_plugin_manager_initialization(self):
        """Test PluginManager initialization."""
        # Test with default path
        manager = PluginManager()
        assert manager.adapters_path.exists()
        assert isinstance(manager.adapter_manager, AdapterManager)
        assert manager._discovered_adapters == set()
        
        # Test with custom path
        custom_path = Path("/tmp/test_adapters")
        manager = PluginManager(adapters_path=str(custom_path))
        assert manager.adapters_path == custom_path
    
    def test_plugin_manager_discover_adapters(self):
        """Test adapter discovery."""
        manager = PluginManager()
        
        # Discover adapters
        adapters = manager.discover_adapters()
        
        # Should find at least the example adapter
        assert "example" in adapters
        assert len(adapters) >= 1
    
    def test_plugin_manager_load_adapter(self):
        """Test loading adapters through plugin manager."""
        manager = PluginManager()
        
        # Load adapter
        adapter = manager.load_adapter("example")
        
        assert isinstance(adapter, ExampleAdapter)
        assert "example" in manager.adapter_manager._loaded_adapters
    
    def test_plugin_manager_run_adapter(self):
        """Test running adapters."""
        manager = PluginManager()
        
        # Run example adapter
        params = {"command": "echo Hello Plugin Manager!"}
        result = manager.run_adapter("example", params)
        
        assert isinstance(result, AdapterResult)
        assert result.status == AdapterResultStatus.SUCCESS
        assert "Hello Plugin Manager!" in result.data["stdout"]
    
    def test_plugin_manager_run_adapter_with_invalid_params(self):
        """Test running adapter with invalid parameters."""
        manager = PluginManager()
        
        # Run with invalid params (missing required 'command')
        with pytest.raises(ValueError, match="Invalid parameters"):
            manager.run_adapter("example", {})
    
    def test_plugin_manager_validate_adapter(self):
        """Test adapter validation through plugin manager."""
        manager = PluginManager()
        
        # Validate example adapter
        assert manager.validate_adapter("example") is True
    
    def test_plugin_manager_get_adapter_info(self):
        """Test getting adapter information through plugin manager."""
        manager = PluginManager()
        
        # Get info
        info = manager.get_adapter_info("example")
        assert info is not None
        assert info["name"] == "ExampleAdapter"
    
    def test_plugin_manager_list_available_adapters(self):
        """Test listing available adapters."""
        manager = PluginManager()
        
        # Discover adapters first
        discovered = manager.discover_adapters()
        
        # List available adapters
        available = manager.list_available_adapters()
        
        # Should include discovered adapters
        assert "example" in available
        assert set(discovered).issubset(set(available))
    
    def test_plugin_manager_list_loaded_adapters(self):
        """Test listing loaded adapters."""
        manager = PluginManager()
        
        # Initially empty
        assert manager.list_loaded_adapters() == []
        
        # Load an adapter
        manager.load_adapter("example")
        assert manager.list_loaded_adapters() == ["example"]
    
    def test_plugin_manager_unload_adapter(self):
        """Test unloading adapters through plugin manager."""
        manager = PluginManager()
        
        # Load adapter
        manager.load_adapter("example")
        assert "example" in manager.list_loaded_adapters()
        
        # Unload adapter
        result = manager.unload_adapter("example")
        assert result is True
        assert "example" not in manager.list_loaded_adapters()
    
    def test_plugin_manager_cleanup(self):
        """Test plugin manager cleanup."""
        manager = PluginManager()
        
        # Load some adapters
        manager.load_adapter("example")
        assert len(manager.adapter_manager._loaded_adapters) == 1
        
        # Clean up
        manager.cleanup()
        assert len(manager.adapter_manager._loaded_adapters) == 0


class TestPluginManagerIntegration:
    """Integration tests for plugin manager components."""
    
    def test_complete_adapter_lifecycle(self):
        """Test complete adapter lifecycle management."""
        manager = PluginManager()
        
        # 1. Discover adapters
        adapters = manager.discover_adapters()
        assert "example" in adapters
        
        # 2. Load adapter
        adapter = manager.load_adapter("example", {"timeout": 10})
        assert adapter is not None
        assert adapter.config["timeout"] == 10
        
        # 3. Validate adapter
        assert manager.validate_adapter("example") is True
        
        # 4. Get adapter info
        info = manager.get_adapter_info("example")
        assert info is not None
        assert "ExampleAdapter" in info["name"]
        
        # 5. Run adapter
        result = manager.run_adapter("example", {"command": "echo Lifecycle Test"})
        assert result.status == AdapterResultStatus.SUCCESS
        assert "Lifecycle Test" in result.data["stdout"]
        
        # 6. List loaded adapters
        loaded = manager.list_loaded_adapters()
        assert "example" in loaded
        
        # 7. Unload adapter
        assert manager.unload_adapter("example") is True
        assert "example" not in manager.list_loaded_adapters()
    
    def test_multiple_adapter_management(self):
        """Test managing multiple adapters."""
        manager = PluginManager()
        
        # Load multiple adapters (same adapter with different configs)
        adapter1 = manager.load_adapter("example", {"name": "adapter1"})
        adapter2 = manager.load_adapter("example", {"name": "adapter2"})
        
        # Both should be loaded
        loaded = manager.list_loaded_adapters()
        assert len(loaded) == 1  # Same adapter name, so only one instance
        
        # Run with different parameters
        result1 = manager.run_adapter("example", {"command": "echo Test1"})
        result2 = manager.run_adapter("example", {"command": "echo Test2"})
        
        assert result1.status == AdapterResultStatus.SUCCESS
        assert result2.status == AdapterResultStatus.SUCCESS
    
    def test_plugin_manager_error_handling(self):
        """Test error handling in plugin manager."""
        manager = PluginManager()
        
        # Try to load non-existent adapter
        with pytest.raises((ImportError, Exception)):
            manager.load_adapter("nonexistent_adapter")
        
        # Try to run non-existent adapter
        with pytest.raises((ImportError, Exception)):
            manager.run_adapter("nonexistent_adapter", {"test": "param"})
        
        # Try to validate non-existent adapter
        assert manager.validate_adapter("nonexistent_adapter") is False
    
    def test_adapter_discovery_with_empty_directory(self):
        """Test adapter discovery with empty directory."""
        # Create temporary empty directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = PluginManager(adapters_path=str(temp_path))
            
            adapters = manager.discover_adapters()
            assert adapters == []  # Should be empty


class TestPluginManagerContext:
    """Test cases for PluginManagerContext."""
    
    def test_plugin_manager_context_manager(self):
        """Test plugin manager context manager."""
        with PluginManagerContext() as manager:
            assert isinstance(manager, PluginManager)
            
            # Test basic functionality within context
            adapters = manager.discover_adapters()
            assert isinstance(adapters, list)
        
        # Manager should be cleaned up after context exit
        # (This is harder to test directly, but the context manager should work)


def test_create_plugin_manager_factory():
    """Test plugin manager factory function."""
    # Test default creation
    manager = create_plugin_manager()
    assert isinstance(manager, PluginManager)
    
    # Test creation with parameters
    custom_path = "/tmp/test"
    config = {"test": "value"}
    manager = create_plugin_manager(adapters_path=custom_path, config=config)
    
    assert isinstance(manager, PluginManager)
    # Handle path separator differences between platforms
    assert str(manager.adapters_path).replace('\\', '/') == custom_path
    assert manager.config == config


if __name__ == "__main__":
    pytest.main([__file__])
