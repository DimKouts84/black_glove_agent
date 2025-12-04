"""
Plugin Manager for Black Glove Pentest Agent

This module implements the plugin system for discovering, loading,
and managing tool adapters with proper validation and lifecycle management.
"""

import logging
import importlib
import importlib.util
import pkgutil
import os
from typing import Any, Dict, List, Optional, Type, Set
from pathlib import Path

from adapters.interface import AdapterInterface, AdapterResult
from adapters.base import BaseAdapter


class AdapterManager:
    """
    Handles adapter lifecycle and configuration management.
    
    Manages the loading, initialization, and cleanup of adapters
    with proper error handling and resource management.
    """
    
    def __init__(self):
        """Initialize the adapter manager."""
        self.logger = logging.getLogger("black_glove.plugin.adapter_manager")
        self._loaded_adapters: Dict[str, AdapterInterface] = {}
        self._adapter_configs: Dict[str, Dict[str, Any]] = {}
    
    def load_adapter(self, adapter_name: str, config: Dict[str, Any] = None) -> AdapterInterface:
        """
        Load and initialize a specific adapter.
        
        Args:
            adapter_name: Name of the adapter to load
            config: Optional configuration for the adapter
            
        Returns:
            AdapterInterface: Loaded adapter instance
            
        Raises:
            ValueError: If adapter name is invalid
            ImportError: If adapter module cannot be imported
            Exception: If adapter initialization fails
        """
        if not adapter_name:
            raise ValueError("Adapter name cannot be empty")
        
        if adapter_name in self._loaded_adapters:
            self.logger.debug(f"Adapter {adapter_name} already loaded")
            return self._loaded_adapters[adapter_name]
        
        if config is None:
            config = self._adapter_configs.get(adapter_name, {})
        
        try:
            # Try to import the adapter module using absolute import from src
            module_name = f"adapters.{adapter_name.lower()}"
            
            self.logger.debug(f"Attempting to import adapter module: {module_name}")
            module = importlib.import_module(module_name)
            
            # Look for adapter class (class name matching adapter name or ending with 'Adapter')
            adapter_class = None
            
            # Build expected class names
            pascal_case = ''.join(word.capitalize() for word in adapter_name.lower().split('_'))
            expected_names = [
                pascal_case + "Adapter",  # e.g., NmapAdapter, GobusterAdapter, DnsLookupAdapter
                pascal_case,               # e.g., Nmap, Gobuster, DnsLookup
                adapter_name.lower(),      # e.g., nmap
                adapter_name.lower() + "adapter",  # e.g., nmapAdapter
            ]
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, AdapterInterface) and 
                    attr != AdapterInterface and 
                    attr != BaseAdapter):
                    
                    # Check if this class matches any expected name pattern
                    for expected in expected_names:
                        if attr_name.lower() == expected.lower():
                            adapter_class = attr
                            break
                    
                    if adapter_class:
                        break
            
            if adapter_class is None:
                raise ImportError(f"No valid adapter class found in module {module_name}. Expected one of: {expected_names}")
            
            # Initialize the adapter
            adapter_instance = adapter_class(config)
            
            # Validate the adapter implements the interface correctly
            if not self.validate_adapter(adapter_instance):
                raise ValueError(f"Adapter {adapter_name} does not properly implement interface")
            
            self._loaded_adapters[adapter_name] = adapter_instance
            self._adapter_configs[adapter_name] = config
            
            self.logger.info(f"Successfully loaded adapter: {adapter_name}")
            return adapter_instance
            
        except ImportError as e:
            self.logger.error(f"Failed to import adapter {adapter_name}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize adapter {adapter_name}: {e}")
            raise
    
    def unload_adapter(self, adapter_name: str) -> bool:
        """
        Unload and cleanup an adapter.
        
        Args:
            adapter_name: Name of the adapter to unload
            
        Returns:
            bool: True if adapter was unloaded, False if not found
        """
        if adapter_name not in self._loaded_adapters:
            return False
        
        try:
            adapter = self._loaded_adapters[adapter_name]
            adapter.cleanup()
            del self._loaded_adapters[adapter_name]
            self.logger.info(f"Successfully unloaded adapter: {adapter_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error unloading adapter {adapter_name}: {e}")
            return False
    
    def validate_adapter(self, adapter: AdapterInterface) -> bool:
        """
        Verify that an adapter properly implements the interface.
        
        Args:
            adapter: Adapter instance to validate
            
        Returns:
            bool: True if adapter is valid, False otherwise
        """
        try:
            # Check that required methods exist and are callable
            required_methods = ['validate_config', 'execute', 'get_info', 'validate_params']
            
            for method_name in required_methods:
                if not hasattr(adapter, method_name):
                    self.logger.error(f"Adapter missing required method: {method_name}")
                    return False
                
                method = getattr(adapter, method_name)
                if not callable(method):
                    self.logger.error(f"Adapter method {method_name} is not callable")
                    return False
            
            # Test basic functionality
            info = adapter.get_info()
            if not isinstance(info, dict):
                self.logger.error("Adapter get_info() must return a dictionary")
                return False
            
            # Validate config (this should not raise exceptions for default config)
            try:
                adapter.validate_config()
            except Exception as e:
                self.logger.warning(f"Adapter config validation failed: {e}")
                # Don't fail validation on config issues, just warn
            
            self.logger.debug(f"Adapter validation passed for: {adapter.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Adapter validation failed: {e}")
            return False
    
    def get_adapter_info(self, adapter_name: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata and capabilities for an adapter.
        
        Args:
            adapter_name: Name of the adapter
            
        Returns:
            Dict containing adapter information, or None if adapter not found
        """
        if adapter_name in self._loaded_adapters:
            return self._loaded_adapters[adapter_name].get_info()
        
        # Try to load and get info without keeping it loaded
        try:
            adapter = self.load_adapter(adapter_name)
            info = adapter.get_info()
            self.unload_adapter(adapter_name)  # Clean up
            return info
        except Exception as e:
            self.logger.error(f"Failed to get info for adapter {adapter_name}: {e}")
            return None
    
    def list_loaded_adapters(self) -> List[str]:
        """
        Get list of currently loaded adapters.
        
        Returns:
            List of loaded adapter names
        """
        return list(self._loaded_adapters.keys())
    
    def cleanup_all(self) -> None:
        """Clean up all loaded adapters."""
        adapter_names = list(self._loaded_adapters.keys())
        for adapter_name in adapter_names:
            self.unload_adapter(adapter_name)


class PluginManager:
    """
    Main plugin manager for discovering and managing adapters.
    
    Handles plugin discovery from the adapters directory, loading,
    validation, and execution of adapters with proper error handling.
    """
    
    def __init__(self, adapters_path: str = None, config: Dict[str, Any] = None, policy_engine = None):
        """
        Initialize the plugin manager.
        
        Args:
            adapters_path: Path to adapters directory (defaults to src/adapters)
            config: Plugin manager configuration
            policy_engine: Optional policy engine for safety enforcement
        """
        self.logger = logging.getLogger("black_glove.plugin.manager")
        
        if adapters_path is None:
            # Default to src/adapters relative to current file
            self.adapters_path = Path(__file__).parent.parent / "adapters"
        else:
            self.adapters_path = Path(adapters_path)
        
        self.config = config or {}
        self.policy_engine = policy_engine  # NEW: Store policy engine for centralized enforcement
        self.adapter_manager = AdapterManager()
        self._discovered_adapters: Set[str] = set()
        
        self.logger.info(f"Plugin manager initialized with adapters path: {self.adapters_path}")
    
    def discover_adapters(self) -> List[str]:
        """
        Discover available adapters in the adapters directory.
        
        Returns:
            List of discovered adapter names
        """
        self.logger.debug(f"Discovering adapters in: {self.adapters_path}")
        
        if not self.adapters_path.exists():
            self.logger.warning(f"Adapters path does not exist: {self.adapters_path}")
            return []
        
        discovered = set()
        
        # Look for Python files in adapters directory
        try:
            for item in self.adapters_path.iterdir():
                if item.is_file() and item.suffix == '.py' and item.name != '__init__.py':
                    # Remove .py extension and get adapter name
                    adapter_name = item.stem
                    if adapter_name != 'interface' and adapter_name != 'base':
                        discovered.add(adapter_name)
                        self.logger.debug(f"Discovered adapter: {adapter_name}")
                
                elif item.is_dir() and not item.name.startswith('__'):
                    # Look for modules in subdirectories
                    if (item / '__init__.py').exists():
                        discovered.add(item.name)
                        self.logger.debug(f"Discovered adapter module: {item.name}")
        
        except Exception as e:
            self.logger.error(f"Error during adapter discovery: {e}")
        
        self._discovered_adapters = discovered
        self.logger.info(f"Discovered {len(discovered)} adapters: {sorted(discovered)}")
        return sorted(list(discovered))
    
    def load_adapter(self, adapter_name: str, config: Dict[str, Any] = None) -> AdapterInterface:
        """
        Load a specific adapter by name.
        
        Args:
            adapter_name: Name of the adapter to load
            config: Optional configuration for the adapter
            
        Returns:
            AdapterInterface: Loaded adapter instance
        """
        return self.adapter_manager.load_adapter(adapter_name, config)
    
    def run_adapter(self, adapter_name: str, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute an adapter with given parameters.
        
        This method enforces safety policy checks (target validation and rate limiting)
        before executing the adapter, ensuring consistent security across all execution paths.
        
        Args:
            adapter_name: Name of the adapter to execute
            params: Parameters for adapter execution
            
        Returns:
            AdapterResult: Result from adapter execution (or error if policy blocked)
        """
        self.logger.debug(f"Running adapter {adapter_name} with params: {params}")
        
        # CENTRALIZED POLICY ENFORCEMENT
        if self.policy_engine:
            # 1. Extract target from parameters (try multiple common keys)
            target = (
                params.get("target") or 
                params.get("domain") or 
                params.get("host") or 
                params.get("url")
            )
            
            # 2. Validate target if present
            if target:
                from .models import Asset
                asset = Asset(target=target, tool_name=adapter_name, parameters=params)
                
                if not self.policy_engine.validate_asset(asset):
                    self.logger.warning(f"BLOCKED: Policy violation for target {target}")
                    from adapters.interface import AdapterResultStatus
                    return AdapterResult(
                        status=AdapterResultStatus.ERROR,
                        data=None,
                        metadata={"error": "Policy violation"},
                        error_message=f"BLOCKED: Target '{target}' is not authorized."
                    )
            
            # 3. Check rate limits
            if not self.policy_engine.enforce_rate_limits(adapter_name):
                self.logger.warning(f"BLOCKED: Rate limit exceeded for {adapter_name}")
                from adapters.interface import AdapterResultStatus
                return AdapterResult(
                    status=AdapterResultStatus.ERROR,
                    data=None,
                    metadata={"error": "Rate limit exceeded"},
                    error_message=f"BLOCKED: Rate limit exceeded for '{adapter_name}'."
                )
        
        # Load adapter if not already loaded
        if adapter_name not in self.adapter_manager.list_loaded_adapters():
            self.load_adapter(adapter_name)
        
        adapter = self.adapter_manager._loaded_adapters[adapter_name]
        
        # Validate parameters
        try:
            adapter.validate_params(params)
        except Exception as e:
            raise ValueError(f"Invalid parameters for adapter {adapter_name}: {e}")
        
        # Execute adapter
        try:
            result = adapter.execute(params)
            
            # Record rate limit usage after successful execution
            if self.policy_engine:
                self.policy_engine.rate_limiter.record_request(adapter_name)
            
            self.logger.info(f"Adapter {adapter_name} executed with status: {result.status.value}")
            return result
        except Exception as e:
            self.logger.error(f"Adapter {adapter_name} execution failed: {e}")
            raise
    
    def validate_adapter(self, adapter_name: str) -> bool:
        """
        Validate that an adapter properly implements the interface.
        
        Args:
            adapter_name: Name of the adapter to validate
            
        Returns:
            bool: True if adapter is valid, False otherwise
        """
        try:
            adapter = self.load_adapter(adapter_name)
            return self.adapter_manager.validate_adapter(adapter)
        except Exception as e:
            self.logger.error(f"Adapter validation failed for {adapter_name}: {e}")
            return False
    
    def get_adapter_info(self, adapter_name: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata and capabilities for an adapter.
        
        Args:
            adapter_name: Name of the adapter
            
        Returns:
            Dict containing adapter information, or None if not found
        """
        return self.adapter_manager.get_adapter_info(adapter_name)
    
    def list_available_adapters(self) -> List[str]:
        """
        Get list of all available adapters (discovered + loaded).
        
        Returns:
            List of available adapter names
        """
        discovered = self._discovered_adapters
        loaded = set(self.adapter_manager.list_loaded_adapters())
        return sorted(list(discovered.union(loaded)))
    
    def list_loaded_adapters(self) -> List[str]:
        """
        Get list of currently loaded adapters.
        
        Returns:
            List of loaded adapter names
        """
        return self.adapter_manager.list_loaded_adapters()
    
    def unload_adapter(self, adapter_name: str) -> bool:
        """
        Unload and cleanup an adapter.
        
        Args:
            adapter_name: Name of the adapter to unload
            
        Returns:
            bool: True if adapter was unloaded, False if not found
        """
        return self.adapter_manager.unload_adapter(adapter_name)
    
    def cleanup(self) -> None:
        """Clean up all loaded adapters and resources."""
        self.logger.info("Cleaning up plugin manager")
        self.adapter_manager.cleanup_all()


# Factory function for creating plugin manager instances
def create_plugin_manager(adapters_path: str = None, config: Dict[str, Any] = None, policy_engine = None) -> PluginManager:
    """
    Factory function to create a plugin manager instance.
    
    Args:
        adapters_path: Optional path to adapters directory
        config: Optional configuration dictionary
        policy_engine: Optional policy engine for safety enforcement
        
    Returns:
        PluginManager: Configured plugin manager instance
    """
    return PluginManager(adapters_path, config, policy_engine)


# Context manager for plugin manager
class PluginManagerContext:
    """
    Context manager for plugin manager to ensure proper cleanup.
    """
    
    def __init__(self, adapters_path: str = None, config: Dict[str, Any] = None):
        self.adapters_path = adapters_path
        self.config = config
        self.plugin_manager = None
    
    def __enter__(self):
        self.plugin_manager = create_plugin_manager(self.adapters_path, self.config)
        return self.plugin_manager
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.plugin_manager:
            self.plugin_manager.cleanup()
