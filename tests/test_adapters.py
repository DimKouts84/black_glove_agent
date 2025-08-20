"""
Tests for Adapter Interface and Base Classes

This module contains tests for the adapter interface, base adapter implementation,
and example adapter to ensure proper functionality and contract adherence.
"""

import pytest
import time
from typing import Dict, Any

from src.adapters.interface import (
    AdapterInterface, AdapterResult, AdapterResultStatus, 
    AdapterError, AdapterConfigError, AdapterExecutionError
)
from src.adapters.base import BaseAdapter
from src.adapters.example import ExampleAdapter, create_example_adapter


class TestAdapterInterface:
    """Test cases for the AdapterInterface abstract base class."""
    
    def test_adapter_interface_cannot_be_instantiated(self):
        """Test that AdapterInterface cannot be directly instantiated."""
        with pytest.raises(TypeError):
            AdapterInterface({})
    
    def test_adapter_result_status_enum(self):
        """Test AdapterResultStatus enumeration values."""
        assert AdapterResultStatus.SUCCESS.value == "success"
        assert AdapterResultStatus.FAILURE.value == "failure"
        assert AdapterResultStatus.PARTIAL.value == "partial"
        assert AdapterResultStatus.TIMEOUT.value == "timeout"
        assert AdapterResultStatus.ERROR.value == "error"
    
    def test_adapter_result_creation(self):
        """Test AdapterResult creation and default values."""
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"test": "data"},
            metadata={"key": "value"}
        )
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data == {"test": "data"}
        assert result.metadata == {"key": "value"}
        assert result.error_message is None
        assert result.execution_time is None
        assert result.evidence_path is None


class TestBaseAdapter:
    """Test cases for the BaseAdapter implementation."""
    
    class ConcreteAdapter(BaseAdapter):
        """Concrete implementation of BaseAdapter for testing."""
        
        def __init__(self, config: Dict[str, Any]):
            super().__init__(config)
            self._required_config_fields = ["required_field"]
            self._required_params = ["required_param"]
        
        def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"result": "test"},
                metadata={"test": True}
            )
        
        def get_info(self) -> Dict[str, Any]:
            base_info = super().get_info()
            base_info.update({
                "name": "ConcreteAdapter",
                "description": "Test concrete adapter"
            })
            return base_info
    
    def test_base_adapter_initialization(self):
        """Test BaseAdapter initialization."""
        config = {"test": "config"}
        adapter = self.ConcreteAdapter(config)
        
        assert adapter.config == config
        assert adapter.name == "ConcreteAdapter"
        assert adapter.version == "1.0.0"
        assert adapter.last_execution_time is None
    
    def test_base_adapter_config_validation(self):
        """Test BaseAdapter configuration validation."""
        # Valid configuration
        config = {"required_field": "value"}
        adapter = self.ConcreteAdapter(config)
        assert adapter.validate_config() is True
        
        # Invalid configuration - missing required field
        config = {"other_field": "value"}
        adapter = self.ConcreteAdapter(config)
        with pytest.raises(ValueError, match="Missing required configuration fields"):
            adapter.validate_config()
    
    def test_base_adapter_param_validation(self):
        """Test BaseAdapter parameter validation."""
        config = {"required_field": "value"}
        adapter = self.ConcreteAdapter(config)
        
        # Valid parameters
        params = {"required_param": "value"}
        assert adapter.validate_params(params) is True
        
        # Invalid parameters - missing required param
        params = {"other_param": "value"}
        with pytest.raises(ValueError, match="Missing required parameters"):
            adapter.validate_params(params)
    
    def test_base_adapter_execution(self):
        """Test BaseAdapter execution with timing."""
        config = {"required_field": "value"}
        adapter = self.ConcreteAdapter(config)
        
        params = {"required_param": "value"}
        result = adapter.execute(params)
        
        assert isinstance(result, AdapterResult)
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data == {"result": "test"}
        assert result.execution_time is not None
        assert result.execution_time >= 0  # Can be 0 on fast systems
        assert adapter.last_execution_time is not None
    
    def test_base_adapter_execution_error_handling(self):
        """Test BaseAdapter error handling during execution."""
        
        class FailingAdapter(BaseAdapter):
            def __init__(self, config: Dict[str, Any]):
                super().__init__(config)
            
            def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
                raise Exception("Test error")
            
            def get_info(self) -> Dict[str, Any]:
                return {"name": "FailingAdapter"}
        
        adapter = FailingAdapter({})
        result = adapter.execute({})
        
        assert result.status == AdapterResultStatus.ERROR
        assert result.error_message == "Test error"
        assert result.execution_time is not None


class TestExampleAdapter:
    """Test cases for the ExampleAdapter implementation."""
    
    def test_example_adapter_initialization(self):
        """Test ExampleAdapter initialization."""
        adapter = create_example_adapter()
        assert isinstance(adapter, ExampleAdapter)
        assert adapter.name == "ExampleAdapter"
    
    def test_example_adapter_config_validation(self):
        """Test ExampleAdapter configuration validation."""
        # Valid configuration
        config = {"timeout": 30}
        adapter = ExampleAdapter(config)
        assert adapter.validate_config() is True
        
        # Invalid timeout
        config = {"timeout": -1}
        adapter = ExampleAdapter(config)
        with pytest.raises(ValueError, match="Timeout must be a positive number"):
            adapter.validate_config()
    
    def test_example_adapter_param_validation(self):
        """Test ExampleAdapter parameter validation."""
        adapter = create_example_adapter()
        
        # Valid parameters
        params = {"command": "echo test"}
        assert adapter.validate_params(params) is True
        
        # Invalid command type
        params = {"command": 123}
        with pytest.raises(ValueError, match="Command must be a string"):
            adapter.validate_params(params)
    
    def test_example_adapter_successful_execution(self):
        """Test ExampleAdapter successful command execution."""
        adapter = create_example_adapter()
        params = {"command": "echo Hello, Black Glove!"}
        
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert "Hello, Black Glove!" in result.data["stdout"]
        assert result.execution_time is not None
        assert result.evidence_path is not None
    
    def test_example_adapter_timeout_execution(self):
        """Test ExampleAdapter timeout handling."""
        adapter = create_example_adapter()
        # Use a command that will take longer than timeout
        # ping with high count on Windows will take time
        params = {"command": "ping -n 10 127.0.0.1", "timeout": 1}
        
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.TIMEOUT
        assert "timed out" in result.error_message
    
    def test_example_adapter_get_info(self):
        """Test ExampleAdapter information retrieval."""
        adapter = create_example_adapter()
        info = adapter.get_info()
        
        assert info["name"] == "ExampleAdapter"
        assert info["version"] == "1.0.0"
        assert "command_execution" in info["capabilities"]
        assert "example_usage" in info


# Integration test
class TestAdapterIntegration:
    """Integration tests for adapter components."""
    
    def test_adapter_lifecycle(self):
        """Test complete adapter lifecycle from creation to cleanup."""
        # Create adapter
        adapter = create_example_adapter({"timeout": 10})
        
        # Get info
        info = adapter.get_info()
        assert info["name"] == "ExampleAdapter"
        
        # Execute command
        params = {"command": "echo Lifecycle Test"}
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert "Lifecycle Test" in result.data["stdout"]
        
        # Check timing
        assert adapter.last_execution_time is not None
        
        # Cleanup
        adapter.cleanup()  # Should not raise any exceptions
    
    def test_multiple_executions(self):
        """Test multiple adapter executions with timing tracking."""
        adapter = create_example_adapter()
        
        # First execution
        result1 = adapter.execute({"command": "echo First"})
        time1 = adapter.last_execution_time
        
        # Second execution
        result2 = adapter.execute({"command": "echo Second"})
        time2 = adapter.last_execution_time
        
        # Both should be successful
        assert result1.status == AdapterResultStatus.SUCCESS
        assert result2.status == AdapterResultStatus.SUCCESS
        
        # Timing should be updated
        assert time1 is not None
        assert time2 is not None
        assert time2 != time1


if __name__ == "__main__":
    pytest.main([__file__])
