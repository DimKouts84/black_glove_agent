"""
Example Adapter for Black Glove Pentest Agent

This module provides a simple example adapter implementation that demonstrates
the adapter pattern and can be used as a template for creating new adapters.
"""

import time
import subprocess
from typing import Any, Dict

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus


class ExampleAdapter(BaseAdapter):
    """
    Example adapter demonstrating the adapter pattern.
    
    This adapter shows how to implement a simple tool adapter that
    executes a basic command and returns structured results.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the example adapter.
        
        Args:
            config: Adapter configuration dictionary
        """
        super().__init__(config)
        self._required_config_fields = []  # No required config for example
        self._required_params = ["command"]  # Required parameter for execution
        self.version = "1.0.0"
    
    def validate_config(self) -> bool:
        """
        Validate the adapter configuration.
        
        Returns:
            bool: True if configuration is valid
        """
        # Call parent validation
        super().validate_config()
        
        # Example-specific validation
        if "timeout" in self.config:
            if not isinstance(self.config["timeout"], (int, float)) or self.config["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        return True
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Validate execution parameters.
        
        Args:
            params: Parameters to validate
            
        Returns:
            bool: True if parameters are valid
        """
        # Call parent validation
        super().validate_params(params)
        
        # Example-specific parameter validation
        if "command" in params:
            if not isinstance(params["command"], str):
                raise ValueError("Command must be a string")
        
        if "timeout" in params:
            if not isinstance(params["timeout"], (int, float)) or params["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        return True
    
    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute the example command.
        
        Args:
            params: Execution parameters containing 'command' and optional 'timeout'
            
        Returns:
            AdapterResult: Standardized result structure
        """
        command = params["command"]
        timeout = params.get("timeout", self.config.get("timeout", 30))
        
        self.logger.info(f"Executing command: {command}")
        
        try:
            # Execute the command
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            execution_time = time.time() - start_time
            
            # Determine status based on return code
            status = AdapterResultStatus.SUCCESS if result.returncode == 0 else AdapterResultStatus.FAILURE
            
            # Store raw evidence
            evidence_filename = f"example_output_{int(time.time())}.txt"
            evidence_path = self._store_evidence(result.stdout + result.stderr, evidence_filename)
            
            return AdapterResult(
                status=status,
                data={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                },
                metadata={
                    "adapter": self.name,
                    "command": command,
                    "timestamp": time.time(),
                    "execution_time": execution_time
                },
                execution_time=execution_time,
                evidence_path=evidence_path
            )
            
        except subprocess.TimeoutExpired:
            return AdapterResult(
                status=AdapterResultStatus.TIMEOUT,
                data=None,
                metadata={
                    "adapter": self.name,
                    "command": command,
                    "timeout": timeout,
                    "timestamp": time.time()
                },
                error_message=f"Command timed out after {timeout} seconds"
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "command": command,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get adapter information.
        
        Returns:
            Dict containing adapter information
        """
        base_info = super().get_info()
        base_info.update({
            "name": "ExampleAdapter",
            "version": self.version,
            "description": "Example adapter demonstrating the adapter pattern",
            "capabilities": base_info["capabilities"] + ["command_execution", "timeout_control"],
            "requirements": ["subprocess"],
            "example_usage": {
                "command": "echo 'Hello, Black Glove!'",
                "timeout": 10
            }
        })
        return base_info


# Example usage function
def create_example_adapter(config: Dict[str, Any] = None) -> ExampleAdapter:
    """
    Factory function to create an example adapter instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        ExampleAdapter: Configured adapter instance
    """
    if config is None:
        config = {}
    return ExampleAdapter(config)
