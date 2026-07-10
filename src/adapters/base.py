"""
Base Adapter Implementation for Black Glove Pentest Agent

This module provides a base adapter class that implements common functionality
for all tool adapters, reducing boilerplate code and ensuring consistency.
"""

import time
import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

from .interface import AdapterInterface, AdapterResult, AdapterResultStatus
from .transient_errors import is_transient_adapter_error


class BaseAdapter(AdapterInterface):
    """
    Base adapter class providing common functionality for all adapters.
    
    This class implements shared logic such as timing, logging, and basic
    validation while still requiring specific implementations for core methods.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the base adapter.
        
        Args:
            config: Adapter configuration dictionary
        """
        super().__init__(config)
        self.logger = logging.getLogger(f"black_glove.adapter.{self.name}")
        self._initialized = False
        self._last_execution_time = None
    
    def validate_config(self) -> bool:
        """
        Basic configuration validation.
        
        This implementation checks for required configuration keys
        and can be extended by subclasses for specific validation.
        
        Returns:
            bool: True if configuration is valid
            
        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")
        
        # Check for common required fields
        required_fields = getattr(self, '_required_config_fields', [])
        missing_fields = [field for field in required_fields if field not in self.config]
        
        if missing_fields:
            raise ValueError(f"Missing required configuration fields: {missing_fields}")
        
        return True
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Basic parameter validation.
        
        This implementation checks for required parameters and can be
        extended by subclasses for specific validation.
        
        Args:
            params: Parameters to validate
            
        Returns:
            bool: True if parameters are valid
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not isinstance(params, dict):
            raise ValueError("Parameters must be a dictionary")
        
        # Check for common required parameters
        required_params = getattr(self, '_required_params', [])
        missing_params = [param for param in required_params if param not in params]
        
        if missing_params:
            raise ValueError(f"Missing required parameters: {missing_params}")
        
        return True
    
    def execute(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute the adapter with timing and error handling.
        
        This method provides common execution logic including timing,
        logging, and basic error handling. Subclasses should implement
        _execute_impl for the actual tool execution.
        
        Args:
            params: Execution parameters
            
        Returns:
            AdapterResult: Standardized result structure
        """
        start_time = time.time()
        retry_limit = int(self.config.get("retries", 3))
        max_attempts = max(1, retry_limit + 1)
        last_result: Optional[AdapterResult] = None
        warnings: List[str] = []

        try:
            self.validate_params(params)
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Adapter {self.name} parameter validation failed: {str(e)}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "timestamp": time.time(),
                    "execution_time": execution_time,
                    "retries_attempted": 0,
                },
                error_message=str(e),
                execution_time=execution_time,
            )

        for attempt in range(max_attempts):
            try:
                result = self._execute_impl(params)
                if not isinstance(result, AdapterResult):
                    raise TypeError(f"{self.name} _execute_impl must return AdapterResult")

                if (
                    result.status in (
                        AdapterResultStatus.FAILURE,
                        AdapterResultStatus.ERROR,
                        AdapterResultStatus.TIMEOUT,
                    )
                    and is_transient_adapter_error(result.error_message or "")
                    and attempt < max_attempts - 1
                ):
                    delay = 2 ** attempt
                    warning = (
                        f"Transient error on attempt {attempt + 1}/{max_attempts}: "
                        f"{result.error_message}; retrying in {delay}s"
                    )
                    warnings.append(warning)
                    self.logger.warning(warning)
                    last_result = result
                    time.sleep(delay)
                    continue

                execution_time = time.time() - start_time
                self._last_execution_time = execution_time
                result.execution_time = execution_time
                if warnings:
                    result.metadata = dict(result.metadata or {})
                    result.metadata["retries_attempted"] = attempt
                    result.metadata["transient_retry_warnings"] = warnings
                self.logger.info(
                    f"Adapter {self.name} executed successfully in {execution_time:.2f}s"
                )
                return result

            except Exception as e:
                if is_transient_adapter_error(str(e)) and attempt < max_attempts - 1:
                    delay = 2 ** attempt
                    warning = (
                        f"Transient exception on attempt {attempt + 1}/{max_attempts}: "
                        f"{e}; retrying in {delay}s"
                    )
                    warnings.append(warning)
                    self.logger.warning(warning)
                    time.sleep(delay)
                    continue

                execution_time = time.time() - start_time
                self.logger.error(f"Adapter {self.name} execution failed: {str(e)}")
                return AdapterResult(
                    status=AdapterResultStatus.ERROR,
                    data=None,
                    metadata={
                        "adapter": self.name,
                        "timestamp": time.time(),
                        "execution_time": execution_time,
                        "retries_attempted": attempt,
                        "transient_retry_warnings": warnings,
                    },
                    error_message=str(e),
                    execution_time=execution_time,
                )

        execution_time = time.time() - start_time
        if last_result is not None:
            last_result.execution_time = execution_time
            last_result.metadata = dict(last_result.metadata or {})
            last_result.metadata["retries_attempted"] = max_attempts - 1
            last_result.metadata["transient_retry_warnings"] = warnings
            return last_result

        return AdapterResult(
            status=AdapterResultStatus.ERROR,
            data=None,
            metadata={
                "adapter": self.name,
                "timestamp": time.time(),
                "execution_time": execution_time,
                "retries_attempted": max_attempts - 1,
                "transient_retry_warnings": warnings,
            },
            error_message="Adapter execution failed after retries",
            execution_time=execution_time,
        )
    
    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Abstract method for actual adapter execution.
        
        Subclasses must implement this method to perform the actual
        tool execution logic.
        
        Args:
            params: Execution parameters
            
        Returns:
            AdapterResult: Standardized result structure
            
        Raises:
            NotImplementedError: If not implemented by subclass
        """
        raise NotImplementedError("Subclasses must implement _execute_impl method")
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get basic adapter information.
        
        Returns:
            Dict containing basic adapter information
        """
        # Build parameters schema from _required_params
        required_params = getattr(self, '_required_params', [])
        parameters = {
            "type": "object",
            "properties": {},
            "required": required_params
        }
        
        # Add basic property definitions for required params
        for param in required_params:
            parameters["properties"][param] = {
                "type": "string",
                "description": f"Required parameter: {param}"
            }
        
        return {
            "name": self.name,
            "version": self.version,
            "description": f"Base adapter for {self.name}",
            "capabilities": ["basic_execution", "timing", "logging"],
            "requirements": [],
            "parameters": parameters
        }
    
    def cleanup(self) -> None:
        """
        Perform cleanup operations.
        
        This implementation provides basic cleanup logging.
        Subclasses can extend this method for specific cleanup logic.
        """
        self.logger.debug(f"Cleaning up adapter {self.name}")
        super().cleanup()
    
    def _store_evidence(self, data: Any, filename: str) -> str:
        """
        Store raw evidence data to file.
        
        Args:
            data: Raw evidence data
            filename: Evidence filename
            
        Returns:
            str: Path to stored evidence file
        """
        evidence_dir = Path("evidence") / self.name.lower()
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        evidence_path = evidence_dir / filename
        with open(evidence_path, 'w') as f:
            if isinstance(data, str):
                f.write(data)
            else:
                import json
                json.dump(data, f, indent=2)
        
        return str(evidence_path)
    
    def interpret_result(self, result: AdapterResult) -> str:
        """
        Interpret the result data into a human-readable summary.
        
        Args:
            result: The AdapterResult object containing data and status
            
        Returns:
            str: A human-readable summary of the findings
        """
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Tool execution failed: {result.error_message}"
            
        # Default implementation for adapters that haven't overridden this yet
        return f"Tool execution successful. Data: {str(result.data)[:500]}..."

    @property
    def last_execution_time(self) -> Optional[float]:
        """
        Get the last execution time.
        
        Returns:
            Optional[float]: Last execution time in seconds, or None if not executed
        """
        return self._last_execution_time
