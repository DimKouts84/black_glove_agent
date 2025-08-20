"""
Adapter Interface for Black Glove Pentest Agent

This module defines the standardized interface contract for all tool adapters,
ensuring consistent integration with the plugin system and orchestration engine.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AdapterResultStatus(Enum):
    """Enumeration of possible adapter result statuses."""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class AdapterResult:
    """
    Standardized result structure for all adapters.
    
    Attributes:
        status: Result status enumeration
        data: Raw output data from the tool
        metadata: Additional information about the execution
        error_message: Error details if applicable
        execution_time: Time taken to execute the adapter
        evidence_path: Path to stored raw evidence
    """
    status: AdapterResultStatus
    data: Any
    metadata: Dict[str, Any]
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    evidence_path: Optional[str] = None


class AdapterInterface(ABC):
    """
    Abstract base class defining the adapter contract.
    
    All tool adapters must inherit from this interface and implement
    the required methods to ensure consistent integration.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the adapter with configuration.
        
        Args:
            config: Adapter-specific configuration dictionary
        """
        self.config = config
        self.name = self.__class__.__name__
        self.version = "1.0.0"
    
    @abstractmethod
    def validate_config(self) -> bool:
        """
        Validate the adapter configuration.
        
        Returns:
            bool: True if configuration is valid, False otherwise
            
        Raises:
            ValueError: If configuration is invalid
        """
        pass
    
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute the adapter with given parameters.
        
        Args:
            params: Execution parameters for the tool
            
        Returns:
            AdapterResult: Standardized result structure
        """
        pass
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """
        Get adapter metadata and capabilities.
        
        Returns:
            Dict containing adapter information including:
            - name: Adapter name
            - version: Adapter version
            - description: Brief description
            - capabilities: List of supported features
            - requirements: List of prerequisites
        """
        pass
    
    @abstractmethod
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Validate execution parameters.
        
        Args:
            params: Parameters to validate
            
        Returns:
            bool: True if parameters are valid, False otherwise
            
        Raises:
            ValueError: If parameters are invalid
        """
        pass
    
    def cleanup(self) -> None:
        """
        Perform cleanup operations after execution.
        
        This method can be overridden by adapters that need
        specific cleanup logic.
        """
        pass


# Base adapter exception classes
class AdapterError(Exception):
    """Base exception for adapter-related errors."""
    pass


class AdapterConfigError(AdapterError):
    """Exception raised for invalid adapter configuration."""
    pass


class AdapterExecutionError(AdapterError):
    """Exception raised for adapter execution failures."""
    pass


class AdapterValidationError(AdapterError):
    """Exception raised for adapter validation failures."""
    pass
