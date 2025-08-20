"""
LLM Client Abstraction for Black Glove Pentest Agent

This module provides an abstraction layer for interacting with different
LLM providers (LMStudio, Ollama, OpenRouter) with consistent interfaces
for planning, analysis, and explanation tasks.
"""

import logging
import requests
import json
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import time


class LLMProvider(Enum):
    """Enumeration of supported LLM providers."""
    LMSTUDIO = "lmstudio"
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"


@dataclass
class LLMConfig:
    """
    Configuration for LLM client.
    
    Attributes:
        provider: LLM provider to use
        endpoint: API endpoint URL
        model: Model name to use
        temperature: Temperature setting for generation
        timeout: Request timeout in seconds
        api_key: Optional API key for providers that require it
    """
    provider: LLMProvider
    endpoint: str
    model: str
    temperature: float = 0.7
    timeout: int = 30
    api_key: Optional[str] = None


@dataclass
class LLMMessage:
    """
    Represents a message in a conversation.
    
    Attributes:
        role: Role of the message sender (system, user, assistant)
        content: Message content
    """
    role: str
    content: str


@dataclass
class LLMResponse:
    """
    Standardized response from LLM calls.
    
    Attributes:
        content: Generated content
        finish_reason: Reason for completion
        usage: Token usage information
        model: Model used for generation
        latency: Response time in seconds
    """
    content: str
    finish_reason: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    model: Optional[str] = None
    latency: Optional[float] = None


class LLMError(Exception):
    """Base exception for LLM-related errors."""
    pass


class LLMConnectionError(LLMError):
    """Exception raised for connection failures."""
    pass


class LLMResponseError(LLMError):
    """Exception raised for invalid or failed responses."""
    pass


class LLMClient:
    """
    LLM abstraction layer for different providers.
    
    Provides consistent interface for LLM interactions while handling
    provider-specific differences in API formats and authentication.
    """
    
    def __init__(self, config: LLMConfig):
        """
        Initialize the LLM client.
        
        Args:
            config: LLM configuration
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.llm.client")
        self.session = requests.Session()
        
        # Set up authentication if needed
        if config.api_key:
            if config.provider == LLMProvider.OPENROUTER:
                self.session.headers.update({
                    "Authorization": f"Bearer {config.api_key}",
                    "HTTP-Referer": "https://github.com/black-glove/agent",
                    "X-Title": "Black Glove Pentest Agent"
                })
            else:
                self.session.headers.update({
                    "Authorization": f"Bearer {config.api_key}"
                })
        
        self.logger.info(f"LLM client initialized for provider: {config.provider.value}")
    
    def _prepare_messages(self, messages: List[LLMMessage]) -> List[Dict[str, str]]:
        """
        Prepare messages for API call.
        
        Args:
            messages: List of LLMMessage objects
            
        Returns:
            List of message dictionaries in API format
        """
        return [{"role": msg.role, "content": msg.content} for msg in messages]
    
    def _make_api_call(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        Make API call to LLM provider.
        
        Args:
            messages: Prepared messages
            **kwargs: Additional parameters for the API call
            
        Returns:
            API response dictionary
            
        Raises:
            LLMConnectionError: If connection fails
            LLMResponseError: If response is invalid
        """
        start_time = time.time()
        
        # Prepare request payload
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            **kwargs
        }
        
        # Provider-specific adjustments
        if self.config.provider == LLMProvider.OLLAMA:
            # Ollama uses slightly different parameter names
            payload["stream"] = False
        
        try:
            response = self.session.post(
                self.config.endpoint,
                json=payload,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            result = response.json()
            
            latency = time.time() - start_time
            self.logger.debug(f"API call completed in {latency:.2f}s")
            
            return result
            
        except requests.exceptions.Timeout:
            raise LLMConnectionError(f"Request timeout after {self.config.timeout}s")
        except requests.exceptions.ConnectionError as e:
            raise LLMConnectionError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise LLMResponseError(f"API request failed: {e}")
        except json.JSONDecodeError as e:
            raise LLMResponseError(f"Invalid JSON response: {e}")
    
    def _parse_response(self, response: Dict[str, Any]) -> LLMResponse:
        """
        Parse API response into standardized format.
        
        Args:
            response: Raw API response
            
        Returns:
            Standardized LLMResponse
        """
        try:
            # Handle different response formats
            if "choices" in response:
                # OpenAI/OpenRouter format
                choice = response["choices"][0]
                content = choice["message"]["content"]
                finish_reason = choice.get("finish_reason")
                
                # Extract usage info if available
                usage = response.get("usage")
                
                # Extract model info
                model = response.get("model")
                
            elif "message" in response:
                # Ollama format
                content = response["message"]["content"]
                finish_reason = response.get("done_reason")
                usage = response.get("prompt_eval_count")
                model = response.get("model")
                
            else:
                raise LLMResponseError("Unsupported response format")
            
            return LLMResponse(
                content=content,
                finish_reason=finish_reason,
                usage=usage,
                model=model
            )
            
        except (KeyError, IndexError) as e:
            raise LLMResponseError(f"Failed to parse response: {e}")
    
    def generate(self, messages: List[LLMMessage], **kwargs) -> LLMResponse:
        """
        Generate response from LLM.
        
        Args:
            messages: List of messages forming the conversation
            **kwargs: Additional parameters for generation
            
        Returns:
            LLMResponse with generated content
            
        Raises:
            LLMError: If generation fails
        """
        self.logger.debug(f"Generating response with {len(messages)} messages")
        
        try:
            prepared_messages = self._prepare_messages(messages)
            raw_response = self._make_api_call(prepared_messages, **kwargs)
            response = self._parse_response(raw_response)
            return response
            
        except Exception as e:
            self.logger.error(f"Generation failed: {e}")
            raise
    
    def plan_next_steps(self, context: str, objective: str) -> LLMResponse:
        """
        Generate scan planning suggestions.
        
        Args:
            context: Current reconnaissance context
            objective: Scanning objective
            
        Returns:
            LLMResponse with planning suggestions
        """
        messages = [
            LLMMessage(
                role="system",
                content="You are a cybersecurity expert assistant helping plan penetration testing activities. Provide clear, actionable steps for reconnaissance and scanning."
            ),
            LLMMessage(
                role="user",
                content=f"Context: {context}\n\nObjective: {objective}\n\nProvide a detailed plan for next steps in passive reconnaissance, including specific tools and techniques to use."
            )
        ]
        
        return self.generate(messages)
    
    def analyze_findings(self, tool_output: str, context: str = "") -> LLMResponse:
        """
        Interpret tool output and identify security issues.
        
        Args:
            tool_output: Raw output from security tools
            context: Additional context about the target
            
        Returns:
            LLMResponse with analysis and findings
        """
        messages = [
            LLMMessage(
                role="system",
                content="You are a cybersecurity expert analyzing tool output for security findings. Identify potential vulnerabilities, misconfigurations, and security issues. Be concise but thorough."
            ),
            LLMMessage(
                role="user",
                content=f"Tool Output:\n{tool_output}\n\nContext: {context}\n\nAnalyze this output and identify any security findings, vulnerabilities, or misconfigurations."
            )
        ]
        
        return self.generate(messages)
    
    def explain_exploit(self, vulnerability: str, context: str = "") -> LLMResponse:
        """
        Provide safe exploit explanations.
        
        Args:
            vulnerability: Description of the vulnerability
            context: Additional context about the environment
            
        Returns:
            LLMResponse with safe explanation
        """
        messages = [
            LLMMessage(
                role="system",
                content="You are a cybersecurity expert explaining vulnerabilities and exploits. Provide educational explanations of how vulnerabilities work and potential impacts, but avoid giving specific exploit code. Focus on defensive measures and remediation."
            ),
            LLMMessage(
                role="user",
                content=f"Vulnerability: {vulnerability}\n\nContext: {context}\n\nExplain this vulnerability, its potential impact, and how it could be exploited in a controlled testing environment. Include defensive measures and remediation steps."
            )
        ]
        
        return self.generate(messages)
    
    def handle_failure(self, error_message: str, context: str = "") -> LLMResponse:
        """
        Manage LLM service unavailability or errors.
        
        Args:
            error_message: Error message from failed operation
            context: Additional context about what was being attempted
            
        Returns:
            LLMResponse with troubleshooting suggestions
        """
        messages = [
            LLMMessage(
                role="system",
                content="You are a technical troubleshooter helping resolve LLM service issues. Provide practical advice for resolving connection problems, configuration issues, or service unavailability."
            ),
            LLMMessage(
                role="user",
                content=f"Error: {error_message}\n\nContext: {context}\n\nProvide troubleshooting steps for this LLM service issue. Include potential causes and solutions."
            )
        ]
        
        return self.generate(messages)
    
    def health_check(self) -> bool:
        """
        Check if the LLM service is available and responsive.
        
        Returns:
            bool: True if service is available, False otherwise
        """
        try:
            # Simple health check - try to get model info
            if self.config.provider == LLMProvider.LMSTUDIO:
                response = self.session.get(
                    f"{self.config.endpoint}/models",
                    timeout=5
                )
                return response.status_code == 200
            elif self.config.provider == LLMProvider.OLLAMA:
                response = self.session.get(
                    f"{self.config.endpoint}/api/tags",
                    timeout=5
                )
                return response.status_code == 200
            else:
                # For other providers, try a simple generation
                test_messages = [
                    LLMMessage(role="user", content="Hello, are you available?")
                ]
                response = self.generate(test_messages)
                return len(response.content) > 0
                
        except Exception as e:
            self.logger.warning(f"Health check failed: {e}")
            return False


# Factory function for creating LLM client instances
def create_llm_client(config: LLMConfig = None) -> LLMClient:
    """
    Factory function to create an LLM client instance.
    
    Args:
        config: Optional LLM configuration
        
    Returns:
        LLMClient: Configured LLM client instance
    """
    if config is None:
        # Default configuration for local LMStudio
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="local-model",
            temperature=0.7
        )
    
    return LLMClient(config)


# Context manager for LLM client
class LLMClientContext:
    """
    Context manager for LLM client to ensure proper cleanup.
    """
    
    def __init__(self, config: LLMConfig = None):
        self.config = config
        self.llm_client = None
    
    def __enter__(self):
        self.llm_client = create_llm_client(self.config)
        return self.llm_client
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # LLMClient doesn't need explicit cleanup, but this provides
        # a consistent interface for resource management
        pass
