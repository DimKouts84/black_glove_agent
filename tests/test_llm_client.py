"""
Tests for LLM Client Implementation

This module contains tests for the LLM client abstraction layer,
including provider support, message handling, and error management.
"""

import pytest
import requests
import json
from unittest.mock import Mock, patch
from typing import List, Dict, Any

from src.agent.llm_client import (
    LLMClient, LLMConfig, LLMMessage, LLMResponse, LLMProvider,
    LLMError, LLMConnectionError, LLMResponseError,
    create_llm_client, LLMClientContext
)


class TestLLMProvider:
    """Test cases for LLM provider enumeration."""
    
    def test_llm_provider_enum(self):
        """Test LLM provider enumeration values."""
        assert LLMProvider.LMSTUDIO.value == "lmstudio"
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.OPENROUTER.value == "openrouter"


class TestLLMConfig:
    """Test cases for LLM configuration."""
    
    def test_llm_config_creation(self):
        """Test LLMConfig creation and default values."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        
        assert config.provider == LLMProvider.LMSTUDIO
        assert config.endpoint == "http://localhost:1234/v1"
        assert config.model == "test-model"
        assert config.temperature == 0.7
        assert config.timeout == 30
        assert config.api_key is None
    
    def test_llm_config_with_custom_values(self):
        """Test LLMConfig with custom values."""
        config = LLMConfig(
            provider=LLMProvider.OPENROUTER,
            endpoint="https://openrouter.ai/api/v1",
            model="test-model",
            temperature=0.5,
            timeout=60,
            api_key="test-key"
        )
        
        assert config.provider == LLMProvider.OPENROUTER
        assert config.temperature == 0.5
        assert config.timeout == 60
        assert config.api_key == "test-key"


class TestLLMMessage:
    """Test cases for LLM message structure."""
    
    def test_llm_message_creation(self):
        """Test LLMMessage creation."""
        message = LLMMessage(role="user", content="Hello, AI!")
        
        assert message.role == "user"
        assert message.content == "Hello, AI!"


class TestLLMResponse:
    """Test cases for LLM response structure."""
    
    def test_llm_response_creation(self):
        """Test LLMResponse creation with minimal parameters."""
        response = LLMResponse(content="Test response")
        
        assert response.content == "Test response"
        assert response.finish_reason is None
        assert response.usage is None
        assert response.model is None
        assert response.latency is None
    
    def test_llm_response_with_all_parameters(self):
        """Test LLMResponse creation with all parameters."""
        response = LLMResponse(
            content="Test response",
            finish_reason="stop",
            usage={"prompt_tokens": 10, "completion_tokens": 20},
            model="test-model",
            latency=0.5
        )
        
        assert response.content == "Test response"
        assert response.finish_reason == "stop"
        assert response.usage == {"prompt_tokens": 10, "completion_tokens": 20}
        assert response.model == "test-model"
        assert response.latency == 0.5


class TestLLMClient:
    """Test cases for the LLMClient implementation."""
    
    def test_llm_client_initialization(self):
        """Test LLMClient initialization."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        
        client = LLMClient(config)
        
        assert client.config == config
        assert client.session is not None
    
    def test_llm_client_with_api_key(self):
        """Test LLMClient initialization with API key."""
        config = LLMConfig(
            provider=LLMProvider.OPENROUTER,
            endpoint="https://openrouter.ai/api/v1",
            model="test-model",
            api_key="test-key"
        )
        
        client = LLMClient(config)
        
        # Check that headers were set
        assert "Authorization" in client.session.headers
        assert client.session.headers["Authorization"] == "Bearer test-key"
    
    def test_prepare_messages(self):
        """Test message preparation for API calls."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        messages = [
            LLMMessage(role="system", content="You are a helpful assistant."),
            LLMMessage(role="user", content="Hello!")
        ]
        
        prepared = client._prepare_messages(messages)
        
        assert len(prepared) == 2
        assert prepared[0] == {"role": "system", "content": "You are a helpful assistant."}
        assert prepared[1] == {"role": "user", "content": "Hello!"}
    
    def test_parse_openai_response(self):
        """Test parsing of OpenAI-style responses."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        response_data = {
            "choices": [{
                "message": {"content": "Test response"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20},
            "model": "test-model"
        }
        
        result = client._parse_response(response_data)
        
        assert isinstance(result, LLMResponse)
        assert result.content == "Test response"
        assert result.finish_reason == "stop"
        assert result.usage == {"prompt_tokens": 10, "completion_tokens": 20}
        assert result.model == "test-model"
    
    def test_parse_ollama_response(self):
        """Test parsing of Ollama-style responses."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            endpoint="http://localhost:11434/api/chat",
            model="test-model"
        )
        client = LLMClient(config)
        
        response_data = {
            "message": {"content": "Ollama response"},
            "done_reason": "stop",
            "model": "test-model"
        }
        
        result = client._parse_response(response_data)
        
        assert isinstance(result, LLMResponse)
        assert result.content == "Ollama response"
        assert result.finish_reason == "stop"
        assert result.model == "test-model"
    
    def test_parse_invalid_response(self):
        """Test parsing of invalid responses."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        # Test unsupported format
        with pytest.raises(LLMResponseError, match="Unsupported response format"):
            client._parse_response({"invalid": "format"})
        
        # Test missing required fields
        with pytest.raises(LLMResponseError, match="Failed to parse response"):
            client._parse_response({"choices": []})


class TestLLMClientAPI:
    """Test cases for LLM client API interactions."""
    
    @patch('requests.Session.post')
    def test_make_api_call_success(self, mock_post):
        """Test successful API call."""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Test response"},
                "finish_reason": "stop"
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        messages = [{"role": "user", "content": "Hello!"}]
        result = client._make_api_call(messages)
        
        assert result["choices"][0]["message"]["content"] == "Test response"
        mock_post.assert_called_once()
    
    @patch('requests.Session.post')
    def test_make_api_call_timeout(self, mock_post):
        """Test API call timeout."""
        mock_post.side_effect = requests.exceptions.Timeout()
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        messages = [{"role": "user", "content": "Hello!"}]
        
        with pytest.raises(LLMConnectionError, match="Request timeout"):
            client._make_api_call(messages)
    
    @patch('requests.Session.post')
    def test_make_api_call_connection_error(self, mock_post):
        """Test API call connection error."""
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        messages = [{"role": "user", "content": "Hello!"}]
        
        with pytest.raises(LLMConnectionError, match="Connection failed"):
            client._make_api_call(messages)
    
    @patch('requests.Session.post')
    def test_generate_success(self, mock_post):
        """Test successful generation."""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Generated response"},
                "finish_reason": "stop"
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        messages = [LLMMessage(role="user", content="Hello!")]
        result = client.generate(messages)
        
        assert isinstance(result, LLMResponse)
        assert result.content == "Generated response"
        assert result.finish_reason == "stop"
    
    def test_generate_with_invalid_response(self):
        """Test generation with invalid response."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        # Mock the _make_api_call to return invalid data
        with patch.object(client, '_make_api_call', return_value={"invalid": "format"}):
            with pytest.raises(LLMResponseError):
                messages = [LLMMessage(role="user", content="Hello!")]
                client.generate(messages)


class TestLLMClientSpecializedMethods:
    """Test cases for specialized LLM client methods."""
    
    @patch('requests.Session.post')
    def test_plan_next_steps(self, mock_post):
        """Test planning next steps."""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Plan: Step 1, Step 2"},
                "finish_reason": "stop"
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.plan_next_steps("Current context", "Scan objective")
        
        assert isinstance(result, LLMResponse)
        assert "Plan:" in result.content
        mock_post.assert_called_once()
    
    @patch('requests.Session.post')
    def test_analyze_findings(self, mock_post):
        """Test analyzing findings."""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Vulnerability found"},
                "finish_reason": "stop"
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.analyze_findings("Tool output data", "Target context")
        
        assert isinstance(result, LLMResponse)
        assert "Vulnerability" in result.content
        mock_post.assert_called_once()
    
    @patch('requests.Session.post')
    def test_explain_exploit(self, mock_post):
        """Test explaining exploit."""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Exploit explanation"},
                "finish_reason": "stop"
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.explain_exploit("Vulnerability description", "Environment context")
        
        assert isinstance(result, LLMResponse)
        assert "Exploit" in result.content
        mock_post.assert_called_once()
    
    @patch('requests.Session.post')
    def test_handle_failure(self, mock_post):
        """Test handling failure."""
        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Troubleshooting steps"},
                "finish_reason": "stop"
            }]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.handle_failure("Error message", "Operation context")
        
        assert isinstance(result, LLMResponse)
        assert "Troubleshooting" in result.content
        mock_post.assert_called_once()


class TestLLMClientHealthCheck:
    """Test cases for LLM client health check."""
    
    @patch('requests.Session.get')
    def test_health_check_lmstudio_success(self, mock_get):
        """Test LMStudio health check success."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.health_check()
        
        assert result is True
        mock_get.assert_called_once_with("http://localhost:1234/v1/models", timeout=5)
    
    @patch('requests.Session.get')
    def test_health_check_lmstudio_failure(self, mock_get):
        """Test LMStudio health check failure."""
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")
        
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.health_check()
        
        assert result is False
    
    @patch('requests.Session.get')
    def test_health_check_ollama_success(self, mock_get):
        """Test Ollama health check success."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            endpoint="http://localhost:11434/api",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.health_check()
        
        assert result is True
        mock_get.assert_called_once_with("http://localhost:11434/api/api/tags", timeout=5)
    
    @patch('src.agent.llm_client.LLMClient.generate')
    def test_health_check_other_provider(self, mock_generate):
        """Test health check for other providers."""
        mock_generate.return_value = LLMResponse(content="Hello")
        
        config = LLMConfig(
            provider=LLMProvider.OPENROUTER,
            endpoint="https://openrouter.ai/api/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        result = client.health_check()
        
        assert result is True
        mock_generate.assert_called_once()


class TestLLMClientFactory:
    """Test cases for LLM client factory function."""
    
    def test_create_llm_client_default(self):
        """Test creating LLM client with default config."""
        client = create_llm_client()
        
        assert isinstance(client, LLMClient)
        assert client.config.provider == LLMProvider.LMSTUDIO
        assert client.config.endpoint == "http://localhost:1234/v1"
        assert client.config.model == "local-model"
    
    def test_create_llm_client_custom(self):
        """Test creating LLM client with custom config."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            endpoint="http://localhost:11434/api",
            model="custom-model"
        )
        
        client = create_llm_client(config)
        
        assert isinstance(client, LLMClient)
        assert client.config.provider == LLMProvider.OLLAMA
        assert client.config.model == "custom-model"


class TestLLMClientContext:
    """Test cases for LLM client context manager."""
    
    def test_llm_client_context_manager(self):
        """Test LLM client context manager."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        
        with LLMClientContext(config) as client:
            assert isinstance(client, LLMClient)
            assert client.config == config
        
        # Context should exit cleanly without errors


class TestLLMClientIntegration:
    """Integration tests for LLM client components."""
    
    def test_complete_message_flow(self):
        """Test complete message flow through LLM client."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        
        # This would normally make real API calls, but we'll test
        # the structure and error handling instead
        client = LLMClient(config)
        
        # Test that all specialized methods exist and are callable
        assert callable(client.plan_next_steps)
        assert callable(client.analyze_findings)
        assert callable(client.explain_exploit)
        assert callable(client.handle_failure)
        assert callable(client.health_check)
    
    def test_error_handling_consistency(self):
        """Test consistent error handling across methods."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        client = LLMClient(config)
        
        # All methods should raise LLMError or subclasses
        methods = [
            client.plan_next_steps,
            client.analyze_findings,
            client.explain_exploit,
            client.handle_failure
        ]
        
        for method in methods:
            # Test that methods properly handle errors
            with patch.object(client, 'generate', side_effect=LLMConnectionError("Test error")):
                with pytest.raises(LLMError):
                    if method == client.plan_next_steps:
                        method("context", "objective")
                    elif method == client.analyze_findings:
                        method("output")
                    elif method == client.explain_exploit:
                        method("vulnerability")
                    elif method == client.handle_failure:
                        method("error")


if __name__ == "__main__":
    pytest.main([__file__])
