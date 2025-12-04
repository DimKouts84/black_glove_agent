"""
Tests for Enhanced LLM Client Implementation

This module contains tests for the enhanced LLM client features including
RAG capabilities, conversation memory, streaming, and advanced provider support.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.llm_client import (
    LLMClient, LLMConfig, LLMProvider, LLMMessage, LLMResponse, RAGDocument,
    ConversationMemory, create_llm_client, LLMError
)
from src.agent.rag.chroma_store import ChromaDBManager


class TestLLMConfig:
    """Test cases for LLM configuration."""
    
    def test_llm_config_creation(self):
        """Test LLMConfig creation with default values."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        
        assert config.provider == LLMProvider.LMSTUDIO
        assert config.endpoint == "http://localhost:1234/v1"
        assert config.model == "test-model"
        assert config.temperature == 0.7
        assert config.enable_rag is False
        assert config.conversation_memory_size == 10
    
    def test_llm_config_with_advanced_options(self):
        """Test LLMConfig with advanced options."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            endpoint="https://api.openai.com/v1",
            model="gpt-4",
            temperature=0.8,
            max_tokens=1000,
            top_p=0.9,
            frequency_penalty=0.5,
            presence_penalty=0.5,
            enable_rag=True,
            rag_db_path="/tmp/test_rag.db",
            conversation_memory_size=20
        )
        
        assert config.provider == LLMProvider.OPENAI
        assert config.max_tokens == 1000
        assert config.top_p == 0.9
        assert config.frequency_penalty == 0.5
        assert config.presence_penalty == 0.5
        assert config.enable_rag is True
        assert config.rag_db_path == "/tmp/test_rag.db"
        assert config.conversation_memory_size == 20


class TestLLMMessage:
    """Test cases for LLM message handling."""
    
    def test_llm_message_creation(self):
        """Test LLMMessage creation."""
        message = LLMMessage(role="user", content="Hello, world!")
        
        assert message.role == "user"
        assert message.content == "Hello, world!"
        assert isinstance(message.timestamp, float)
        assert len(message.message_id) == 8
        assert isinstance(message.message_id, str)
    
    def test_llm_message_with_custom_id(self):
        """Test LLMMessage with custom ID."""
        message = LLMMessage(
            role="assistant",
            content="Hello back!",
            message_id="custom123"
        )
        
        assert message.message_id == "custom123"


class TestConversationMemory:
    """Test cases for conversation memory management."""
    
    def test_conversation_memory_initialization(self):
        """Test ConversationMemory initialization."""
        memory = ConversationMemory(max_size=5)
        
        assert memory.max_size == 5
        assert len(memory.messages) == 0
    
    def test_conversation_memory_add_message(self):
        """Test adding messages to conversation memory."""
        memory = ConversationMemory(max_size=3)
        
        msg1 = LLMMessage(role="user", content="Hello")
        msg2 = LLMMessage(role="assistant", content="Hi there!")
        msg3 = LLMMessage(role="user", content="How are you?")
        
        memory.add_message(msg1)
        memory.add_message(msg2)
        memory.add_message(msg3)
        
        assert len(memory.messages) == 3
        assert memory.messages[0].content == "Hello"
        assert memory.messages[1].content == "Hi there!"
        assert memory.messages[2].content == "How are you?"
    
    def test_conversation_memory_size_limit(self):
        """Test conversation memory size limiting."""
        memory = ConversationMemory(max_size=2)
        
        msg1 = LLMMessage(role="user", content="Message 1")
        msg2 = LLMMessage(role="assistant", content="Message 2")
        msg3 = LLMMessage(role="user", content="Message 3")
        
        memory.add_message(msg1)
        memory.add_message(msg2)
        memory.add_message(msg3)
        
        assert len(memory.messages) == 2  # Limited to max_size
        assert memory.messages[0].content == "Message 2"  # Oldest removed
        assert memory.messages[1].content == "Message 3"
    
    def test_conversation_memory_get_recent_messages(self):
        """Test getting recent messages from memory."""
        memory = ConversationMemory(max_size=5)
        
        # Add exactly 5 messages to a max_size=5 memory
        for i in range(5):
            memory.add_message(LLMMessage(role="user", content=f"Message {i}"))
        
        # Get all messages
        all_messages = memory.get_recent_messages()
        assert len(all_messages) == 5
        
        # Get last 3 messages
        recent_messages = memory.get_recent_messages(3)
        assert len(recent_messages) == 3
        assert recent_messages[0].content == "Message 2"
        assert recent_messages[1].content == "Message 3"
        assert recent_messages[2].content == "Message 4"
    
    def test_conversation_memory_get_context_string(self):
        """Test getting conversation context as string."""
        memory = ConversationMemory(max_size=3)
        
        # Add messages one by one with unique IDs
        memory.add_message(LLMMessage(role="user", content="Hello", message_id="msg1"))
        memory.add_message(LLMMessage(role="assistant", content="Hi!", message_id="msg2"))
        memory.add_message(LLMMessage(role="user", content="How are you?", message_id="msg3"))
        
        context = memory.get_context_string()
        expected = "USER: Hello\nASSISTANT: Hi!\nUSER: How are you?"
        assert context == expected
    
    def test_conversation_memory_clear(self):
        """Test clearing conversation memory."""
        memory = ConversationMemory(max_size=5)
        
        for i in range(3):
            memory.add_message(LLMMessage(role="user", content=f"Message {i}"))
        
        assert len(memory.messages) == 3
        
        memory.clear()
        assert len(memory.messages) == 0


class TestRAGDocument:
    """Test cases for RAG document handling."""
    
    def test_rag_document_creation(self):
        """Test RAGDocument creation."""
        doc = RAGDocument(
            content="This is test content",
            metadata={"source": "test.txt", "category": "security"},
            doc_id="test123"
        )
        
        assert doc.content == "This is test content"
        assert doc.metadata == {"source": "test.txt", "category": "security"}
        assert doc.doc_id == "test123"
        assert doc.embedding is None
    
    def test_rag_document_with_embedding(self):
        """Test RAGDocument with embedding."""
        embedding = [0.1, 0.2, 0.3, 0.4]
        doc = RAGDocument(
            content="Test content",
            embedding=embedding
        )
        
        assert doc.embedding == embedding




class TestEnhancedLLMClient:
    """Test cases for enhanced LLM client features."""
    
    @pytest.fixture
    def mock_llm_client(self):
        """Create a mock LLM client for testing."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model",
            enable_rag=True
        )
        client = LLMClient(config)
        return client
    
    def test_llm_client_initialization(self, mock_llm_client):
        """Test LLM client initialization."""
        assert mock_llm_client.config is not None
        assert mock_llm_client.conversation_memory is not None
        assert mock_llm_client.rag_manager is not None
        assert mock_llm_client.session is not None
    
    def test_llm_client_conversation_memory_integration(self, mock_llm_client):
        """Test conversation memory integration in LLM client."""
        messages = [
            LLMMessage(role="user", content="Hello"),
            LLMMessage(role="assistant", content="Hi there!")
        ]
        
        # Mock the API call to avoid actual network requests
        with patch.object(mock_llm_client, '_make_api_call') as mock_call:
            mock_call.return_value = {
                "choices": [{
                    "message": {"content": "Hello back!"},
                    "finish_reason": "stop"
                }]
            }
            
            response = mock_llm_client.generate(messages)
            
            # Check that messages were added to memory
            memory_messages = mock_llm_client.conversation_memory.get_recent_messages()
            assert len(memory_messages) >= 2
            assert any(msg.content == "Hello" for msg in memory_messages)
    
    def test_llm_client_rag_integration(self, mock_llm_client):
        """Test RAG integration in LLM client."""
        # Add a document to RAG
        doc = RAGDocument(
            content="Security best practice: Always validate user input",
            metadata={"source": "security_guide.txt"},
            doc_id="best_practice_1"
        )
        mock_llm_client.add_rag_document(doc)
        
        messages = [
            LLMMessage(role="user", content="What are security best practices for input validation?")
        ]
        
        # Mock the API call
        with patch.object(mock_llm_client, '_make_api_call') as mock_call:
            mock_call.return_value = {
                "choices": [{
                    "message": {"content": "Always validate user input to prevent injection attacks."},
                    "finish_reason": "stop"
                }]
            }
            
            response = mock_llm_client.generate(messages)
            
            # Check that RAG context was used (this would be in the enhanced messages)
            # The actual enhancement happens in the generate method
            assert response is not None
    
    def test_llm_client_add_rag_document(self, mock_llm_client):
        """Test adding RAG document through LLM client."""
        doc = RAGDocument(
            content="Test document content",
            metadata={"source": "test.txt"},
            doc_id="test123"
        )
        
        # This should not raise an exception
        mock_llm_client.add_rag_document(doc)
    
    def test_llm_client_search_rag_documents(self, mock_llm_client):
        """Test searching RAG documents through LLM client."""
        doc = RAGDocument(
            content="Searchable security content",
            metadata={"source": "guide.txt"},
            doc_id="search_test"
        )
        mock_llm_client.add_rag_document(doc)
        
        results = mock_llm_client.search_rag_documents("security", limit=5)
        assert len(results) >= 1
        assert any("security" in result.content.lower() for result in results)
    
    def test_llm_client_get_conversation_context(self, mock_llm_client):
        """Test getting conversation context from LLM client."""
        mock_llm_client.conversation_memory.add_message(
            LLMMessage(role="user", content="Test message")
        )
        
        context = mock_llm_client.get_conversation_context()
        assert "USER: Test message" in context
    
    def test_llm_client_clear_conversation_memory(self, mock_llm_client):
        """Test clearing conversation memory through LLM client."""
        mock_llm_client.conversation_memory.add_message(
            LLMMessage(role="user", content="Test message")
        )
        assert len(mock_llm_client.conversation_memory.messages) == 1
        
        mock_llm_client.clear_conversation_memory()
        assert len(mock_llm_client.conversation_memory.messages) == 0
    
    def test_llm_client_plan_next_steps(self, mock_llm_client):
        """Test planning next steps functionality."""
        with patch.object(mock_llm_client, 'generate') as mock_generate:
            mock_generate.return_value = LLMResponse(content="Plan content")
            
            response = mock_llm_client.plan_next_steps("Current context", "Test objective")
            assert response is not None
            mock_generate.assert_called_once()
    
    def test_llm_client_analyze_findings(self, mock_llm_client):
        """Test analyzing findings functionality."""
        with patch.object(mock_llm_client, 'generate') as mock_generate:
            mock_generate.return_value = LLMResponse(content="Analysis content")
            
            response = mock_llm_client.analyze_findings("Tool output", "Context")
            assert response is not None
            mock_generate.assert_called_once()
    
    def test_llm_client_explain_exploit(self, mock_llm_client):
        """Test explaining exploit functionality."""
        with patch.object(mock_llm_client, 'generate') as mock_generate:
            mock_generate.return_value = LLMResponse(content="Explanation content")
            
            response = mock_llm_client.explain_exploit("Vulnerability", "Context")
            assert response is not None
            mock_generate.assert_called_once()
    
    def test_llm_client_handle_failure(self, mock_llm_client):
        """Test handling failure functionality."""
        with patch.object(mock_llm_client, 'generate') as mock_generate:
            mock_generate.return_value = LLMResponse(content="Troubleshooting content")
            
            response = mock_llm_client.handle_failure("Error message", "Context")
            assert response is not None
            mock_generate.assert_called_once()


class TestLLMClientFactory:
    """Test cases for LLM client factory function."""
    
    def test_create_llm_client_with_config(self):
        """Test creating LLM client with custom configuration."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            endpoint="http://localhost:11434/api/generate",
            model="llama2",
            enable_rag=True
        )
        
        client = create_llm_client(config)
        assert isinstance(client, LLMClient)
        assert client.config.provider == LLMProvider.OLLAMA
        assert client.config.enable_rag is True
    
    def test_create_llm_client_default(self):
        """Test creating LLM client with default configuration."""
        client = create_llm_client()
        assert isinstance(client, LLMClient)
        assert client.config.provider == LLMProvider.LMSTUDIO
        assert client.config.enable_rag is True


class TestLLMClientContext:
    """Test cases for LLM client context manager."""
    
    def test_llm_client_context_manager(self):
        """Test LLM client context manager."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        
        with patch('src.agent.llm_client.create_llm_client') as mock_create:
            mock_client = MagicMock()
            mock_create.return_value = mock_client
            
            from src.agent.llm_client import LLMClientContext
            with LLMClientContext(config) as client:
                assert client == mock_client


# Integration tests
class TestLLMIntegration:
    """Integration tests for enhanced LLM features."""
    
    @pytest.fixture
    def integration_client(self):
        """Create an integration test client."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model",
            enable_rag=True,
            conversation_memory_size=5
        )
        return LLMClient(config)
    
    def test_complete_conversation_flow(self, integration_client):
        """Test complete conversation flow with memory and RAG."""
        # Add some RAG context
        doc = RAGDocument(
            content="Security guideline: Use parameterized queries to prevent SQL injection",
            metadata={"source": "security_guidelines.txt", "type": "best_practice"},
            doc_id="sql_injection_guide"
        )
        integration_client.add_rag_document(doc)
        
        # Simulate conversation
        conversation = [
            ("user", "What security guidelines do you know about SQL injection?"),
            ("assistant", "Always use parameterized queries to prevent SQL injection attacks."),
            ("user", "What are the risks of SQL injection?"),
            ("assistant", "SQL injection can lead to data breaches and unauthorized access.")
        ]
        
        # Mock API responses
        responses = [
            "Security guideline: Use parameterized queries to prevent SQL injection",
            "SQL injection risks include data breaches and unauthorized database access",
            "Prevention methods include input validation and stored procedures",
            "Detection involves monitoring query patterns and database logs"
        ]
        
        with patch.object(integration_client, '_make_api_call') as mock_call:
            mock_call.side_effect = [
                {"choices": [{"message": {"content": response}, "finish_reason": "stop"}]}
                for response in responses
            ]
            
            # Simulate conversation
            for i, (role, content) in enumerate(conversation):
                message = LLMMessage(role=role, content=content)
                response = integration_client.generate([message])
                assert response.content == responses[i]
            
            # Check conversation memory
            memory_context = integration_client.get_conversation_context()
            assert len(memory_context) > 0
            assert "USER:" in memory_context
            assert "ASSISTANT:" in memory_context
    
    def test_rag_enhanced_query(self, integration_client):
        """Test RAG-enhanced query processing."""
        # Add security documents
        documents = [
            RAGDocument(
                content="XSS (Cross-Site Scripting) is a client-side code injection attack",
                metadata={"source": "owasp_guide.txt", "category": "web_security"},
                doc_id="xss_guide"
            ),
            RAGDocument(
                content="Prevent XSS by validating and escaping user input properly",
                metadata={"source": "security_best_practices.txt", "category": "prevention"},
                doc_id="xss_prevention"
            )
        ]
        
        for doc in documents:
            integration_client.add_rag_document(doc)
        
        # Test query that should trigger RAG
        query_message = LLMMessage(
            role="user",
            content="How can I prevent XSS vulnerabilities in web applications?"
        )
        
        with patch.object(integration_client, '_make_api_call') as mock_call:
            mock_call.return_value = {
                "choices": [{
                    "message": {"content": "Prevent XSS by validating and escaping user input."},
                    "finish_reason": "stop"
                }]
            }
            
            response = integration_client.generate([query_message])
            assert response is not None
            # The RAG context should have been added to enhance the prompt


if __name__ == "__main__":
    pytest.main([__file__])
