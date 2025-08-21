"""
Integration Tests for Enhanced LLM Client Features

This module tests the core enhanced features of the LLM client in isolation.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.llm_client import (
    LLMClient, LLMConfig, LLMProvider, LLMMessage, RAGDocument, create_llm_client
)
from agent.models import Asset


class TestLLMEnhancedFeatures:
    """Test core enhanced LLM features."""
    
    def test_conversation_memory_integration(self):
        """Test conversation memory functionality."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model",
            conversation_memory_size=5
        )
        client = LLMClient(config)
        
        # Test memory initialization
        assert client.conversation_memory is not None
        assert client.conversation_memory.max_size == 5
        
        # Test adding messages
        message = LLMMessage(role="user", content="Test message")
        client.conversation_memory.add_message(message)
        
        # Test getting context
        context = client.get_conversation_context()
        assert "USER: Test message" in context
        
        print("✅ Conversation memory integration test passed")
    
    def test_rag_integration(self):
        """Test RAG functionality."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model",
            enable_rag=True
        )
        client = LLMClient(config)
        
        # Test RAG manager initialization
        assert client.rag_manager is not None
        
        # Test adding document
        doc = RAGDocument(
            content="Test security content",
            metadata={"source": "test.txt"},
            doc_id="test123"
        )
        client.add_rag_document(doc)
        
        # Test searching documents
        results = client.search_rag_documents("security", limit=5)
        assert len(results) >= 1
        assert "security" in results[0].content.lower()
        
        print("✅ RAG integration test passed")
    
    def test_factory_function_integration(self):
        """Test factory function with enhanced features."""
        # Test default client
        client = create_llm_client()
        assert isinstance(client, LLMClient)
        assert client.config.enable_rag is True
        assert client.config.conversation_memory_size > 0
        
        # Test custom client
        custom_config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            endpoint="http://localhost:11434/api/generate",
            model="llama2",
            temperature=0.8,
            enable_rag=False,
            conversation_memory_size=3
        )
        custom_client = create_llm_client(custom_config)
        assert custom_client.config.provider == LLMProvider.OLLAMA
        assert custom_client.config.enable_rag is False
        assert custom_client.config.conversation_memory_size == 3
        
        print("✅ Factory function integration test passed")
    
    def test_model_compatibility(self):
        """Test compatibility with existing data models."""
        # Test that Asset model works with LLM messages
        asset = Asset(
            target="example.com",
            tool_name="nmap",
            parameters={"port": 80}
        )
        
        message_content = f"Scanning target: {asset.target} with tool: {asset.tool_name}"
        message = LLMMessage(role="user", content=message_content)
        
        assert message.content == "Scanning target: example.com with tool: nmap"
        
        print("✅ Model compatibility test passed")
    
    def test_end_to_end_workflow(self):
        """Test complete enhanced LLM workflow."""
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model",
            enable_rag=True,
            conversation_memory_size=10
        )
        client = LLMClient(config)
        
        # Add knowledge base
        doc = RAGDocument(
            content="Security best practice: Always validate inputs",
            metadata={"source": "security_guide.txt"},
            doc_id="best_practice_1"
        )
        client.add_rag_document(doc)
        
        # Simulate conversation
        messages = [
            LLMMessage(role="user", content="What are security best practices?")
        ]
        
        # Test that RAG context would be available
        context_docs = client.search_rag_documents("security best practices")
        assert len(context_docs) >= 1
        
        # Test conversation memory
        for message in messages:
            client.conversation_memory.add_message(message)
        
        context = client.get_conversation_context()
        assert len(context) > 0
        
        print("✅ End-to-end workflow test passed")


if __name__ == "__main__":
    pytest.main([__file__])
