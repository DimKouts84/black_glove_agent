"""
Enhanced LLM Client Demo

This script demonstrates the enhanced features of the LLM client including
RAG capabilities, conversation memory, and advanced provider support.
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.llm_client import (
    LLMClient, LLMConfig, LLMProvider, LLMMessage, RAGDocument, create_llm_client
)


def demo_conversation_memory():
    """Demonstrate conversation memory functionality."""
    print("=== Conversation Memory Demo ===")
    
    # Create LLM client with conversation memory
    config = LLMConfig(
        provider=LLMProvider.LMSTUDIO,
        endpoint="http://localhost:1234/v1",
        model="test-model",
        conversation_memory_size=5
    )
    client = LLMClient(config)
    
    # Simulate a conversation
    conversation = [
        ("user", "Hello, what can you help me with?"),
        ("assistant", "I can help with cybersecurity tasks like vulnerability analysis and pentesting planning."),
        ("user", "What tools do you recommend for network scanning?"),
        ("assistant", "For network scanning, I recommend nmap, masscan, and rustscan for different use cases."),
        ("user", "Which one is fastest for large networks?")
    ]
    
    print("Conversation flow:")
    for role, content in conversation:
        print(f"  {role.upper()}: {content}")
    
    # Add messages to memory (simulating actual API calls)
    for role, content in conversation:
        message = LLMMessage(role=role, content=content)
        client.conversation_memory.add_message(message)
    
    # Get conversation context
    context = client.get_conversation_context()
    print(f"\nConversation context:\n{context}")
    
    print("✅ Conversation memory demo completed\n")


def demo_rag_capabilities():
    """Demonstrate RAG capabilities."""
    print("=== RAG Capabilities Demo ===")
    
    # Create LLM client with RAG enabled
    config = LLMConfig(
        provider=LLMProvider.LMSTUDIO,
        endpoint="http://localhost:1234/v1",
        model="test-model",
        enable_rag=True,
        rag_db_path="data/demo_rag.db"
    )
    client = LLMClient(config)
    
    # Add security documents to RAG
    documents = [
        RAGDocument(
            content="SQL Injection is a code injection technique where an attacker inserts malicious SQL queries into input fields. Prevention methods include using parameterized queries, input validation, and stored procedures.",
            metadata={"source": "owasp_top_10.txt", "category": "web_security", "risk": "high"},
            doc_id="sql_injection_guide"
        ),
        RAGDocument(
            content="Cross-Site Scripting (XSS) occurs when untrusted data is included in web pages without proper validation or escaping. Types include stored XSS, reflected XSS, and DOM-based XSS. Prevention involves output encoding and Content Security Policy.",
            metadata={"source": "owasp_top_10.txt", "category": "web_security", "risk": "medium"},
            doc_id="xss_guide"
        ),
        RAGDocument(
            content="Network reconnaissance involves gathering information about target systems including IP addresses, open ports, services, and operating systems. Tools like nmap, masscan, and rustscan are commonly used for this purpose.",
            metadata={"source": "pentest_guide.txt", "category": "reconnaissance", "risk": "info"},
            doc_id="network_recon"
        )
    ]
    
    print("Adding documents to RAG system:")
    for doc in documents:
        client.add_rag_document(doc)
        print(f"  ✓ Added: {doc.metadata['source']} - {doc.doc_id}")
    
    # Search for relevant documents
    print("\nSearching for 'web security vulnerabilities':")
    results = client.search_rag_documents("web security vulnerabilities", limit=2)
    for i, doc in enumerate(results, 1):
        print(f"  {i}. {doc.metadata['source']} - {list(doc.metadata.keys())}")
        print(f"     Content preview: {doc.content[:100]}...")
    
    # Get context for a query
    query = "How to prevent SQL injection attacks?"
    print(f"\nGetting context for query: '{query}'")
    context = client.rag_manager.get_context_for_query(query, limit=1)
    if context:
        print(f"  Context retrieved:\n{context}")
    else:
        print("  No relevant context found")
    
    print("✅ RAG capabilities demo completed\n")


def demo_provider_configuration():
    """Demonstrate different provider configurations."""
    print("=== Provider Configuration Demo ===")
    
    providers = [
        (LLMProvider.LMSTUDIO, "http://localhost:1234/v1", "local-model"),
        (LLMProvider.OLLAMA, "http://localhost:11434/api/generate", "llama2"),
        (LLMProvider.OPENAI, "https://api.openai.com/v1", "gpt-4"),
        (LLMProvider.OPENROUTER, "https://openrouter.ai/api/v1", "mistralai/mistral-7b-instruct"),
    ]
    
    print("Available LLM providers:")
    for provider, endpoint, model in providers:
        config = LLMConfig(
            provider=provider,
            endpoint=endpoint,
            model=model,
            temperature=0.7,
            max_tokens=500,
            enable_rag=True
        )
        print(f"  ✓ {provider.value}: {model}")
        print(f"    Endpoint: {endpoint}")
        print(f"    Features: RAG={'enabled' if config.enable_rag else 'disabled'}")
    
    print("✅ Provider configuration demo completed\n")


def demo_factory_function():
    """Demonstrate factory function usage."""
    print("=== Factory Function Demo ===")
    
    # Create client with default config
    default_client = create_llm_client()
    print(f"Default client: {default_client.config.provider.value} - {default_client.config.model}")
    print(f"RAG enabled: {default_client.config.enable_rag}")
    print(f"Memory size: {default_client.config.conversation_memory_size}")
    
    # Create client with custom config
    custom_config = LLMConfig(
        provider=LLMProvider.OLLAMA,
        endpoint="http://localhost:11434/api/generate",
        model="codellama",
        temperature=0.8,
        enable_rag=False
    )
    custom_client = create_llm_client(custom_config)
    print(f"Custom client: {custom_client.config.provider.value} - {custom_client.config.model}")
    print(f"RAG enabled: {custom_client.config.enable_rag}")
    
    print("✅ Factory function demo completed\n")


def main():
    """Run all demos."""
    print("🤖 Black Glove Enhanced LLM Client Demo")
    print("=" * 50)
    
    try:
        demo_conversation_memory()
        demo_rag_capabilities()
        demo_provider_configuration()
        demo_factory_function()
        
        print("🎉 All demos completed successfully!")
        print("\nKey features demonstrated:")
        print("  • Conversation memory with size limits")
        print("  • RAG document management and search")
        print("  • Multiple LLM provider support")
        print("  • Factory pattern for client creation")
        print("  • Context-aware query processing")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
