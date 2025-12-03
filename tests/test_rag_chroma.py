import pytest
import shutil
from pathlib import Path
import time
import gc
from src.agent.rag import ChromaDBManager, RAGDocument
from src.agent.llm_client import LLMClient, LLMConfig, LLMProvider

@pytest.fixture
def chroma_manager(tmp_path):
    # Setup
    db_path = tmp_path / "chroma_db"
    manager = ChromaDBManager(db_path=str(db_path), collection_name="test_collection")
    yield manager
    
    # Teardown - try to help release resources
    del manager
    gc.collect()

def test_chroma_initialization(chroma_manager):
    assert chroma_manager.collection is not None

def test_add_and_search_document(chroma_manager):
    doc = RAGDocument(
        content="The quick brown fox jumps over the lazy dog.",
        metadata={"source": "test", "category": "animals"},
        doc_id="doc1"
    )
    
    chroma_manager.add_document(doc)
    
    # Search for "fox"
    results = chroma_manager.search_documents("fox", limit=1)
    assert len(results) == 1
    assert "fox" in results[0].content
    assert results[0].doc_id == "doc1"
    assert results[0].metadata["source"] == "test"

def test_get_context(chroma_manager):
    doc1 = RAGDocument(content="Python is a programming language.", metadata={"source": "wiki"}, doc_id="doc1")
    doc2 = RAGDocument(content="ChromaDB is a vector database.", metadata={"source": "docs"}, doc_id="doc2")
    
    chroma_manager.add_document(doc1)
    chroma_manager.add_document(doc2)
    
    context = chroma_manager.get_context_for_query("vector database", limit=1)
    assert "ChromaDB" in context
    assert "Source: docs" in context

def test_llm_client_integration(tmp_path):
    # Setup LLMClient with RAG enabled
    db_path = tmp_path / "llm_chroma_db"
    
    config = LLMConfig(
        provider=LLMProvider.LMSTUDIO,
        endpoint="http://localhost:1234/v1",
        model="local-model",
        enable_rag=True,
        rag_db_path=str(db_path)
    )
    
    client = LLMClient(config)
    
    # Test add_rag_document
    doc = RAGDocument(
        content="Black Glove is a pentest agent.",
        metadata={"type": "fact"},
        doc_id="fact1"
    )
    client.add_rag_document(doc)
    
    # Test search via client
    docs = client.search_rag_documents("pentest agent")
    assert len(docs) > 0
    assert "Black Glove" in docs[0].content
    
    # Explicitly delete client to help cleanup
    del client
    gc.collect()
