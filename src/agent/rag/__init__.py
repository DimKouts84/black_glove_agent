"""
RAG Module

Provides Retrieval-Augmented Generation capabilities using ChromaDB.
"""

from .manager import RAGManager, RAGDocument
from .chroma_store import ChromaDBManager

__all__ = ["RAGManager", "RAGDocument", "ChromaDBManager"]
