"""
RAG Manager Interface

Defines the abstract base class for RAG managers and the data structures for documents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import time
import hashlib
import json

@dataclass
class RAGDocument:
    """
    Represents a document for RAG retrieval.
    
    Attributes:
        content: Document content
        metadata: Document metadata
        embedding: Optional embedding vector
        doc_id: Unique document identifier
    """
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    doc_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "doc_id": self.doc_id,
            "content": self.content,
            "metadata": self.metadata,
            "embedding": self.embedding
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RAGDocument':
        """Create from dictionary."""
        return cls(
            content=data["content"],
            metadata=data.get("metadata", {}),
            embedding=data.get("embedding"),
            doc_id=data.get("doc_id", hashlib.md5(str(time.time()).encode()).hexdigest())
        )

class RAGManager(ABC):
    """
    Abstract base class for RAG managers.
    """

    @abstractmethod
    def add_document(self, document: RAGDocument) -> None:
        """
        Add a document to the RAG system.
        
        Args:
            document: Document to add
        """
        pass

    @abstractmethod
    def search_documents(self, query: str, limit: int = 5) -> List[RAGDocument]:
        """
        Search for relevant documents based on query.
        
        Args:
            query: Search query
            limit: Maximum number of documents to return
            
        Returns:
            List of relevant documents
        """
        pass

    @abstractmethod
    def get_context_for_query(self, query: str, limit: int = 3) -> str:
        """
        Get relevant context for a query.
        
        Args:
            query: Query to get context for
            limit: Maximum number of context snippets
            
        Returns:
            Context string combining relevant document contents
        """
        pass
