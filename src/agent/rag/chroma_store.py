"""
ChromaDB Implementation of RAG Manager

Implements the RAGManager interface using ChromaDB for vector storage and retrieval.
"""

import logging
import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from .manager import RAGManager, RAGDocument

class ChromaDBManager(RAGManager):
    """
    Manages Retrieval-Augmented Generation using ChromaDB.
    """

    def __init__(self, db_path: str = "data/chroma_db", collection_name: str = "black_glove_memory"):
        """
        Initialize ChromaDB manager.
        
        Args:
            db_path: Path to ChromaDB persistence directory
            collection_name: Name of the collection to use
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("black_glove.rag.chroma")
        
        try:
            self.client = chromadb.PersistentClient(path=str(self.db_path))
            self.collection = self.client.get_or_create_collection(name=collection_name)
            self.logger.info(f"ChromaDB initialized at {self.db_path}, collection: {collection_name}")
        except Exception as e:
            # Handle Windows-specific file locking/existence race condition (OS Error 183)
            if "os error 183" in str(e) or "Cannot create a file when that file already exists" in str(e):
                self.logger.warning(f"ChromaDB initialization encountered OS error 183. Retrying after delay...")
                try:
                    import time
                    time.sleep(2.0) # Increased delay
                    # Try to re-initialize client
                    self.client = chromadb.PersistentClient(path=str(self.db_path))
                    self.collection = self.client.get_or_create_collection(name=collection_name)
                    self.logger.info(f"ChromaDB initialized successfully on retry.")
                    return
                except Exception as retry_error:
                    # If tenant error occurs, it might be a transient state.
                    if "Could not connect to tenant" in str(retry_error):
                         self.logger.warning(f"ChromaDB tenant error on retry. Attempting one last time...")
                         time.sleep(2.0)
                         try:
                             self.client = chromadb.PersistentClient(path=str(self.db_path))
                             self.collection = self.client.get_or_create_collection(name=collection_name)
                             self.logger.info(f"ChromaDB initialized successfully on second retry.")
                             return
                         except Exception as final_error:
                             self.logger.error(f"ChromaDB final retry failed: {final_error}")
                             # Graceful degradation: Disable RAG instead of crashing
                             self.logger.warning("Disabling RAG functionality due to persistent database errors.")
                             self.client = None
                             self.collection = None
                             return
                    
                    self.logger.error(f"ChromaDB retry failed: {retry_error}")
                    # Graceful degradation
                    self.logger.warning("Disabling RAG functionality due to persistent database errors.")
                    self.client = None
                    self.collection = None
                    return

            self.logger.error(f"Failed to initialize ChromaDB: {e}")
            # Graceful degradation
            self.logger.warning("Disabling RAG functionality due to persistent database errors.")
            self.client = None
            self.collection = None

    def add_document(self, document: RAGDocument) -> None:
        """
        Add a document to the RAG system.
        
        Args:
            document: Document to add
        """
        if not self.collection:
            return

        try:
            # Prepare metadata (ensure values are simple types for Chroma)
            # Chroma metadata values must be str, int, float, or bool
            safe_metadata = {}
            for k, v in document.metadata.items():
                if isinstance(v, (str, int, float, bool)):
                    safe_metadata[k] = v
                else:
                    safe_metadata[k] = str(v)
            
            self.collection.add(
                documents=[document.content],
                metadatas=[safe_metadata],
                ids=[document.doc_id],
                embeddings=[document.embedding] if document.embedding else None
            )
            self.logger.debug(f"Added document {document.doc_id} to ChromaDB")
        except Exception as e:
            self.logger.error(f"Failed to add document to ChromaDB: {e}")

    def search_documents(self, query: str, limit: int = 5) -> List[RAGDocument]:
        """
        Search for relevant documents based on query.
        
        Args:
            query: Search query
            limit: Maximum number of documents to return
            
        Returns:
            List of relevant documents
        """
        if not self.collection:
            return []

        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=limit
            )
            
            documents = []
            if results["ids"] and results["ids"][0]:
                for i in range(len(results["ids"][0])):
                    doc_id = results["ids"][0][i]
                    content = results["documents"][0][i]
                    metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                    
                    # Reconstruct RAGDocument
                    documents.append(RAGDocument(
                        content=content,
                        metadata=metadata,
                        doc_id=doc_id
                    ))
            
            self.logger.debug(f"Found {len(documents)} relevant documents for query: {query}")
            return documents
            
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return []

    def get_context_for_query(self, query: str, limit: int = 3) -> str:
        """
        Get relevant context for a query.
        
        Args:
            query: Query to get context for
            limit: Maximum number of context snippets
            
        Returns:
            Context string combining relevant document contents
        """
        documents = self.search_documents(query, limit)
        if not documents:
            return ""
        
        context_parts = []
        for doc in documents:
            # Add document content with metadata context
            source = doc.metadata.get('source', 'unknown')
            timestamp = doc.metadata.get('timestamp', '')
            header = f"[Source: {source}"
            if timestamp:
                header += f" | Time: {timestamp}"
            header += "]"
            
            context_parts.append(f"{header}\n{doc.content}")
        
        return "\n\n---\n\n".join(context_parts)
