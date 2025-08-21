"""
LLM Client Abstraction for Black Glove Pentest Agent

This module provides an abstraction layer for interacting with different
LLM providers (LMStudio, Ollama, OpenRouter) with consistent interfaces
for planning, analysis, and explanation tasks, plus advanced features
like RAG, conversation memory, and streaming.
"""

import logging
import requests
import json
from typing import Any, Dict, List, Optional, Union, Iterator, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
import time
import asyncio
import aiohttp
from pathlib import Path
import hashlib
from collections import deque
import sqlite3


class LLMProvider(Enum):
    """Enumeration of supported LLM providers."""
    LMSTUDIO = "lmstudio"
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


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
        max_tokens: Maximum tokens to generate
        top_p: Top-p sampling parameter
        frequency_penalty: Frequency penalty for generation
        presence_penalty: Presence penalty for generation
        enable_rag: Whether to enable RAG capabilities
        rag_db_path: Path to RAG database
        conversation_memory_size: Number of messages to keep in memory
    """
    provider: LLMProvider
    endpoint: str
    model: str
    temperature: float = 0.7
    timeout: int = 30
    api_key: Optional[str] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    enable_rag: bool = False
    rag_db_path: str = "data/rag_cache.db"
    conversation_memory_size: int = 10


@dataclass
class LLMMessage:
    """
    Represents a message in a conversation.
    
    Attributes:
        role: Role of the message sender (system, user, assistant)
        content: Message content
        timestamp: When the message was created
        message_id: Unique identifier for the message
    """
    role: str
    content: str
    timestamp: float = field(default_factory=time.time)
    message_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])


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
        message_id: ID of the response message
        context_used: Context retrieved from RAG (if any)
    """
    content: str
    finish_reason: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    model: Optional[str] = None
    latency: Optional[float] = None
    message_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    context_used: Optional[List[str]] = None


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


class LLMError(Exception):
    """Base exception for LLM-related errors."""
    pass


class LLMConnectionError(LLMError):
    """Exception raised for connection failures."""
    pass


class LLMResponseError(LLMError):
    """Exception raised for invalid or failed responses."""
    pass


class ConversationMemory:
    """
    Manages conversation history with memory limits and context retrieval.
    """
    
    def __init__(self, max_size: int = 10):
        """
        Initialize conversation memory.
        
        Args:
            max_size: Maximum number of messages to keep
        """
        self.max_size = max_size
        self.messages: deque = deque(maxlen=max_size)
        self.logger = logging.getLogger("black_glove.llm.memory")
    
    def add_message(self, message: LLMMessage) -> None:
        """
        Add a message to conversation memory.
        
        Args:
            message: Message to add
        """
        self.messages.append(message)
        self.logger.debug(f"Added message to memory (total: {len(self.messages)})")
    
    def get_recent_messages(self, count: int = None) -> List[LLMMessage]:
        """
        Get recent messages from memory.
        
        Args:
            count: Number of recent messages to retrieve
            
        Returns:
            List of recent messages
        """
        if count is None:
            return list(self.messages)
        return list(self.messages)[-count:]
    
    def get_context_string(self) -> str:
        """
        Get conversation context as a string.
        
        Returns:
            String representation of conversation context
        """
        context_parts = []
        for msg in self.messages:
            context_parts.append(f"{msg.role.upper()}: {msg.content}")
        return "\n".join(context_parts)
    
    def clear(self) -> None:
        """Clear conversation memory."""
        self.messages.clear()
        self.logger.debug("Conversation memory cleared")


class RAGManager:
    """
    Manages Retrieval-Augmented Generation capabilities.
    """
    
    def __init__(self, db_path: str = "data/rag_cache.db"):
        """
        Initialize RAG manager.
        
        Args:
            db_path: Path to SQLite database for document storage
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("black_glove.llm.rag")
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the RAG database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                doc_id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                metadata TEXT,
                embedding TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS document_index (
                term TEXT NOT NULL,
                doc_id TEXT NOT NULL,
                frequency INTEGER DEFAULT 1,
                PRIMARY KEY (term, doc_id)
            )
        """)
        
        conn.commit()
        conn.close()
        self.logger.info("RAG database initialized")
    
    def add_document(self, document: RAGDocument) -> None:
        """
        Add a document to the RAG system.
        
        Args:
            document: Document to add
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store document
        cursor.execute("""
            INSERT OR REPLACE INTO documents (doc_id, content, metadata, embedding)
            VALUES (?, ?, ?, ?)
        """, (
            document.doc_id,
            document.content,
            json.dumps(document.metadata),
            json.dumps(document.embedding) if document.embedding else None
        ))
        
        # Index document terms (simple keyword indexing)
        terms = self._extract_terms(document.content)
        for term, frequency in terms.items():
            cursor.execute("""
                INSERT OR REPLACE INTO document_index (term, doc_id, frequency)
                VALUES (?, ?, ?)
            """, (term.lower(), document.doc_id, frequency))
        
        conn.commit()
        conn.close()
        self.logger.debug(f"Added document {document.doc_id} to RAG system")
    
    def _extract_terms(self, text: str) -> Dict[str, int]:
        """
        Extract terms from text for indexing.
        
        Args:
            text: Text to extract terms from
            
        Returns:
            Dictionary of terms and their frequencies
        """
        # Simple term extraction (can be enhanced with NLP libraries)
        import re
        words = re.findall(r'\b\w+\b', text.lower())
        terms = {}
        for word in words:
            if len(word) > 2:  # Filter out short words
                terms[word] = terms.get(word, 0) + 1
        return terms
    
    def search_documents(self, query: str, limit: int = 5) -> List[RAGDocument]:
        """
        Search for relevant documents based on query.
        
        Args:
            query: Search query
            limit: Maximum number of documents to return
            
        Returns:
            List of relevant documents
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Extract query terms
        query_terms = list(self._extract_terms(query).keys())
        if not query_terms:
            return []
        
        # Build search query
        placeholders = ','.join(['?' for _ in query_terms])
        sql = f"""
            SELECT d.doc_id, d.content, d.metadata, d.embedding,
                   SUM(di.frequency) as relevance_score
            FROM documents d
            JOIN document_index di ON d.doc_id = di.doc_id
            WHERE di.term IN ({placeholders})
            GROUP BY d.doc_id
            ORDER BY relevance_score DESC
            LIMIT ?
        """
        
        cursor.execute(sql, query_terms + [limit])
        results = cursor.fetchall()
        conn.close()
        
        documents = []
        for row in results:
            doc_id, content, metadata_str, embedding_str, score = row
            metadata = json.loads(metadata_str) if metadata_str else {}
            embedding = json.loads(embedding_str) if embedding_str else None
            
            documents.append(RAGDocument(
                content=content,
                metadata=metadata,
                embedding=embedding,
                doc_id=doc_id
            ))
        
        self.logger.debug(f"Found {len(documents)} relevant documents for query: {query}")
        return documents
    
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
            context_parts.append(f"[Source: {source}]\n{doc.content}")
        
        return "\n\n---\n\n".join(context_parts)


class LLMClient:
    """
    Enhanced LLM abstraction layer for different providers.
    
    Provides consistent interface for LLM interactions while handling
    provider-specific differences in API formats and authentication,
    plus advanced features like RAG, conversation memory, and streaming.
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
        self.conversation_memory = ConversationMemory(config.conversation_memory_size)
        
        # Initialize RAG if enabled
        self.rag_manager = None
        if config.enable_rag:
            self.rag_manager = RAGManager(config.rag_db_path)
        
        # Set up authentication if needed
        if config.api_key:
            if config.provider == LLMProvider.OPENROUTER:
                self.session.headers.update({
                    "Authorization": f"Bearer {config.api_key}",
                    "HTTP-Referer": "https://github.com/black-glove/agent",
                    "X-Title": "Black Glove Pentest Agent"
                })
            elif config.provider == LLMProvider.ANTHROPIC:
                self.session.headers.update({
                    "x-api-key": config.api_key,
                    "anthropic-version": "2023-06-01"
                })
            elif config.provider == LLMProvider.OPENAI:
                self.session.headers.update({
                    "Authorization": f"Bearer {config.api_key}"
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
    
    def _make_api_call(self, messages: List[Dict[str, str]], stream: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Make API call to LLM provider.
        
        Args:
            messages: Prepared messages
            stream: Whether to stream the response
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
            "stream": stream,
            **kwargs
        }
        
        # Add optional parameters
        if self.config.max_tokens:
            payload["max_tokens"] = self.config.max_tokens
        if self.config.top_p:
            payload["top_p"] = self.config.top_p
        if self.config.frequency_penalty:
            payload["frequency_penalty"] = self.config.frequency_penalty
        if self.config.presence_penalty:
            payload["presence_penalty"] = self.config.presence_penalty
        
        # Provider-specific adjustments
        if self.config.provider in [LLMProvider.OLLAMA, LLMProvider.LMSTUDIO]:
            # These providers use slightly different parameter names
            payload["stream"] = stream
        
        try:
            # Determine the correct endpoint URL
            if self.config.provider in [LLMProvider.LMSTUDIO, LLMProvider.OLLAMA, LLMProvider.OPENAI]:
                # These providers use the chat completions endpoint
                endpoint_url = f"{self.config.endpoint}/chat/completions"
            else:
                # Default to the base endpoint
                endpoint_url = self.config.endpoint
                
            response = self.session.post(
                endpoint_url,
                json=payload,
                timeout=self.config.timeout,
                stream=stream
            )
            
            response.raise_for_status()
            
            if stream:
                return response  # Return streaming response
            else:
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
                # OpenAI/OpenRouter/Anthropic format
                choice = response["choices"][0]
                if "message" in choice:
                    content = choice["message"]["content"]
                elif "delta" in choice:
                    content = choice["delta"].get("content", "")
                else:
                    content = ""
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
    
    def generate(self, messages: List[LLMMessage], stream: bool = False, **kwargs) -> Union[LLMResponse, Iterator[LLMResponse]]:
        """
        Generate response from LLM.
        
        Args:
            messages: List of messages forming the conversation
            stream: Whether to stream the response
            **kwargs: Additional parameters for generation
            
        Returns:
            LLMResponse or iterator of LLMResponse for streaming
            
        Raises:
            LLMError: If generation fails
        """
        self.logger.debug(f"Generating response with {len(messages)} messages")
        
        try:
            # Add messages to conversation memory
            for msg in messages:
                self.conversation_memory.add_message(msg)
            
            # Enhance messages with RAG context if enabled
            enhanced_messages = messages
            context_used = None
            if self.rag_manager and messages:
                # Get the last user message as query
                user_messages = [msg for msg in messages if msg.role == "user"]
                if user_messages:
                    query = user_messages[-1].content
                    rag_context = self.rag_manager.get_context_for_query(query)
                    if rag_context:
                        # Add RAG context to system message or create new one
                        context_msg = LLMMessage(
                            role="system",
                            content=f"Relevant context:\n{rag_context}"
                        )
                        enhanced_messages = [context_msg] + messages
                        context_used = [rag_context]
                        self.logger.debug("Added RAG context to prompt")
            
            prepared_messages = self._prepare_messages(enhanced_messages)
            
            if stream:
                return self._stream_response(prepared_messages, **kwargs)
            else:
                raw_response = self._make_api_call(prepared_messages, stream=False, **kwargs)
                response = self._parse_response(raw_response)
                response.context_used = context_used
                return response
                
        except Exception as e:
            self.logger.error(f"Generation failed: {e}")
            raise
    
    def _stream_response(self, messages: List[Dict[str, str]], **kwargs) -> Iterator[LLMResponse]:
        """
        Stream response from LLM.
        
        Args:
            messages: Prepared messages
            **kwargs: Additional parameters
            
        Yields:
            LLMResponse objects with partial content
        """
        response = self._make_api_call(messages, stream=True, **kwargs)
        
        full_content = ""
        for line in response.iter_lines():
            if line:
                try:
                    line_str = line.decode('utf-8')
                    if line_str.startswith('data: '):
                        data_str = line_str[6:]  # Remove 'data: ' prefix
                        if data_str.strip() == '[DONE]':
                            break
                        
                        chunk_data = json.loads(data_str)
                        chunk_response = self._parse_response(chunk_data)
                        
                        if chunk_response.content:
                            full_content += chunk_response.content
                            yield chunk_response
                            
                except (json.JSONDecodeError, LLMResponseError) as e:
                    self.logger.warning(f"Failed to parse streaming chunk: {e}")
                    continue
        
        # Add final complete message to memory
        if full_content:
            final_message = LLMMessage(role="assistant", content=full_content)
            self.conversation_memory.add_message(final_message)
    
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
                content="You are a cybersecurity expert assistant helping plan penetration testing activities. Provide clear, actionable steps for reconnaissance and scanning. Be specific about tools, techniques, and methodologies. Consider safety, legality, and ethical guidelines in your recommendations."
            ),
            LLMMessage(
                role="user",
                content=f"Context: {context}\n\nObjective: {objective}\n\nProvide a detailed plan for next steps in passive reconnaissance, including specific tools and techniques to use. Prioritize safety and only suggest actions on authorized targets."
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
                content="You are a cybersecurity expert analyzing tool output for security findings. Identify potential vulnerabilities, misconfigurations, and security issues. Be concise but thorough. Focus on actionable findings with clear risk levels (High/Medium/Low) and remediation suggestions. Only discuss findings related to authorized testing targets."
            ),
            LLMMessage(
                role="user",
                content=f"Tool Output:\n{tool_output}\n\nContext: {context}\n\nAnalyze this output and identify any security findings, vulnerabilities, or misconfigurations. Provide risk levels and remediation steps for each finding."
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
                content="You are a cybersecurity expert explaining vulnerabilities and exploits. Provide educational explanations of how vulnerabilities work and potential impacts, but avoid giving specific exploit code. Focus on defensive measures, remediation, and detection methods. Emphasize ethical hacking practices and legal boundaries."
            ),
            LLMMessage(
                role="user",
                content=f"Vulnerability: {vulnerability}\n\nContext: {context}\n\nExplain this vulnerability, its potential impact, and how it could be exploited in a controlled testing environment. Include defensive measures, remediation steps, and detection methods. Avoid providing actual exploit code."
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
                content="You are a technical troubleshooter helping resolve LLM service issues. Provide practical advice for resolving connection problems, configuration issues, or service unavailability. Consider common issues with different LLM providers and local deployments."
            ),
            LLMMessage(
                role="user",
                content=f"Error: {error_message}\n\nContext: {context}\n\nProvide troubleshooting steps for this LLM service issue. Include potential causes and solutions for both local and cloud-based LLM deployments."
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
    
    def add_rag_document(self, document: RAGDocument) -> None:
        """
        Add a document to the RAG system.
        
        Args:
            document: Document to add
        """
        if self.rag_manager:
            self.rag_manager.add_document(document)
        else:
            raise LLMError("RAG is not enabled in configuration")
    
    def search_rag_documents(self, query: str, limit: int = 5) -> List[RAGDocument]:
        """
        Search for relevant documents in RAG system.
        
        Args:
            query: Search query
            limit: Maximum number of documents to return
            
        Returns:
            List of relevant documents
        """
        if self.rag_manager:
            return self.rag_manager.search_documents(query, limit)
        else:
            raise LLMError("RAG is not enabled in configuration")
    
    def get_conversation_context(self) -> str:
        """
        Get current conversation context.
        
        Returns:
            String representation of conversation context
        """
        return self.conversation_memory.get_context_string()
    
    def clear_conversation_memory(self) -> None:
        """Clear conversation memory."""
        self.conversation_memory.clear()


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
            temperature=0.7,
            enable_rag=True,
            conversation_memory_size=10
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


# Async version of LLM client for better performance
class AsyncLLMClient:
    """
    Asynchronous version of LLM client for better performance with multiple requests.
    """
    
    def __init__(self, config: LLMConfig):
        """
        Initialize the async LLM client.
        
        Args:
            config: LLM configuration
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.llm.async_client")
        self.conversation_memory = ConversationMemory(config.conversation_memory_size)
        self.rag_manager = None
        if config.enable_rag:
            self.rag_manager = RAGManager(config.rag_db_path)
    
    async def generate(self, messages: List[LLMMessage], **kwargs) -> LLMResponse:
        """
        Asynchronously generate response from LLM.
        
        Args:
            messages: List of messages forming the conversation
            **kwargs: Additional parameters for generation
            
        Returns:
            LLMResponse with generated content
        """
        # This is a simplified async implementation
        # In practice, you'd want to use aiohttp for async requests
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._sync_generate(messages, **kwargs))
    
    def _sync_generate(self, messages: List[LLMMessage], **kwargs) -> LLMResponse:
        """Synchronous generation for async client."""
        sync_client = LLMClient(self.config)
        return sync_client.generate(messages, **kwargs)
