"""
Session management module for Black Glove pentest agent.
Handles persistent storage and retrieval of chat sessions in SQLite database.
"""

import uuid
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import asdict

from .db import get_db_connection
from .llm_client import LLMMessage

class SessionManager:
    """
    Manages chat sessions and conversation persistence.
    
    Handles creation, loading, and management of chat sessions in the SQLite database.
    Provides a persistent alternative to the in-memory ConversationMemory.
    """
    
    def __init__(self):
        """Initialize the session manager with database connection."""
        self.conn = get_db_connection()
    
    def __del__(self):
        """Close database connection when object is destroyed."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
    
    def create_session(self, title: Optional[str] = None) -> str:
        """
        Create a new chat session.
        
        Args:
            title: Optional title for the session
            
        Returns:
            str: Session ID (UUID)
        """
        session_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
                (session_id, title, created_at, created_at)
            )
        
        return session_id
    
    def load_session(self, session_id: str) -> List[LLMMessage]:
        """
        Load all messages for a given session.
        
        Args:
            session_id: ID of the session to load
            
        Returns:
            List[LLMMessage]: Messages in the session, ordered by timestamp
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, role, content, timestamp, llm_response_metadata FROM chat_messages "
            "WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,)
        )
        
        messages = []
        for row in cursor.fetchall():
            msg_id, role, content, timestamp, metadata_json = row
            
            # Parse metadata if it exists
            metadata = None
            if metadata_json:
                try:
                    metadata = json.loads(metadata_json)
                except:
                    pass
            
            # Create message object
            message = LLMMessage(
                role=role,
                content=content,
                timestamp=datetime.fromisoformat(timestamp).timestamp(),
                message_id=str(msg_id)
            )
            messages.append(message)
        
        return messages
    
    def save_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict] = None
    ) -> int:
        """
        Save a message to a session.
        
        Args:
            session_id: ID of the session
            role: Message role (user, assistant, system)
            content: Message content
            metadata: Optional LLM response metadata
            
        Returns:
            int: ID of the newly created message
        """
        timestamp = datetime.now().isoformat()
        
        # Convert metadata to JSON string if provided
        metadata_json = None
        if metadata:
            try:
                metadata_json = json.dumps(metadata)
            except:
                pass
        
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO chat_messages (session_id, role, content, timestamp, llm_response_metadata) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, role, content, timestamp, metadata_json)
            )
            return cursor.lastrowid
    
    def update_session_activity(self, session_id: str) -> bool:
        """
        Update the last active timestamp for a session.
        
        Args:
            session_id: ID of the session
            
        Returns:
            bool: True if session was updated, False if not found
        """
        timestamp = datetime.now().isoformat()
        
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE sessions SET last_active = ? WHERE id = ?",
                (timestamp, session_id)
            )
            return cursor.rowcount > 0
    
    def list_sessions(self, limit: int = 10) -> List[Dict]:
        """
        List recent sessions.
        
        Args:
            limit: Maximum number of sessions to return
            
        Returns:
            List[Dict]: Session information with ID, title, and timestamps
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, title, created_at, last_active FROM sessions "
            "ORDER BY last_active DESC LIMIT ?",
            (limit,)
        )
        
        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                'id': row[0],
                'title': row[1],
                'created_at': row[2],
                'last_active': row[3]
            })
        
        return sessions
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """
        Get information about a specific session.
        
        Args:
            session_id: ID of the session
            
        Returns:
            Optional[Dict]: Session information if found
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, title, created_at, last_active FROM sessions WHERE id = ?",
            (session_id,)
        )
        row = cursor.fetchone()
        
        if row:
            return {
                'id': row[0],
                'title': row[1],
                'created_at': row[2],
                'last_active': row[3]
            }
        return None
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session and all its messages.
        
        Args:
            session_id: ID of the session to delete
            
        Returns:
            bool: True if session was deleted, False if not found
        """
        with self.conn:
            cursor = self.conn.cursor()
            # Delete messages first (due to foreign key constraint)
            cursor.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
            # Delete session
            cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            return cursor.rowcount > 0
