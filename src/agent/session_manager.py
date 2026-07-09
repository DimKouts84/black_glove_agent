"""
Session management module for Black Glove pentest agent.
Handles persistent storage and retrieval of chat sessions in SQLite database.
"""

import uuid
import json
from contextlib import contextmanager
from datetime import datetime
from typing import List, Dict, Optional, Iterator

from .db import get_db_connection
from .llm_client import LLMMessage


class SessionManager:
    """
    Manages chat sessions and conversation persistence.

    Handles creation, loading, and management of chat sessions in the SQLite database.
    Provides a persistent alternative to the in-memory ConversationMemory.
    """

    @contextmanager
    def _connection(self) -> Iterator:
        conn = get_db_connection()
        try:
            yield conn
        finally:
            conn.close()

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

        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
                    (session_id, title, created_at, created_at),
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
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, role, content, timestamp, llm_response_metadata FROM chat_messages "
                "WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,),
            )

            messages = []
            for row in cursor.fetchall():
                msg_id, role, content, timestamp, metadata_json = row

                if metadata_json:
                    try:
                        json.loads(metadata_json)
                    except json.JSONDecodeError:
                        pass

                message = LLMMessage(
                    role=role,
                    content=content,
                    timestamp=datetime.fromisoformat(timestamp).timestamp(),
                    message_id=str(msg_id),
                )
                messages.append(message)

        return messages

    def save_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict] = None,
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

        metadata_json = None
        if metadata:
            try:
                metadata_json = json.dumps(metadata)
            except (TypeError, ValueError):
                pass

        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO chat_messages (session_id, role, content, timestamp, llm_response_metadata) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (session_id, role, content, timestamp, metadata_json),
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

        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE sessions SET last_active = ? WHERE id = ?",
                    (timestamp, session_id),
                )
                return cursor.rowcount > 0

    def list_sessions(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """
        List recent sessions.

        Args:
            limit: Maximum number of sessions to return
            offset: Pagination offset

        Returns:
            List[Dict]: Session information with ID, title, and timestamps
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, title, created_at, last_active FROM sessions "
                "ORDER BY last_active DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )

            sessions = []
            for row in cursor.fetchall():
                sessions.append({
                    "id": row[0],
                    "title": row[1],
                    "created_at": row[2],
                    "last_active": row[3],
                })

        return sessions

    def get_session_trace(self, session_id: str) -> List[Dict]:
        """Return orchestration runs and events for a session."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, query, status, started_at, finished_at, final_answer "
                "FROM agent_runs WHERE session_id = ? ORDER BY started_at ASC",
                (session_id,),
            )
            runs = []
            for row in cursor.fetchall():
                run_id = row[0]
                cursor.execute(
                    "SELECT id, agent, type, content, params_json, ts "
                    "FROM agent_events WHERE run_id = ? ORDER BY ts ASC",
                    (run_id,),
                )
                events = [
                    {
                        "id": e[0],
                        "agent": e[1],
                        "type": e[2],
                        "content": e[3],
                        "params": json.loads(e[4]) if e[4] else None,
                        "ts": e[5],
                    }
                    for e in cursor.fetchall()
                ]
                runs.append({
                    "id": run_id,
                    "query": row[1],
                    "status": row[2],
                    "started_at": row[3],
                    "finished_at": row[4],
                    "final_answer": row[5],
                    "events": events,
                })
        return runs

    def get_messages(self, session_id: str) -> List[Dict]:
        """Return messages as dicts for API responses."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, role, content, timestamp, llm_response_metadata "
                "FROM chat_messages WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,),
            )
            messages = []
            for row in cursor.fetchall():
                meta = None
                if row[4]:
                    try:
                        meta = json.loads(row[4])
                    except json.JSONDecodeError:
                        pass
                messages.append({
                    "id": row[0],
                    "role": row[1],
                    "content": row[2],
                    "timestamp": row[3],
                    "metadata": meta,
                })
        return messages

    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """
        Get information about a specific session.

        Args:
            session_id: ID of the session

        Returns:
            Optional[Dict]: Session information if found
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, title, created_at, last_active FROM sessions WHERE id = ?",
                (session_id,),
            )
            row = cursor.fetchone()

            if row:
                return {
                    "id": row[0],
                    "title": row[1],
                    "created_at": row[2],
                    "last_active": row[3],
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
        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM agent_events WHERE run_id IN "
                    "(SELECT id FROM agent_runs WHERE session_id = ?)",
                    (session_id,),
                )
                cursor.execute("DELETE FROM agent_runs WHERE session_id = ?", (session_id,))
                cursor.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
                cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
                return cursor.rowcount > 0
