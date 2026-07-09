"""Tests for SessionManager thread safety and persistence."""

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, "src")

from agent.db import DB_PATH, init_db
from agent.session_manager import SessionManager


@pytest.fixture
def session_manager(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    db_path = home / ".homepentest" / "homepentest.db"
    monkeypatch.setattr("agent.db.DB_PATH", db_path)
    init_db()
    return SessionManager()


class TestSessionManager:
    def test_session_crud(self, session_manager):
        sm = session_manager
        sid = sm.create_session("Test Session")
        assert sid

        info = sm.get_session_info(sid)
        assert info is not None
        assert info["id"] == sid
        assert info["title"] == "Test Session"

        msg_id = sm.save_message(sid, "user", "hello", metadata={"type": "user_input"})
        assert msg_id > 0

        messages = sm.load_session(sid)
        assert len(messages) == 1
        assert messages[0].role == "user"
        assert messages[0].content == "hello"

        api_messages = sm.get_messages(sid)
        assert len(api_messages) == 1
        assert api_messages[0]["content"] == "hello"

        sessions = sm.list_sessions()
        assert any(s["id"] == sid for s in sessions)

        assert sm.update_session_activity(sid) is True
        assert sm.delete_session(sid) is True
        assert sm.get_session_info(sid) is None

    def test_get_session_info_from_different_thread(self, session_manager):
        sm = session_manager
        sid = sm.create_session("thread test")
        result = {}

        def worker():
            result["info"] = sm.get_session_info(sid)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        assert result["info"] is not None
        assert result["info"]["id"] == sid
