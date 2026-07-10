"""Trace persistence tests for structured tool-result metadata."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, "src")

from agent.db import init_db, get_db_connection
from agent.runtime import AgentRuntime
from agent.session_manager import SessionManager


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    db_path = home / ".homepentest" / "homepentest.db"
    monkeypatch.setattr("agent.db.DB_PATH", db_path)
    init_db()
    return db_path


def test_trace_persists_tool_result_details(isolated_db):
    sm = SessionManager()
    session_id = sm.create_session("Trace Meta Test")

    conn = get_db_connection()
    runtime = AgentRuntime.__new__(AgentRuntime)
    run_id = "run-trace-meta"
    runtime._create_run(conn, run_id, session_id, "test query", "2026-01-01T12:00:00")
    runtime._persist_event(
        conn,
        run_id,
        {
            "agent": "root_agent",
            "type": "tool_result",
            "content": "Whois partial",
            "tool": "whois",
            "status": "partial",
            "warnings": ["RDAP HTTP 503"],
            "coverage": {"has_core_fields": False},
            "evidence_paths": ["/evidence/whois.txt"],
            "ts": "2026-01-01T12:00:01",
        },
    )
    conn.close()

    trace = sm.get_session_trace(session_id)
    assert len(trace) == 1
    event = trace[0]["events"][0]
    assert event["tool"] == "whois"
    assert event["status"] == "partial"
    assert event["warnings"] == ["RDAP HTTP 503"]
    assert event["evidence_paths"] == ["/evidence/whois.txt"]
