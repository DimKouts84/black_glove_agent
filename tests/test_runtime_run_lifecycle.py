"""Tests for AgentRuntime run lifecycle."""

import asyncio
import sqlite3
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.db import (
    create_agent_events_table,
    create_agent_runs_table,
    create_sessions_table,
)
from agent.models import ConfigModel
from agent.run_recovery import recover_stale_runs
from agent.runtime import AgentRuntime, reset_agent_runtime


@pytest.fixture
def memory_db(tmp_path, monkeypatch):
    db_path = tmp_path / "homepentest.db"
    monkeypatch.setattr("agent.db.DB_PATH", db_path)
    conn = sqlite3.connect(db_path)
    create_sessions_table(conn)
    create_agent_runs_table(conn)
    create_agent_events_table(conn)
    conn.execute(
        "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
        ("sess-1", "Test", "2026-01-01T00:00:00", "2026-01-01T00:00:00"),
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture(autouse=True)
def _reset_runtime():
    reset_agent_runtime()
    yield
    reset_agent_runtime()


def test_run_turn_marks_cancelled_on_cancelled_error(memory_db):
    runtime = AgentRuntime(config=ConfigModel())

    mock_executor = AsyncMock()
    mock_executor.run = AsyncMock(side_effect=asyncio.CancelledError())

    async def _run():
        with patch("agent.runtime.AgentExecutor", return_value=mock_executor):
            with pytest.raises(asyncio.CancelledError):
                await runtime.run_turn("sess-1", "test query")

    asyncio.run(_run())

    conn = sqlite3.connect(memory_db)
    row = conn.execute(
        "SELECT status, final_answer FROM agent_runs WHERE session_id = ?",
        ("sess-1",),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "cancelled"
    assert row[1] == "Run cancelled"


def test_recover_stale_runs_marks_interrupted(memory_db):
    conn = sqlite3.connect(memory_db)
    conn.execute(
        "INSERT INTO agent_runs (id, session_id, query, status, started_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "stale-run",
            "sess-1",
            "old query",
            "running",
            "2020-01-01T00:00:00",
        ),
    )
    conn.commit()
    conn.close()

    count = recover_stale_runs(max_age_seconds=60)
    assert count == 1

    conn = sqlite3.connect(memory_db)
    row = conn.execute(
        "SELECT status, final_answer FROM agent_runs WHERE id = ?",
        ("stale-run",),
    ).fetchone()
    conn.close()
    assert row[0] == "interrupted"
    assert "interrupted" in row[1].lower() or "partial" in row[1].lower()


def test_recover_stale_runs_ignores_recent(memory_db):
    conn = sqlite3.connect(memory_db)
    now = "2099-01-01T12:00:00"
    conn.execute(
        "INSERT INTO agent_runs (id, session_id, query, status, started_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("fresh-run", "sess-1", "new query", "running", now),
    )
    conn.commit()
    conn.close()

    count = recover_stale_runs(max_age_seconds=900)
    assert count == 0

    conn = sqlite3.connect(memory_db)
    row = conn.execute(
        "SELECT status FROM agent_runs WHERE id = ?",
        ("fresh-run",),
    ).fetchone()
    conn.close()
    assert row[0] == "running"
