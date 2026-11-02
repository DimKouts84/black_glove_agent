"""Tests for AgentRuntime."""

import asyncio
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, "src")

from agent.models import ConfigModel
from agent.runtime import AgentRuntime, reset_agent_runtime


@pytest.fixture(autouse=True)
def _reset():
    reset_agent_runtime()
    yield
    reset_agent_runtime()


class TestAgentRuntime:
    def test_boots_and_lists_tools(self):
        runtime = AgentRuntime(config=ConfigModel())
        tools = runtime.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0
        names = {t["name"] for t in tools}
        assert "generate_report" in names or "nmap" in names

    def test_available_agents(self):
        runtime = AgentRuntime(config=ConfigModel())
        agents = runtime.available_agents()
        assert agents == [
            "black_glove",
            "recon_agent",
            "network_agent",
            "web_agent",
            "assessment_agent",
        ]

    def test_run_turn_uses_pydantic_ai_runner(self, monkeypatch):
        """Chat calls the new runner with a fake model and does not scan."""
        from pydantic_ai.messages import ModelResponse, TextPart
        from pydantic_ai.models.function import FunctionModel

        from agent.db import (
            create_agent_events_table,
            create_agent_runs_table,
            create_chat_messages_table,
            create_sessions_table,
        )
        import sqlite3

        class _NoCloseConnection:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def close(self):
                return None

        conn = sqlite3.connect(":memory:")
        create_sessions_table(conn)
        create_chat_messages_table(conn)
        create_agent_runs_table(conn)
        create_agent_events_table(conn)
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
            ("pai-session", "Test", "2026-01-01", "2026-01-01"),
        )
        conn.commit()
        monkeypatch.setattr("agent.runtime.get_db_connection", lambda: _NoCloseConnection(conn))

        def script(messages, info):
            return ModelResponse(parts=[TextPart("Hello from Black Glove")])

        monkeypatch.setattr(
            "agent.ai.runner.build_model",
            lambda config: FunctionModel(script),
        )
        runtime = AgentRuntime(config=ConfigModel())
        runtime.execute_scan_plan = AsyncMock()

        result = asyncio.run(runtime.run_turn("pai-session", "hello"))

        assert result["final_answer"]["answer"] == "Hello from Black Glove"
        runtime.execute_scan_plan.assert_not_called()
        row = conn.execute(
            "SELECT type, agent FROM agent_events WHERE type = 'answer'"
        ).fetchone()
        assert row is not None
        assert row[0] == "answer"
        assert row[1] == "black_glove"

    def test_run_turn_rejects_a_second_active_run_and_records_failure(self, monkeypatch):
        from agent.db import (
            create_agent_events_table,
            create_agent_runs_table,
            create_chat_messages_table,
            create_sessions_table,
        )
        import sqlite3

        class _NoCloseConnection:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def close(self):
                return None

        conn = sqlite3.connect(":memory:")
        create_sessions_table(conn)
        create_chat_messages_table(conn)
        create_agent_runs_table(conn)
        create_agent_events_table(conn)
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
            ("busy-session", "Test", "2026-01-01", "2026-01-01"),
        )
        conn.commit()
        monkeypatch.setattr("agent.runtime.get_db_connection", lambda: _NoCloseConnection(conn))
        runtime = AgentRuntime(config=ConfigModel())
        started = asyncio.Event()
        release = asyncio.Event()

        async def _hold(**kwargs):
            started.set()
            await release.wait()
            return {"final_answer": {"answer": "done"}}

        async def _scenario():
            with patch("agent.runtime.run_chat_turn", new=_hold):
                first = asyncio.create_task(runtime.run_turn("busy-session", "first"))
                await started.wait()
                with pytest.raises(RuntimeError, match="already has an active run"):
                    await runtime.run_turn("busy-session", "second")
                release.set()
                await first
            with patch(
                "agent.runtime.run_chat_turn",
                new=AsyncMock(side_effect=RuntimeError("model down")),
            ):
                with pytest.raises(RuntimeError, match="model down"):
                    await runtime.run_turn("busy-session", "third")

        asyncio.run(_scenario())
        statuses = [
            row[0]
            for row in conn.execute(
                "SELECT status FROM agent_runs WHERE session_id = ? ORDER BY started_at",
                ("busy-session",),
            ).fetchall()
        ]
        assert "completed" in statuses
        assert "failed" in statuses

    def test_reload_config(self):
        runtime = AgentRuntime(config=ConfigModel(llm_model="original"))
        assert runtime.config.llm_model == "original"

    def test_run_turn_persists_trace(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "agent.runtime.get_db_connection",
            lambda: __import__("sqlite3").connect(":memory:"),
        )
        from agent.db import (
            create_agent_events_table,
            create_agent_runs_table,
            create_sessions_table,
            create_chat_messages_table,
        )
        import sqlite3

        class _NoCloseConnection:
            """Wrapper so run_turn's conn.close() does not break test assertions."""

            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def close(self):
                return None

        conn = sqlite3.connect(":memory:")
        create_sessions_table(conn)
        create_chat_messages_table(conn)
        create_agent_runs_table(conn)
        create_agent_events_table(conn)
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
            ("test-session", "Test", "2026-01-01", "2026-01-01"),
        )
        conn.commit()

        wrapped = _NoCloseConnection(conn)
        monkeypatch.setattr("agent.runtime.get_db_connection", lambda: wrapped)

        runtime = AgentRuntime(config=ConfigModel())
        mock_result = {"final_answer": {"answer": "test response"}}

        async def _run():
            with patch(
                "agent.runtime.run_chat_turn",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                result = await runtime.run_turn(
                    "test-session",
                    "hello",
                    on_activity=lambda e: None,
                )
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM agent_runs WHERE session_id = ?", ("test-session",)
            )
            count = cursor.fetchone()[0]
            return result, count

        result, count = asyncio.run(_run())
        assert "final_answer" in result
        assert count == 1

    def test_run_turn_includes_run_id_in_activity_callback(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "agent.runtime.get_db_connection",
            lambda: __import__("sqlite3").connect(":memory:"),
        )
        from agent.db import (
            create_agent_events_table,
            create_agent_runs_table,
            create_sessions_table,
            create_chat_messages_table,
        )
        import sqlite3

        class _NoCloseConnection:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def close(self):
                return None

        conn = sqlite3.connect(":memory:")
        create_sessions_table(conn)
        create_chat_messages_table(conn)
        create_agent_runs_table(conn)
        create_agent_events_table(conn)
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, last_active) VALUES (?, ?, ?, ?)",
            ("test-session", "Test", "2026-01-01", "2026-01-01"),
        )
        conn.commit()
        wrapped = _NoCloseConnection(conn)
        monkeypatch.setattr("agent.runtime.get_db_connection", lambda: wrapped)

        runtime = AgentRuntime(config=ConfigModel())
        captured = []
        mock_result = {"final_answer": {"answer": "test response"}}

        async def _run_with_emit():
            async def fake_chat(**kwargs):
                on_activity = kwargs.get("on_activity")
                if on_activity:
                    on_activity({
                        "agent": "black_glove",
                        "type": "answer",
                        "content": "test",
                    })
                return mock_result

            with patch("agent.runtime.run_chat_turn", new=fake_chat):
                def on_activity(event):
                    captured.append(event)

                await runtime.run_turn("test-session", "hello", on_activity=on_activity)

        asyncio.run(_run_with_emit())
        assert captured
        assert captured[0].get("run_id")
        assert captured[0].get("id") is not None
