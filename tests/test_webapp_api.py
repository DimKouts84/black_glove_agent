"""Tests for web API routes."""

import asyncio
import sys
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.websockets import WebSocketDisconnect, WebSocketState

sys.path.insert(0, "src")

from fastapi.testclient import TestClient
from webapp.app import create_app
from webapp.deps import reset_deps
from webapp.websocket import _is_disconnect_error, _safe_send_json, _ws_is_open


@pytest.fixture
def client(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    reset_deps()
    app = create_app()
    with TestClient(app) as c:
        yield c
    reset_deps()


class TestWebAPI:
    def test_create_app_imports(self):
        app = create_app()
        assert app is not None

    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_config_get(self, client):
        r = client.get("/api/config")
        assert r.status_code == 200
        assert "llm_provider" in r.json()

    def test_config_schema(self, client):
        r = client.get("/api/config/schema")
        assert r.status_code == 200
        assert "fields" in r.json()

    def test_config_patch(self, client):
        r = client.patch("/api/config", json={"llm_model": "test-model"})
        assert r.status_code == 200
        assert r.json()["llm_model"] == "test-model"

    def test_config_patch_persists_after_reload_with_cwd_config(self, client, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cwd_config = tmp_path / "config.yaml"
        cwd_config.write_text("llm_provider: ollama\nllm_model: original-model\n")
        r = client.patch("/api/config", json={"llm_model": "persisted-model"})
        assert r.status_code == 200
        assert r.json()["llm_model"] == "persisted-model"
        r = client.get("/api/config")
        assert r.status_code == 200
        assert r.json()["llm_model"] == "persisted-model"

    def test_sessions_crud(self, client):
        r = client.post("/api/sessions", json={"title": "Test Session"})
        assert r.status_code == 200
        sid = r.json()["id"]

        r = client.get("/api/sessions")
        assert r.status_code == 200
        assert len(r.json()["sessions"]) >= 1

        r = client.get(f"/api/sessions/{sid}/messages")
        assert r.status_code == 200

        r = client.delete(f"/api/sessions/{sid}")
        assert r.status_code == 200

    def test_tools_dynamic(self, client):
        r = client.get("/api/tools")
        assert r.status_code == 200
        assert "tools" in r.json()
        assert len(r.json()["tools"]) > 0

    def test_findings_and_assets(self, client):
        r = client.get("/api/findings")
        assert r.status_code == 200
        r = client.get("/api/assets")
        assert r.status_code == 200

    def test_websocket_ping(self, client):
        r = client.post("/api/sessions", json={"title": "WS Test"})
        assert r.status_code == 200
        sid = r.json()["id"]

        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "ping"})
            msg = ws.receive_json()
            assert msg["type"] == "pong"

    def test_websocket_streams_activity_before_answer(self, client):
        from unittest.mock import patch

        r = client.post("/api/sessions", json={"title": "Stream Test"})
        assert r.status_code == 200
        sid = r.json()["id"]

        async def mock_run_turn(
            session_id, content, history=None, on_activity=None, approval_callback=None
        ):
            if on_activity:
                on_activity({
                    "type": "thinking",
                    "agent": "planner_agent",
                    "content": "Planning scan",
                    "run_id": "run-123",
                })
                on_activity({
                    "type": "tool_call",
                    "agent": "researcher_agent",
                    "content": "nmap",
                    "params": {"target": "example.com"},
                    "run_id": "run-123",
                })
            return {"final_answer": {"answer": "Scan complete"}}

        with patch("webapp.websocket.get_deps_runtime") as mock_runtime:
            mock_runtime.return_value.run_turn = mock_run_turn
            with client.websocket_connect(f"/ws/chat/{sid}") as ws:
                ws.send_json({"type": "user_message", "content": "scan example.com"})
                messages = []
                while len(messages) < 10:
                    msg = ws.receive_json()
                    messages.append(msg)
                    if msg.get("type") == "assistant_message":
                        break

                types = [m["type"] for m in messages]
                assert "status" in types
                assert "thinking" in types
                assert "tool_call" in types
                assert types.index("thinking") < types.index("assistant_message")
                assert types.index("tool_call") < types.index("assistant_message")

                thinking = next(m for m in messages if m["type"] == "thinking")
                assert thinking["agent"] == "planner_agent"
                assert thinking.get("run_id") == "run-123"
                answer = next(m for m in messages if m["type"] == "assistant_message")
                assert answer.get("run_id") == "run-123"

        saved = client.get(f"/api/sessions/{sid}/messages")
        assistant = next(m for m in saved.json()["messages"] if m["role"] == "assistant")
        assert assistant["metadata"]["run_id"] == "run-123"

    def test_session_trace_endpoint(self, client):
        r = client.post("/api/sessions", json={"title": "Trace Test"})
        sid = r.json()["id"]
        r = client.get(f"/api/sessions/{sid}/trace")
        assert r.status_code == 200
        assert "runs" in r.json()
        assert isinstance(r.json()["runs"], list)

    def test_websocket_disconnect_during_run_turn(self, client):
        r = client.post("/api/sessions", json={"title": "Disconnect Test"})
        assert r.status_code == 200
        sid = r.json()["id"]
        turn_started = threading.Event()
        turn_finished = threading.Event()

        async def mock_run_turn(
            session_id, content, history=None, on_activity=None, approval_callback=None
        ):
            turn_started.set()
            if on_activity:
                on_activity({
                    "type": "thinking",
                    "agent": "planner_agent",
                    "content": "Planning",
                    "run_id": "run-disconnect",
                })
            await asyncio.sleep(0.3)
            if on_activity:
                on_activity({
                    "type": "tool_call",
                    "agent": "researcher_agent",
                    "content": "nmap",
                    "run_id": "run-disconnect",
                })
            turn_finished.set()
            return {"final_answer": {"answer": "Completed after disconnect"}}

        with patch("webapp.websocket.get_deps_runtime") as mock_runtime:
            mock_runtime.return_value.run_turn = mock_run_turn
            with client.websocket_connect(f"/ws/chat/{sid}") as ws:
                ws.send_json({"type": "user_message", "content": "scan example.com"})
                assert turn_started.wait(timeout=2.0)
                ws.close()
                assert turn_finished.wait(timeout=5.0)

        deadline = time.time() + 3.0
        roles: list = []
        while time.time() < deadline:
            r = client.get(f"/api/sessions/{sid}/messages")
            assert r.status_code == 200
            roles = [m["role"] for m in r.json()["messages"]]
            if "assistant" in roles:
                break
            time.sleep(0.05)

        r = client.get(f"/api/sessions/{sid}/messages")
        assert r.status_code == 200
        roles = [m["role"] for m in r.json()["messages"]]
        assert "user" in roles
        assert "assistant" in roles
        assert any("Completed after disconnect" in m["content"] for m in r.json()["messages"])

    def test_reports_returns_latest_run_full_body(self, client, tmp_path):
        report = tmp_path / "run-new.md"
        report.write_text("# Full report\n" + ("detail line\n" * 80), encoding="utf-8")
        with patch("webapp.routes._latest_run_id", return_value="run-new"), patch(
            "webapp.routes.ReportTool"
        ) as tool_cls:
            tool_cls.return_value.execute.return_value = {
                "format": "markdown",
                "report_path": str(report),
                "report_preview": "short preview",
                "summary": "one run",
            }
            response = client.post("/api/reports", json={"format": "markdown"})

        assert response.status_code == 200
        body = response.json()
        assert body["run_id"] == "run-new"
        assert body["content"] == report.read_text(encoding="utf-8")
        assert "short preview" not in body["content"]

    def test_reports_404_when_no_runs(self, client):
        with patch("webapp.routes._latest_run_id", return_value=None):
            response = client.post("/api/reports", json={"format": "markdown"})
        assert response.status_code == 404

    def test_reports_endpoint_returns_latest_run_body(self, tmp_path, monkeypatch):
        db_path = tmp_path / "homepentest.db"
        monkeypatch.setattr("agent.db.DB_PATH", db_path)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        from agent.db import get_db_connection, init_db

        init_db()
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO sessions (id, title) VALUES ('s', 't')")
            conn.execute(
                "INSERT INTO agent_runs (id, session_id, query, status, started_at) VALUES (?, ?, ?, ?, ?)",
                ("run-old", "s", "old", "completed", "2020-01-01T00:00:00"),
            )
            conn.execute(
                "INSERT INTO agent_runs (id, session_id, query, status, started_at) VALUES (?, ?, ?, ?, ?)",
                ("run-new", "s", "new", "completed", "2026-01-01T00:00:00"),
            )
            conn.execute(
                "INSERT INTO assets (name, type, value) VALUES ('example.com', 'domain', 'example.com')"
            )
            asset_id = conn.execute("SELECT id FROM assets").fetchone()[0]
            conn.execute(
                "INSERT INTO findings (asset_id, title, severity, confidence, description, run_id) "
                "VALUES (?, 'OLD-RUN-MARKER', 'high', 0.9, 'old finding', 'run-old')",
                (asset_id,),
            )
            conn.execute(
                "INSERT INTO findings (asset_id, title, severity, confidence, description, run_id) "
                "VALUES (?, 'LATEST-ONLY-MARKER', 'high', 0.9, 'latest finding body', 'run-new')",
                (asset_id,),
            )
            old_id = conn.execute(
                "SELECT id FROM findings WHERE title = 'OLD-RUN-MARKER'"
            ).fetchone()[0]
            new_id = conn.execute(
                "SELECT id FROM findings WHERE title = 'LATEST-ONLY-MARKER'"
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO finding_observations (finding_id, run_id, description) VALUES (?, 'run-old', 'old finding')",
                (old_id,),
            )
            conn.execute(
                "INSERT INTO finding_observations (finding_id, run_id, description) VALUES (?, 'run-new', 'latest finding body')",
                (new_id,),
            )
            conn.commit()
        finally:
            conn.close()

        reset_deps()
        app = create_app()
        with TestClient(app) as client:
            response = client.post("/api/reports", json={"format": "markdown"})
        reset_deps()

        assert response.status_code == 200
        body = response.json()
        assert body["run_id"] == "run-new"
        assert "LATEST-ONLY-MARKER" in body["content"]
        assert "OLD-RUN-MARKER" not in body["content"]
        report_path = Path(body["report_path"])
        assert body["content"] == report_path.read_text(encoding="utf-8")
        assert len(body["content"]) > len(body.get("summary") or "")

    def test_package_requires_python_39(self):
        text = open("pyproject.toml", encoding="utf-8").read()
        assert 'requires-python = ">=3.9"' in text
        assert 'python_version = "3.9"' in text

    def test_delete_asset_removes_findings(self, tmp_path, monkeypatch):
        import agent.db as db_module

        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "homepentest.db")
        reset_deps()
        app = create_app()
        with TestClient(app) as client:
            created = client.post(
                "/api/assets",
                json={"name": "probe", "type": "host", "value": "192.0.2.77"},
            )
            assert created.status_code == 200
            asset_id = created.json()["id"]
            conn = db_module.get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO findings (asset_id, title, severity, confidence) VALUES (?, ?, ?, ?)",
                    (asset_id, "probe finding", "low", 0.5),
                )
                finding_id = cursor.lastrowid
                cursor.execute(
                    "INSERT INTO finding_observations (finding_id, description) VALUES (?, ?)",
                    (finding_id, "probe"),
                )
                conn.commit()
            finally:
                conn.close()

            deleted = client.delete(f"/api/assets/{asset_id}")
            assert deleted.status_code == 200
            assert deleted.json()["deleted"] is True

            listed = client.get("/api/assets")
            assert all(item["id"] != asset_id for item in listed.json()["assets"])
            conn = db_module.get_db_connection()
            try:
                findings = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE asset_id = ?", (asset_id,)
                ).fetchone()[0]
                observations = conn.execute(
                    "SELECT COUNT(*) FROM finding_observations WHERE finding_id = ?",
                    (finding_id,),
                ).fetchone()[0]
            finally:
                conn.close()
            assert findings == 0
            assert observations == 0
        reset_deps()


class TestWebSocketHelpers:
    def test_safe_send_json_success(self):
        async def _run() -> None:
            ws = AsyncMock()
            ws.client_state = WebSocketState.CONNECTED
            ws.application_state = WebSocketState.CONNECTED
            connected = asyncio.Event()
            connected.set()

            ok = await _safe_send_json(ws, {"type": "pong"}, connected)

            assert ok is True
            assert connected.is_set()
            ws.send_json.assert_awaited_once_with({"type": "pong"})

        asyncio.run(_run())

    def test_safe_send_json_clears_connected_on_disconnect(self):
        async def _run() -> None:
            ws = AsyncMock()
            ws.client_state = WebSocketState.CONNECTED
            ws.application_state = WebSocketState.CONNECTED
            ws.send_json.side_effect = RuntimeError(
                'Cannot call "send" once a close message has been sent.'
            )
            connected = asyncio.Event()
            connected.set()

            ok = await _safe_send_json(ws, {"type": "error"}, connected)

            assert ok is False
            assert not connected.is_set()

        asyncio.run(_run())

    def test_safe_send_json_skips_when_not_connected(self):
        async def _run() -> None:
            ws = AsyncMock()
            connected = asyncio.Event()

            ok = await _safe_send_json(ws, {"type": "pong"}, connected)

            assert ok is False
            ws.send_json.assert_not_called()

        asyncio.run(_run())

    def test_ws_is_open(self):
        ws = MagicMock()
        ws.client_state = WebSocketState.CONNECTED
        ws.application_state = WebSocketState.CONNECTED
        assert _ws_is_open(ws) is True

        ws.application_state = WebSocketState.DISCONNECTED
        assert _ws_is_open(ws) is False

    def test_is_disconnect_error(self):
        assert _is_disconnect_error(WebSocketDisconnect()) is True
        assert _is_disconnect_error(RuntimeError("close message has been sent")) is True
        assert _is_disconnect_error(ValueError("bad payload")) is False
