"""Tests for web API routes."""

import asyncio
import sys
import threading
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

        r = client.get(f"/api/sessions/{sid}/messages")
        assert r.status_code == 200
        roles = [m["role"] for m in r.json()["messages"]]
        assert "user" in roles
        assert "assistant" in roles
        assert any("Completed after disconnect" in m["content"] for m in r.json()["messages"])


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
