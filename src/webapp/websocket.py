"""WebSocket chat handler with streaming and approval."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from webapp.deps import get_deps_runtime, get_deps_session_manager

logger = logging.getLogger("black_glove.webapp.ws")
ws_router = APIRouter()

# Keep background turn tasks alive after WebSocket handler exits
_detached_turns: set[asyncio.Task] = set()


def _spawn_detached(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _detached_turns.add(task)
    task.add_done_callback(_detached_turns.discard)
    return task


def _format_output(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, dict):
        if "answer" in output and len(output) == 1:
            return str(output["answer"])
        if any(k in output for k in ("summary", "findings", "conclusion")):
            lines = []
            if "summary" in output:
                lines.append(f"### {output['summary']}")
            if "findings" in output:
                lines.append("\n**Findings:**")
                findings = output["findings"]
                if isinstance(findings, list):
                    lines.extend(f"- {f}" for f in findings)
                else:
                    lines.append(str(findings))
            if "conclusion" in output:
                lines.append(f"\n**Conclusion:**\n{output['conclusion']}")
            return "\n".join(lines)
        return json.dumps(output, indent=2, default=str)
    return str(output)


def _activity_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": event.get("id"),
        "type": event.get("type", "activity"),
        "agent": event.get("agent"),
        "content": event.get("content"),
        "params": event.get("params"),
        "tool": event.get("tool"),
        "approved": event.get("approved"),
        "run_id": event.get("run_id"),
        "ts": event.get("ts"),
    }


def _ws_is_open(ws: WebSocket) -> bool:
    return (
        ws.client_state == WebSocketState.CONNECTED
        and ws.application_state == WebSocketState.CONNECTED
    )


def _is_disconnect_error(exc: BaseException) -> bool:
    if isinstance(exc, WebSocketDisconnect):
        return True
    if isinstance(exc, RuntimeError):
        return True
    name = type(exc).__name__.lower()
    if "disconnect" in name:
        return True
    msg = str(exc).lower()
    return "close" in msg or "disconnect" in msg


async def _safe_send_json(
    ws: WebSocket, payload: Dict[str, Any], connected: asyncio.Event
) -> bool:
    if not connected.is_set() or not _ws_is_open(ws):
        return False
    try:
        await ws.send_json(payload)
        return True
    except Exception as exc:
        if _is_disconnect_error(exc):
            connected.clear()
            return False
        raise


@ws_router.websocket("/ws/chat/{session_id}")
async def chat_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    sm = get_deps_session_manager()
    runtime = get_deps_runtime()
    connected = asyncio.Event()
    connected.set()

    if not sm.get_session_info(session_id):
        await websocket.send_json({"type": "error", "content": "Session not found"})
        await websocket.close()
        return

    pending_approval: Dict[str, asyncio.Future] = {}
    activity_queue: asyncio.Queue = asyncio.Queue()
    sender_task: Optional[asyncio.Task] = None
    active_turn_task: Optional[asyncio.Task] = None

    async def activity_sender() -> None:
        while True:
            payload = await activity_queue.get()
            try:
                if payload is None:
                    return
                if not await _safe_send_json(websocket, payload, connected):
                    logger.debug(
                        "Stopped activity sender; client disconnected for session %s",
                        session_id,
                    )
                    return
            finally:
                activity_queue.task_done()

    sender_task = asyncio.create_task(activity_sender())

    def on_activity(event: Dict[str, Any]) -> None:
        activity_queue.put_nowait(_activity_payload(event))

    async def approval_callback(tool_name: str, params: dict) -> bool:
        approval_id = f"{tool_name}_{id(params)}"
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        pending_approval[approval_id] = future
        sent = await _safe_send_json(websocket, {
            "type": "approval_request",
            "approval_id": approval_id,
            "tool": tool_name,
            "params": params,
            "content": f"Approve execution of {tool_name}?",
        }, connected)
        if not sent:
            pending_approval.pop(approval_id, None)
            return False
        try:
            result = await asyncio.wait_for(future, timeout=300.0)
            return bool(result)
        except asyncio.TimeoutError:
            return False
        finally:
            pending_approval.pop(approval_id, None)

    async def _run_turn(content: str, history) -> None:
        nonlocal active_turn_task
        try:
            result = await runtime.run_turn(
                session_id,
                content,
                history=history,
                on_activity=on_activity,
                approval_callback=approval_callback,
            )
            await activity_queue.join()
            final_output = result.get("final_answer", result)
            answer_text = _format_output(final_output)
            if not answer_text.strip():
                answer_text = "No response generated."

            sm.save_message(
                session_id,
                "assistant",
                answer_text,
                metadata={"type": "response", "is_final": True},
            )
            if connected.is_set():
                await _safe_send_json(websocket, {
                    "type": "assistant_message",
                    "content": answer_text,
                }, connected)
            else:
                logger.info(
                    "Client disconnected before assistant reply for session %s; "
                    "message persisted",
                    session_id,
                )
        except asyncio.CancelledError:
            logger.info("Chat turn cancelled for session %s", session_id)
            raise
        except Exception as exc:
            logger.exception("Chat turn failed")
            if connected.is_set():
                await _safe_send_json(
                    websocket, {"type": "error", "content": str(exc)}, connected
                )
        finally:
            active_turn_task = None

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await _safe_send_json(
                    websocket, {"type": "error", "content": "Invalid JSON"}, connected
                )
                continue

            msg_type = msg.get("type")

            if msg_type == "ping":
                await _safe_send_json(websocket, {"type": "pong"}, connected)
                continue

            if msg_type == "approval":
                approval_id = msg.get("approval_id")
                approved = msg.get("approved", False)
                future = pending_approval.get(approval_id)
                if future and not future.done():
                    future.set_result(approved)
                continue

            if msg_type == "user_message":
                content = msg.get("content", "").strip()
                if not content:
                    continue

                if active_turn_task is not None and not active_turn_task.done():
                    await _safe_send_json(
                        websocket,
                        {
                            "type": "error",
                            "content": "A scan is already in progress for this session.",
                        },
                        connected,
                    )
                    continue

                sm.update_session_activity(session_id)
                history = sm.load_session(session_id)
                sm.save_message(
                    session_id, "user", content, metadata={"type": "user_input"}
                )

                await _safe_send_json(
                    websocket, {"type": "status", "content": "acting"}, connected
                )

                active_turn_task = _spawn_detached(_run_turn(content, history))

    except WebSocketDisconnect:
        connected.clear()
        logger.info(
            "WebSocket disconnected for session %s; background turn continues if active",
            session_id,
        )
    except Exception:
        logger.exception("WebSocket error")
        if connected.is_set():
            await _safe_send_json(
                websocket, {"type": "error", "content": "WebSocket error"}, connected
            )
    finally:
        connected.clear()
        if active_turn_task is not None and not active_turn_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(active_turn_task), timeout=300.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                logger.info(
                    "Background turn for session %s did not finish before handler exit",
                    session_id,
                )
        if sender_task is not None:
            await activity_queue.join()
            activity_queue.put_nowait(None)
            try:
                await asyncio.wait_for(sender_task, timeout=5.0)
            except asyncio.TimeoutError:
                sender_task.cancel()
