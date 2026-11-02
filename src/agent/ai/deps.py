"""Per-turn dependencies shared by the coordinator and domain specialists."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Set

from agent.models import ConfigModel
from agent.tools.registry import ToolRegistry

ActivityCallback = Callable[[Dict[str, Any]], None]
ApprovalCallback = Callable[[str, Dict[str, Any]], Awaitable[bool]]

HTTP_PORTS = frozenset({80, 443, 8080, 8443})


@dataclass
class SessionScanState:
    """Nmap evidence remembered for one chat session."""

    open_ports: Set[int] = field(default_factory=set)
    nmap_seen: bool = False


_SESSION_SCAN: Dict[str, SessionScanState] = {}


def session_scan_state(session_id: str) -> SessionScanState:
    """Return the mutable scan evidence for a session, creating it on first use."""
    state = _SESSION_SCAN.get(session_id)
    if state is None:
        state = SessionScanState()
        _SESSION_SCAN[session_id] = state
    return state


def reset_session_scan_state(session_id: Optional[str] = None) -> None:
    """Drop remembered nmap evidence. Tests use this to isolate sessions."""
    if session_id is None:
        _SESSION_SCAN.clear()
        return
    _SESSION_SCAN.pop(session_id, None)


@dataclass
class TurnDeps:
    """Objects a tool call needs that are not model arguments."""

    config: ConfigModel
    tool_registry: ToolRegistry
    session_id: str
    scan_state: SessionScanState
    require_approval: bool
    safe_tools: Set[str]
    approval_callback: Optional[ApprovalCallback] = None
    on_activity: Optional[ActivityCallback] = None
    agent_name: str = "black_glove"
    temperature: float = 0.7


def emit_activity(
    deps: TurnDeps,
    event_type: str,
    content: Any,
    **kwargs: Any,
) -> None:
    """Send one timeline event using the names the web UI already renders."""
    if deps.on_activity is None:
        return
    from datetime import datetime

    deps.on_activity(
        {
            "agent": deps.agent_name,
            "type": event_type,
            "content": content,
            "ts": datetime.now().isoformat(),
            **kwargs,
        }
    )
