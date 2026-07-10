"""
Thread-local run provenance for tool execution and findings persistence.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Dict, Optional

_run_context: ContextVar[Optional[Dict[str, Any]]] = ContextVar("run_context", default=None)


def set_run_context(
    *,
    session_id: Optional[str] = None,
    run_id: Optional[str] = None,
    step_id: Optional[str] = None,
) -> None:
    _run_context.set(
        {
            "session_id": session_id,
            "run_id": run_id,
            "step_id": step_id,
        }
    )


def clear_run_context() -> None:
    _run_context.set(None)


def get_run_context() -> Dict[str, Any]:
    return dict(_run_context.get() or {})
