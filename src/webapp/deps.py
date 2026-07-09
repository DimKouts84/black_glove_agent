"""FastAPI dependency injection singletons."""

from __future__ import annotations

from typing import Optional

from agent.config_service import ConfigService, get_config_service
from agent.runtime import AgentRuntime, get_agent_runtime, reset_agent_runtime
from agent.session_manager import SessionManager

_config_service: Optional[ConfigService] = None
_runtime: Optional[AgentRuntime] = None
_session_manager: Optional[SessionManager] = None


def get_deps_config_service() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = get_config_service()
    return _config_service


def get_deps_runtime() -> AgentRuntime:
    global _runtime
    if _runtime is None:
        _runtime = get_agent_runtime()
    return _runtime


def get_deps_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def reset_deps() -> None:
    """Reset all singletons (for tests)."""
    global _config_service, _runtime, _session_manager
    _config_service = None
    _runtime = None
    _session_manager = None
    reset_agent_runtime()
