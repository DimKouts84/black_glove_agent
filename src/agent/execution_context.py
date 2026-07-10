"""
Immutable execution context for concurrent agent/worker runs.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional
from uuid import uuid4

ActivityCallback = Callable[[Dict[str, Any]], None]
ApprovalCallback = Callable[[str, Dict[str, Any]], Awaitable[bool]]


@dataclass(frozen=True)
class ActivityEvent:
    """Structured activity payload for UI adapters."""

    type: str
    content: Any
    agent: str = "unknown"
    run_id: Optional[str] = None
    graph_id: Optional[str] = None
    step_id: Optional[str] = None
    task_id: Optional[str] = None
    worker_instance_id: Optional[str] = None
    parallel_group: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "type": self.type,
            "content": self.content,
            "agent": self.agent,
        }
        for key in (
            "run_id",
            "graph_id",
            "step_id",
            "task_id",
            "worker_instance_id",
            "parallel_group",
            "params",
        ):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        payload.update(self.extra)
        return payload


@dataclass
class ExecutionContext:
    """Per-run immutable context passed through orchestration."""

    session_id: str
    run_id: str
    on_activity: Optional[ActivityCallback] = None
    approval_callback: Optional[ApprovalCallback] = None
    engagement_id: Optional[str] = None
    graph_id: Optional[str] = None
    cancel_event: Optional[asyncio.Event] = None
    config_snapshot: Optional[Dict[str, Any]] = None
    budget_snapshot: Optional[Dict[str, Any]] = None

    def emit(self, event_type: str, content: Any, **kwargs) -> None:
        if not self.on_activity:
            return
        event = ActivityEvent(
            type=event_type,
            content=content,
            run_id=self.run_id,
            graph_id=self.graph_id,
            **kwargs,
        )
        self.on_activity(event.to_dict())

    def is_cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())


@dataclass(frozen=True)
class WorkerContext:
    """Worker-scoped context derived from an execution context."""

    parent: ExecutionContext
    task_id: str
    step_id: str
    worker_instance_id: str
    parallel_group: Optional[str] = None
    shard_key: Optional[str] = None
    attempt: int = 1

    @classmethod
    def create(
        cls,
        parent: ExecutionContext,
        *,
        step_id: str,
        parallel_group: Optional[str] = None,
        shard_key: Optional[str] = None,
        attempt: int = 1,
    ) -> "WorkerContext":
        return cls(
            parent=parent,
            task_id=str(uuid4()),
            step_id=step_id,
            worker_instance_id=str(uuid4()),
            parallel_group=parallel_group,
            shard_key=shard_key,
            attempt=attempt,
        )

    def emit(self, event_type: str, content: Any, **kwargs) -> None:
        self.parent.emit(
            event_type,
            content,
            step_id=self.step_id,
            task_id=self.task_id,
            worker_instance_id=self.worker_instance_id,
            parallel_group=self.parallel_group,
            **kwargs,
        )

    @property
    def session_id(self) -> str:
        return self.parent.session_id

    @property
    def run_id(self) -> str:
        return self.parent.run_id

    @property
    def approval_callback(self) -> Optional[ApprovalCallback]:
        return self.parent.approval_callback

    @property
    def cancel_event(self) -> Optional[asyncio.Event]:
        return self.parent.cancel_event
