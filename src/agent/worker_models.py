"""
Worker task/result models for parallel orchestration.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from agent.tool_result import ToolResultEnvelope


class WorkerKind(str, Enum):
    ADAPTER = "adapter"
    RESEARCHER = "researcher"
    ANALYST = "analyst"
    REDUCER = "reducer"


class WorkerTask(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    graph_id: str
    step_id: str
    engagement_id: str
    run_id: Optional[str] = None
    session_id: Optional[str] = None
    kind: WorkerKind = WorkerKind.ADAPTER
    agent_name: Optional[str] = None
    tool_name: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    phase: str = "passive"
    parallel_group: Optional[str] = None
    shard_key: Optional[str] = None
    depends_on: List[str] = Field(default_factory=list)
    attempt: int = 1
    max_wall_seconds: float = 600.0
    rationale: str = ""


class WorkerResult(BaseModel):
    task_id: str
    step_id: str
    status: Literal["success", "error", "blocked", "timeout", "cancelled"]
    envelope: ToolResultEnvelope
    structured_output: Optional[Dict[str, Any]] = None
    finding_ids: List[int] = Field(default_factory=list)
    evidence_paths: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    finished_at: Optional[str] = None
    worker_instance_id: str = Field(default_factory=lambda: str(uuid4()))


class FanInBatch(BaseModel):
    batch_id: str = Field(default_factory=lambda: str(uuid4()))
    graph_id: str
    shard_key: str = "default"
    worker_results: List[WorkerResult] = Field(default_factory=list)
    reducer_kind: Literal["deterministic", "analyst_llm"] = "deterministic"
    summary: str = ""
