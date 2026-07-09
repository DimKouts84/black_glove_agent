"""
Persisted work-graph models for governed pentest execution.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class WorkPhase(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    CREDENTIAL = "credential"
    EXPLOIT = "exploit"
    ANALYSIS = "analysis"
    REPORT = "report"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class EngagementStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkStep(BaseModel):
    """Single executable unit in a work graph."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    tool: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    phase: WorkPhase = WorkPhase.PASSIVE
    rationale: str = ""
    depends_on: List[str] = Field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    risk_class: str = "passive"
    retry_count: int = 0
    max_retries: int = 1
    result_digest: Optional[str] = None
    evidence_paths: List[str] = Field(default_factory=list)
    finding_ids: List[int] = Field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class WorkGraph(BaseModel):
    """Ordered collection of steps with engagement metadata."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    engagement_id: str
    session_id: Optional[str] = None
    run_id: Optional[str] = None
    goal: str
    status: EngagementStatus = EngagementStatus.PENDING
    current_phase: WorkPhase = WorkPhase.PASSIVE
    steps: List[WorkStep] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    completed_step_ids: List[str] = Field(default_factory=list)
    revision: int = 1


class Engagement(BaseModel):
    """Scoped pentest engagement bound to authorized targets."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    targets: List[str] = Field(default_factory=list)
    status: EngagementStatus = EngagementStatus.PENDING
    session_id: Optional[str] = None
    lab_mode: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    budget: Dict[str, Any] = Field(
        default_factory=lambda: {
            "max_steps": 50,
            "max_wall_seconds": 3600,
            "max_concurrent_passive": 2,
            "max_credential_attempts": 100,
        }
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EngagementBudget(BaseModel):
    """Runtime budget counters."""

    steps_executed: int = 0
    wall_seconds: float = 0.0
    credential_attempts: int = 0
    started_at: Optional[str] = None

    def within_limits(self, engagement: Engagement) -> bool:
        budget = engagement.budget
        if self.steps_executed >= budget.get("max_steps", 50):
            return False
        if self.wall_seconds >= budget.get("max_wall_seconds", 3600):
            return False
        return True
