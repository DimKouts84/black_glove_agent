"""
Structured tool result envelopes for cross-agent information passing.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolResultEnvelope(BaseModel):
    """Canonical result passed between executor, agents, and persistence."""

    status: str = "success"
    tool_name: str
    summary: str = ""
    finding_ids: List[int] = Field(default_factory=list)
    evidence_paths: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    retryable: bool = False
    error: Optional[str] = None
    raw_digest: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

    def to_llm_context(self, max_len: int = 8000) -> str:
        """Bounded string for LLM history without losing pointers."""
        payload = {
            "status": self.status,
            "summary": self.summary,
            "finding_ids": self.finding_ids,
            "evidence_paths": self.evidence_paths,
            "metrics": self.metrics,
            "error": self.error,
            "raw_digest": self.raw_digest,
        }
        if self.data:
            display = dict(self.data)
            display.pop("interpretation", None)
            if "interpretation" in (self.data or {}):
                payload["interpretation"] = self.data["interpretation"]
            payload["data_keys"] = list(display.keys())
        text = json.dumps(payload, default=str)
        if len(text) > max_len:
            return text[:max_len] + "...[truncated]"
        return text

    @classmethod
    def from_raw(
        cls,
        tool_name: str,
        result: Any,
        *,
        interpretation: Optional[str] = None,
    ) -> "ToolResultEnvelope":
        if isinstance(result, str) and result.startswith("Error:"):
            return cls(
                status="error",
                tool_name=tool_name,
                summary=result,
                error=result,
                retryable=True,
            )
        data = result if isinstance(result, dict) else {"value": result}
        evidence_paths = []
        if isinstance(data, dict) and data.get("evidence_path"):
            evidence_paths.append(str(data["evidence_path"]))
        summary = interpretation or ""
        if not summary and isinstance(data, dict):
            summary = str(data.get("interpretation", ""))[:500]
        if not summary:
            summary = f"{tool_name} completed"
        digest = json.dumps(data, default=str)
        if len(digest) > 2000:
            digest = digest[:2000] + "...[digest_truncated]"
        return cls(
            status="success",
            tool_name=tool_name,
            summary=summary,
            raw_digest=digest,
            data=data if isinstance(data, dict) else None,
            evidence_paths=evidence_paths,
        )
