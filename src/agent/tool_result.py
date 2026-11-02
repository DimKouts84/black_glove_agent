"""
Structured tool result envelopes for cross-agent information passing.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


def _is_retryable_error(error: Optional[str], status: str) -> bool:
    if status != "error":
        return False
    if not error:
        return True
    try:
        from adapters.transient_errors import is_transient_adapter_error
        return is_transient_adapter_error(error)
    except ImportError:
        return True


class ToolResultEnvelope(BaseModel):
    """Canonical result passed between executor, agents, and persistence."""

    status: str = "success"
    tool_name: str
    summary: str = ""
    finding_ids: List[int] = Field(default_factory=list)
    evidence_paths: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    coverage: Dict[str, Any] = Field(default_factory=dict)
    retryable: bool = False
    error: Optional[str] = None
    raw_digest: Optional[str] = None
    report_content: Optional[str] = None
    report_path: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

    def to_llm_context(self, max_len: int = 8000) -> str:
        """Bounded string for LLM history without losing pointers."""
        payload: Dict[str, Any] = {
            "status": self.status,
            "summary": self.summary,
            "finding_ids": self.finding_ids,
            "evidence_paths": self.evidence_paths,
            "metrics": self.metrics,
            "warnings": self.warnings,
            "coverage": self.coverage,
            "error": self.error,
            "raw_digest": self.raw_digest,
        }
        if self.report_content:
            payload["report_preview"] = self.report_content[:1500]
        if self.report_path:
            payload["report_path"] = self.report_path
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

    def to_trace_details(self) -> Dict[str, Any]:
        """Structured metadata for trace persistence."""
        details: Dict[str, Any] = {
            "tool": self.tool_name,
            "status": self.status,
            "evidence_paths": self.evidence_paths,
            "warnings": self.warnings,
            "coverage": self.coverage,
            "metrics": self.metrics,
            "result_digest": self.raw_digest,
            "error": self.error,
        }
        if self.report_path:
            details["report_path"] = self.report_path
        return details

    @classmethod
    def _map_adapter_status(cls, status_value: Optional[str]) -> str:
        mapping = {
            "success": "success",
            "partial": "partial",
            "failure": "error",
            "error": "error",
            "timeout": "error",
        }
        return mapping.get(str(status_value or "").lower(), "success")

    @classmethod
    def _extract_subagent_fields(cls, data: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        if "result" in data and isinstance(data["result"], dict):
            inner = data["result"]
            if "summary" in inner:
                success = inner.get("success", True)
                status = "success" if success else "error"
                summary = str(inner.get("summary", ""))[:500]
                if not summary:
                    summary = "Subagent reported failure" if not success else "Subagent completed"
                return status, summary
        if "scan_plan" in data and isinstance(data["scan_plan"], dict):
            inner = data["scan_plan"]
            goal = str(inner.get("goal", "Scan plan ready"))[:500]
            return "success", goal
        if "analysis" in data and isinstance(data["analysis"], dict):
            inner = data["analysis"]
            summary = str(inner.get("summary") or "Analysis ready")
            titles = [
                str(item.get("title"))
                for item in (inner.get("findings") or [])
                if isinstance(item, dict) and item.get("title")
            ]
            if titles:
                summary = summary + " Findings: " + "; ".join(titles)
            return "success", summary[:500]
        if "final_answer" in data:
            inner = data["final_answer"]
            if isinstance(inner, dict) and "answer" in inner:
                return "success", str(inner["answer"])[:500]
            if isinstance(inner, str):
                return "success", inner[:500]
        return None

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
                retryable=_is_retryable_error(result, "error"),
            )

        if isinstance(result, str) and not result.startswith("Error:"):
            preview = result[:1500] + ("...[truncated]" if len(result) > 1500 else "")
            return cls(
                status="success",
                tool_name=tool_name,
                summary=preview[:500] or f"{tool_name} completed",
                report_content=preview if len(result) > 200 else None,
                raw_digest=result[:2000] + ("...[digest_truncated]" if len(result) > 2000 else ""),
            )

        data = result if isinstance(result, dict) else {"value": result}
        evidence_paths: List[str] = []
        if isinstance(data, dict) and data.get("evidence_path"):
            evidence_paths.append(str(data["evidence_path"]))

        if (
            tool_name == "generate_report"
            and isinstance(data, dict)
            and data.get("report_path")
        ):
            report_path = str(data["report_path"])
            summary = str(data.get("summary", "Report generated"))[:500]
            preview = str(data.get("report_preview", ""))[:1500]
            return cls(
                status="success",
                tool_name=tool_name,
                summary=summary,
                report_content=preview or None,
                report_path=report_path,
                raw_digest=report_path,
                evidence_paths=[report_path],
                data=data,
            )

        subagent = cls._extract_subagent_fields(data) if isinstance(data, dict) else None
        if subagent:
            status, summary = subagent
            digest = json.dumps(data, default=str)
            if "analysis" not in data and len(digest) > 2000:
                digest = digest[:2000] + "...[digest_truncated]"
            return cls(
                status=status,
                tool_name=tool_name,
                summary=summary,
                error=summary if status == "error" else None,
                raw_digest=digest,
                data=data,
                evidence_paths=evidence_paths,
                retryable=_is_retryable_error(summary if status == "error" else None, status),
            )

        status = "success"
        warnings: List[str] = []
        coverage: Dict[str, Any] = {}
        if isinstance(data, dict):
            if data.get("not_applicable"):
                status = "not_applicable"
            elif data.get("coverage", {}).get("untested") and data.get("coverage", {}).get("reason"):
                status = "not_applicable"
            elif data.get("adapter_status"):
                status = cls._map_adapter_status(data.get("adapter_status"))
            elif data.get("coverage", {}).get("untested"):
                status = "partial"
            warnings = list(data.get("warnings") or [])
            for item in data.get("transient_retry_warnings") or []:
                text = str(item)
                if text and text not in warnings:
                    warnings.append(text)
            coverage = dict(data.get("coverage") or {})

        summary = interpretation or ""
        if not summary and isinstance(data, dict):
            summary = str(data.get("interpretation", ""))[:500]
        if not summary:
            if status == "not_applicable":
                summary = data.get("message", f"{tool_name}: not applicable (no test surface)")
            elif status == "partial":
                summary = f"{tool_name} returned partial results"
            elif status == "error":
                summary = str(
                    data.get("error_message")
                    or data.get("error")
                    or f"{tool_name} failed"
                )
            else:
                value = data.get("value") if isinstance(data, dict) else None
                if isinstance(value, str) and value.strip():
                    summary = value[:500]
                else:
                    summary = f"{tool_name} completed"

        finding_ids: List[int] = []
        if isinstance(data, dict):
            raw_ids = data.get("finding_ids")
            if not raw_ids and isinstance(data.get("envelope"), dict):
                raw_ids = data["envelope"].get("finding_ids")
            if isinstance(raw_ids, list):
                for item in raw_ids:
                    try:
                        finding_ids.append(int(item))
                    except (TypeError, ValueError):
                        continue

        digest = json.dumps(data, default=str)
        if len(digest) > 2000:
            digest = digest[:2000] + "...[digest_truncated]"

        return cls(
            status=status,
            tool_name=tool_name,
            summary=summary,
            finding_ids=finding_ids,
            raw_digest=digest,
            data=data if isinstance(data, dict) else None,
            evidence_paths=evidence_paths,
            warnings=warnings,
            coverage=coverage,
            error=summary if status == "error" else None,
            retryable=_is_retryable_error(summary if status == "error" else None, status),
        )

    @classmethod
    def from_tool_return(cls, tool_name: str, result: Any) -> "ToolResultEnvelope":
        """Reuse an envelope the wrapper already built, including finding ids."""
        if isinstance(result, dict):
            nested = result.get("envelope")
            if isinstance(nested, dict) and nested.get("status"):
                env = cls.model_validate(nested)
                if not env.finding_ids and result.get("finding_ids"):
                    env.finding_ids = [int(item) for item in result["finding_ids"]]
                if result.get("evidence_path"):
                    path = str(result["evidence_path"])
                    if path not in env.evidence_paths:
                        env.evidence_paths.append(path)
                return env
        return cls.from_raw(tool_name, result)

    @classmethod
    def from_adapter_result(
        cls,
        tool_name: str,
        adapter_result: Any,
        payload: Dict[str, Any],
        interpretation: Optional[str] = None,
    ) -> "ToolResultEnvelope":
        status_value = getattr(getattr(adapter_result, "status", None), "value", "success")
        enriched = dict(payload)
        enriched["adapter_status"] = status_value
        if interpretation:
            enriched["interpretation"] = interpretation
        if getattr(adapter_result, "metadata", None):
            meta = adapter_result.metadata
            meta_warnings = list(meta.get("warnings") or [])
            meta_warnings.extend(meta.get("transient_retry_warnings") or [])
            if meta_warnings:
                enriched.setdefault("warnings", [])
                merged = list(enriched.get("warnings") or [])
                for item in meta_warnings:
                    text = str(item)
                    if text and text not in merged:
                        merged.append(text)
                enriched["warnings"] = merged
        return cls.from_raw(tool_name, enriched, interpretation=interpretation)
