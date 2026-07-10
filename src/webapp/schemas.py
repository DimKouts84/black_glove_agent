"""Pydantic schemas for web API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ConfigPatchRequest(BaseModel):
    """Partial config update - any ConfigModel fields."""
    llm_provider: Optional[str] = None
    llm_endpoint: Optional[str] = None
    llm_model: Optional[str] = None
    llm_temperature: Optional[float] = None
    llm_api_key: Optional[str] = None
    llm_timeout: Optional[int] = None
    llm_retry_attempts: Optional[int] = None
    llm_retry_backoff_factor: Optional[float] = None
    scan_timeout: Optional[int] = None
    log_level: Optional[str] = None
    log_retention_days: Optional[int] = None
    enable_exploit_adapters: Optional[bool] = None
    require_approval: Optional[bool] = None
    evidence_storage_path: Optional[str] = None
    web_host: Optional[str] = None
    web_port: Optional[int] = None
    web_api_token: Optional[str] = None
    adapters: Optional[Dict[str, Dict[str, Any]]] = None
    extra_settings: Optional[Dict[str, Any]] = None

    def to_partial_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.model_dump().items() if v is not None}


class SessionCreateRequest(BaseModel):
    title: Optional[str] = "Security Assessment"


class AssetCreateRequest(BaseModel):
    name: str
    type: str = Field(..., pattern="^(host|domain|vm)$")
    value: str


class ReportGenerateRequest(BaseModel):
    format: str = "markdown"
    include_evidence: bool = True


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
