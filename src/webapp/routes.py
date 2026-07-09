"""REST API route handlers."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from agent.db import get_db_connection
from agent.models import AssetModel, AssetType, DatabaseManager
from agent.tools.report_tool import ReportTool
from webapp.deps import (
    get_deps_config_service,
    get_deps_runtime,
    get_deps_session_manager,
)
from webapp.schemas import (
    AssetCreateRequest,
    ConfigPatchRequest,
    HealthResponse,
    ReportGenerateRequest,
    SessionCreateRequest,
)

router = APIRouter(prefix="/api")


def _check_token(token: Optional[str], expected: Optional[str]) -> None:
    if expected and token != expected:
        raise HTTPException(status_code=401, detail="Invalid API token")


@router.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse()


@router.get("/version")
def version():
    return {"version": "0.1.0", "name": "black-glove"}


# --- Config ---

@router.get("/config")
def get_config():
    svc = get_deps_config_service()
    return svc.to_dict(masked=True)


@router.get("/config/schema")
def get_config_schema():
    svc = get_deps_config_service()
    return {"fields": svc.schema()}


@router.patch("/config")
def patch_config(body: ConfigPatchRequest):
    svc = get_deps_config_service()
    partial = body.to_partial_dict()
    if not partial:
        raise HTTPException(status_code=400, detail="No fields to update")
    config = svc.save(partial)
    get_deps_runtime().reload_config()
    return svc.to_masked_dict(config.model_dump())


@router.post("/config/validate")
def validate_config(body: ConfigPatchRequest):
    svc = get_deps_config_service()
    try:
        result = svc.validate_partial(body.to_partial_dict())
        return {"valid": True, "config": svc.to_masked_dict(result.model_dump())}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


@router.post("/config/reload")
def reload_config():
    svc = get_deps_config_service()
    config = svc.reload()
    get_deps_runtime().reload_config()
    return svc.to_masked_dict(config.model_dump())


# --- Sessions ---

@router.get("/sessions")
def list_sessions(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    sm = get_deps_session_manager()
    return {"sessions": sm.list_sessions(limit=limit, offset=offset)}


@router.post("/sessions")
def create_session(body: SessionCreateRequest):
    sm = get_deps_session_manager()
    sid = sm.create_session(body.title)
    return sm.get_session_info(sid)


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    sm = get_deps_session_manager()
    info = sm.get_session_info(session_id)
    if not info:
        raise HTTPException(status_code=404, detail="Session not found")
    return info


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str):
    sm = get_deps_session_manager()
    if not sm.delete_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": True}


@router.get("/sessions/{session_id}/messages")
def get_session_messages(session_id: str):
    sm = get_deps_session_manager()
    if not sm.get_session_info(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"messages": sm.get_messages(session_id)}


@router.get("/sessions/{session_id}/trace")
def get_session_trace(session_id: str):
    sm = get_deps_session_manager()
    if not sm.get_session_info(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"runs": sm.get_session_trace(session_id)}


# --- Findings ---

@router.get("/findings")
def list_findings(asset_id: Optional[int] = None):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if asset_id:
            cursor.execute(
                "SELECT f.id, f.asset_id, f.title, f.severity, f.confidence, "
                "f.evidence_path, f.recommended_fix, f.created_at, a.name, a.value "
                "FROM findings f JOIN assets a ON f.asset_id = a.id "
                "WHERE f.asset_id = ? ORDER BY f.created_at DESC",
                (asset_id,),
            )
        else:
            cursor.execute(
                "SELECT f.id, f.asset_id, f.title, f.severity, f.confidence, "
                "f.evidence_path, f.recommended_fix, f.created_at, a.name, a.value "
                "FROM findings f JOIN assets a ON f.asset_id = a.id "
                "ORDER BY f.created_at DESC"
            )
        findings = [
            {
                "id": r[0], "asset_id": r[1], "title": r[2], "severity": r[3],
                "confidence": r[4], "evidence_path": r[5], "recommended_fix": r[6],
                "created_at": r[7], "asset_name": r[8], "asset_value": r[9],
            }
            for r in cursor.fetchall()
        ]
        return {"findings": findings}
    finally:
        conn.close()


# --- Assets ---

@router.get("/assets")
def list_assets():
    db = DatabaseManager()
    assets = db.list_assets()
    return {
        "assets": [
            {"id": a.id, "name": a.name, "type": a.type.value, "value": a.value}
            for a in assets
        ]
    }


@router.post("/assets")
def create_asset(body: AssetCreateRequest):
    db = DatabaseManager()
    asset = AssetModel(name=body.name, type=AssetType(body.type), value=body.value)
    asset_id = db.add_asset(asset)
    return {"id": asset_id, "name": body.name, "type": body.type, "value": body.value}


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int):
    db = DatabaseManager()
    if not db.remove_asset(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"deleted": True}


# --- Reports ---

@router.post("/reports")
def generate_report(body: ReportGenerateRequest):
    tool = ReportTool()
    content = tool.execute({
        "format": body.format,
        "include_evidence": body.include_evidence,
    })
    return {"format": body.format, "content": content}


# --- Tools (dynamic decoupling contract) ---

@router.get("/tools")
def list_tools():
    runtime = get_deps_runtime()
    return {"tools": runtime.list_tools(), "agents": runtime.available_agents()}
