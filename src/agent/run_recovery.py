"""
Recovery utilities for orphaned agent runs left in 'running' state.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from agent.db import get_db_connection

logger = logging.getLogger("black_glove.run_recovery")

DEFAULT_STALE_SECONDS = 900


def recover_stale_runs(max_age_seconds: int = DEFAULT_STALE_SECONDS) -> int:
    """
    Mark agent runs stuck in 'running' as interrupted.

    A run is stale when its last agent_events timestamp (or started_at if no
    events) is older than max_age_seconds.
    """
    cutoff = datetime.now() - timedelta(seconds=max_age_seconds)
    cutoff_iso = cutoff.isoformat()
    recovered = 0

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT r.id, r.session_id, r.started_at,
                   (SELECT MAX(e.ts) FROM agent_events e WHERE e.run_id = r.id) AS last_event
            FROM agent_runs r
            WHERE r.status = 'running'
            """
        )
        rows = cursor.fetchall()

        for run_id, session_id, started_at, last_event in rows:
            reference = last_event or started_at
            if not reference or reference > cutoff_iso:
                continue

            final_answer = _build_interrupted_answer(session_id, run_id)
            conn.execute(
                "UPDATE agent_runs SET status = ?, finished_at = ?, final_answer = ? "
                "WHERE id = ? AND status = 'running'",
                ("interrupted", datetime.now().isoformat(), final_answer, run_id),
            )
            if conn.total_changes:
                recovered += 1
                logger.info(
                    "Recovered stale run %s (session %s, last activity %s)",
                    run_id,
                    session_id,
                    reference,
                )

        conn.commit()
    finally:
        conn.close()

    return recovered


def _build_interrupted_answer(session_id: str, run_id: str) -> str:
    """Build a user-facing message for a recovered run, with report if possible."""
    prefix = (
        "This scan was interrupted before completion (server recovery). "
        "Partial results below:\n\n"
    )
    try:
        from agent.tools.report_tool import ReportTool

        report = ReportTool().execute({"format": "markdown"})
        if report and len(report.strip()) > 50:
            return prefix + report
    except Exception as exc:
        logger.debug("Could not generate report for interrupted run %s: %s", run_id, exc)

    return (
        f"{prefix}Run {run_id} for session {session_id} had no final answer. "
        "Check the session trace for tool outputs."
    )
