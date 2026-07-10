"""
Append-only audit trail for governed pentest operations.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, Optional

from agent.db import get_db_connection

logger = logging.getLogger("black_glove.audit")

_MAX_RETRIES = 5
_RETRY_DELAY = 0.05


class AuditWriter:
    """Persist immutable audit events with retry on lock contention."""

    def __init__(self, actor: str = "black_glove"):
        self.actor = actor

    def write(
        self,
        event_type: str,
        data: Dict[str, Any],
        *,
        actor: Optional[str] = None,
        conn=None,
    ) -> None:
        payload = json.dumps(data, default=str)
        ts = datetime.now().isoformat()
        own_conn = conn is None
        if own_conn:
            conn = get_db_connection()
        try:
            for attempt in range(_MAX_RETRIES):
                try:
                    conn.execute(
                        "INSERT INTO audit_log (ts, actor, event_type, data) VALUES (?, ?, ?, ?)",
                        (ts, actor or self.actor, event_type, payload),
                    )
                    conn.commit()
                    return
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == _MAX_RETRIES - 1:
                        raise
                    time.sleep(_RETRY_DELAY * (attempt + 1))
        except Exception as exc:
            logger.error("Failed to write audit event %s: %s", event_type, exc)
        finally:
            if own_conn:
                conn.close()


_default_writer: Optional[AuditWriter] = None


def get_audit_writer(actor: str = "black_glove") -> AuditWriter:
    global _default_writer
    if _default_writer is None:
        _default_writer = AuditWriter(actor=actor)
    return _default_writer


def write_audit(
    event_type: str,
    data: Dict[str, Any],
    *,
    actor: str = "black_glove",
    conn=None,
) -> None:
    get_audit_writer(actor).write(event_type, data, actor=actor, conn=conn)
