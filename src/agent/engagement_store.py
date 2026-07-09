"""
Persistence layer for engagements and work graphs.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from agent.db import get_db_connection
from agent.work_graph import Engagement, EngagementStatus, WorkGraph, WorkPhase, WorkStep

logger = logging.getLogger("black_glove.engagement_store")


def _ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS engagements (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            targets_json TEXT NOT NULL,
            status TEXT NOT NULL,
            session_id TEXT,
            lab_mode INTEGER NOT NULL DEFAULT 0,
            budget_json TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS work_graphs (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            session_id TEXT,
            run_id TEXT,
            goal TEXT NOT NULL,
            status TEXT NOT NULL,
            current_phase TEXT NOT NULL,
            steps_json TEXT NOT NULL,
            completed_step_ids_json TEXT,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(engagement_id) REFERENCES engagements(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS run_step_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            run_id TEXT,
            tool_name TEXT NOT NULL,
            target TEXT,
            status TEXT,
            summary TEXT,
            evidence_paths_json TEXT,
            finding_ids_json TEXT,
            ts TEXT NOT NULL
        )
        """
    )


class EngagementStore:
    """SQLite-backed engagement and work-graph store."""

    def __init__(self, conn=None):
        self._conn = conn

    def _connection(self):
        if self._conn is not None:
            return self._conn
        conn = get_db_connection()
        _ensure_tables(conn)
        return conn

    def save_engagement(self, engagement: Engagement) -> Engagement:
        conn = self._connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO engagements
            (id, name, targets_json, status, session_id, lab_mode, budget_json,
             metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                engagement.name,
                json.dumps(engagement.targets),
                engagement.status.value,
                engagement.session_id,
                1 if engagement.lab_mode else 0,
                json.dumps(engagement.budget),
                json.dumps(engagement.metadata),
                engagement.created_at,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
        return engagement

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        conn = self._connection()
        row = conn.execute(
            "SELECT id, name, targets_json, status, session_id, lab_mode, "
            "budget_json, metadata_json, created_at, updated_at "
            "FROM engagements WHERE id = ?",
            (engagement_id,),
        ).fetchone()
        if not row:
            return None
        return Engagement(
            id=row[0],
            name=row[1],
            targets=json.loads(row[2]),
            status=EngagementStatus(row[3]),
            session_id=row[4],
            lab_mode=bool(row[5]),
            budget=json.loads(row[6] or "{}"),
            metadata=json.loads(row[7] or "{}"),
            created_at=row[8],
            updated_at=row[9],
        )

    def save_work_graph(self, graph: WorkGraph) -> WorkGraph:
        conn = self._connection()
        graph.updated_at = datetime.now().isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO work_graphs
            (id, engagement_id, session_id, run_id, goal, status, current_phase,
             steps_json, completed_step_ids_json, revision, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                graph.id,
                graph.engagement_id,
                graph.session_id,
                graph.run_id,
                graph.goal,
                graph.status.value,
                graph.current_phase.value,
                json.dumps([s.model_dump() for s in graph.steps]),
                json.dumps(graph.completed_step_ids),
                graph.revision,
                graph.created_at,
                graph.updated_at,
            ),
        )
        conn.commit()
        return graph

    def get_work_graph(self, graph_id: str) -> Optional[WorkGraph]:
        conn = self._connection()
        row = conn.execute(
            "SELECT id, engagement_id, session_id, run_id, goal, status, "
            "current_phase, steps_json, completed_step_ids_json, revision, "
            "created_at, updated_at FROM work_graphs WHERE id = ?",
            (graph_id,),
        ).fetchone()
        if not row:
            return None
        steps = [WorkStep(**s) for s in json.loads(row[7])]
        return WorkGraph(
            id=row[0],
            engagement_id=row[1],
            session_id=row[2],
            run_id=row[3],
            goal=row[4],
            status=EngagementStatus(row[5]),
            current_phase=WorkPhase(row[6]),
            steps=steps,
            completed_step_ids=json.loads(row[8] or "[]"),
            revision=row[9],
            created_at=row[10],
            updated_at=row[11],
        )

    def save_step_summary(
        self,
        *,
        session_id: str,
        run_id: Optional[str],
        tool_name: str,
        target: str,
        status: str,
        summary: str,
        evidence_paths: Optional[List[str]] = None,
        finding_ids: Optional[List[int]] = None,
    ) -> None:
        conn = self._connection()
        conn.execute(
            """
            INSERT INTO run_step_summaries
            (session_id, run_id, tool_name, target, status, summary,
             evidence_paths_json, finding_ids_json, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                run_id,
                tool_name,
                target,
                status,
                summary,
                json.dumps(evidence_paths or []),
                json.dumps(finding_ids or []),
                datetime.now().isoformat(),
            ),
        )
        conn.commit()

    def load_step_summaries(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        conn = self._connection()
        rows = conn.execute(
            "SELECT tool_name, target, status, summary, evidence_paths_json, "
            "finding_ids_json, ts FROM run_step_summaries "
            "WHERE session_id = ? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        summaries = []
        for row in reversed(rows):
            summaries.append(
                {
                    "tool_name": row[0],
                    "target": row[1],
                    "status": row[2],
                    "summary": row[3],
                    "evidence_paths": json.loads(row[4] or "[]"),
                    "finding_ids": json.loads(row[5] or "[]"),
                    "ts": row[6],
                }
            )
        return summaries

    def format_summaries_for_context(self, session_id: str) -> str:
        summaries = self.load_step_summaries(session_id)
        if not summaries:
            return ""
        lines = ["RECENT EXECUTION HISTORY:"]
        for item in summaries:
            lines.append(
                f"- [{item['ts']}] {item['tool_name']} on {item['target']}: "
                f"{item['status']} — {item['summary'][:200]}"
            )
        return "\n".join(lines)
