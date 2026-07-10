"""Inspect agent_events for LLM vs tool failure patterns."""
import sqlite3
from pathlib import Path

DB_PATH = Path.home() / ".homepentest" / "homepentest.db"


def main() -> None:
    if not DB_PATH.exists():
        print(f"No database at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(
            """
            SELECT run_id, agent, type, substr(content, 1, 200) AS content
            FROM agent_events
            WHERE content LIKE '%Unsupported%'
               OR content LIKE '%response format%'
            ORDER BY ts DESC
            LIMIT 15
            """
        ).fetchall()
        print(f"Events matching 'Unsupported' / 'response format': {len(rows)}")
        for row in rows:
            print(row)

        failed = conn.execute(
            """
            SELECT id, status, substr(final_answer, 1, 300) AS answer
            FROM agent_runs
            WHERE status = 'failed'
            ORDER BY started_at DESC
            LIMIT 5
            """
        ).fetchall()
        print(f"\nFailed runs: {len(failed)}")
        for row in failed:
            print(row)

        tool_events = conn.execute(
            """
            SELECT run_id, type, substr(content, 1, 120) AS content
            FROM agent_events
            WHERE type IN ('tool_result', 'tool_call', 'llm_error')
            ORDER BY ts DESC
            LIMIT 20
            """
        ).fetchall()
        print(f"\nRecent tool/llm events: {len(tool_events)}")
        for row in tool_events:
            print(row)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
