"""
Database initialization module for Black Glove pentest agent.
Creates and manages the SQLite database with assets, findings, and audit_log tables.
"""
import sqlite3
import os
from pathlib import Path
from typing import Optional

# Database path - stored in user's home directory
DB_PATH = Path.home() / ".homepentest" / "homepentest.db"

def init_db() -> None:
    """
    Initialize the SQLite database with required tables.
    Creates the database file and directory structure if they don't exist.
    """
    # Create the directory structure if it doesn't exist
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # Connect to database (creates file if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)
    
    try:
        with conn:
            # Create assets table
            create_assets_table(conn)
            # Create findings table
            create_findings_table(conn)
            # Create audit_log table
            create_audit_log_table(conn)
            # Create sessions table
            create_sessions_table(conn)
            # Create chat_messages table
            create_chat_messages_table(conn)
            # Create agent orchestration trace tables
            create_agent_runs_table(conn)
            create_agent_events_table(conn)
            create_engagement_tables(conn)
            _migrate_findings_columns(conn)
            _migrate_agent_events_columns(conn)
            _create_worker_tables(conn)
            create_finding_observations_table(conn)
            _supersede_stale_scan_completed_findings(conn)
            _merge_duplicate_header_findings(conn)
    finally:
        conn.close()

def create_assets_table(conn: sqlite3.Connection) -> None:
    """
    Create the assets table with schema from section 10 of requirements.
    
    Schema:
    - id: INTEGER PRIMARY KEY AUTOINCREMENT
    - name: TEXT NOT NULL
    - type: TEXT CHECK(type IN ('host','domain','vm')) NOT NULL
    - value: TEXT NOT NULL
    - created_at: TEXT DEFAULT CURRENT_TIMESTAMP
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT CHECK(type IN ('host','domain','vm')) NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

def create_findings_table(conn: sqlite3.Connection) -> None:
    """
    Create the findings table with schema from section 10 of requirements.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('low','medium','high','critical')),
            confidence REAL,
            evidence_path TEXT,
            recommended_fix TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(asset_id) REFERENCES assets(id)
        )
    """)
    _migrate_findings_columns(conn)


def _migrate_findings_columns(conn: sqlite3.Connection) -> None:
    """Add extended finding columns for provenance and deduplication."""
    cursor = conn.execute("PRAGMA table_info(findings)")
    existing = {row[1] for row in cursor.fetchall()}
    migrations = {
        "description": "TEXT DEFAULT ''",
        "evidence_hash": "TEXT",
        "source_tool": "TEXT",
        "verification_state": "TEXT DEFAULT 'indicator'",
        "fingerprint": "TEXT",
        "observation_count": "INTEGER DEFAULT 1",
        "run_id": "TEXT",
        "step_id": "TEXT",
    }
    for column, definition in migrations.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)"
    )


def create_finding_observations_table(conn: sqlite3.Connection) -> None:
    """Append-only ledger linking canonical findings to run/step observations."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            run_id TEXT,
            step_id TEXT,
            evidence_path TEXT,
            evidence_hash TEXT,
            description TEXT,
            observed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_observations_run_id "
        "ON finding_observations(run_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_observations_finding_id "
        "ON finding_observations(finding_id)"
    )
    _backfill_finding_observations(conn)


def _backfill_finding_observations(conn: sqlite3.Connection) -> None:
    """Copy legacy run_id-tagged findings into the observation ledger (idempotent)."""
    conn.execute(
        """
        INSERT INTO finding_observations
            (finding_id, run_id, step_id, evidence_path, evidence_hash, description, observed_at)
        SELECT f.id, f.run_id, f.step_id, f.evidence_path, f.evidence_hash,
               f.description, COALESCE(f.created_at, CURRENT_TIMESTAMP)
        FROM findings f
        WHERE f.run_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM finding_observations o
              WHERE o.finding_id = f.id AND o.run_id = f.run_id
          )
        """
    )


def _supersede_stale_scan_completed_findings(conn: sqlite3.Connection) -> None:
    """Mark pre-fix generic scan-completed rows as superseded (idempotent)."""
    conn.execute(
        """
        UPDATE findings
        SET verification_state = 'superseded'
        WHERE verification_state NOT IN ('superseded', 'conflicted')
          AND title LIKE '%scan completed%'
          AND source_tool IN (
              'web_vuln_scanner', 'sqli_scanner', 'sublist3r',
              'wappalyzer', 'passive_recon', 'osint_harvester'
          )
        """
    )


def _merge_duplicate_header_findings(conn: sqlite3.Connection) -> None:
    """Merge duplicate web_server_scanner header rows; stabilize fingerprints (idempotent)."""
    import hashlib

    cursor = conn.execute(
        """
        SELECT asset_id, title, GROUP_CONCAT(id) AS ids
        FROM findings
        WHERE source_tool = 'web_server_scanner'
          AND (title LIKE 'Missing %' OR title LIKE 'Present %')
        GROUP BY asset_id, title
        HAVING COUNT(*) > 1
        """
    )
    for asset_id, title, ids_str in cursor.fetchall():
        ids = sorted(int(x) for x in ids_str.split(","))
        keep_id, dup_ids = ids[0], ids[1:]
        for dup_id in dup_ids:
            conn.execute(
                "UPDATE finding_observations SET finding_id = ? WHERE finding_id = ?",
                (keep_id, dup_id),
            )
            conn.execute("DELETE FROM findings WHERE id = ?", (dup_id,))

    for row in conn.execute(
        """
        SELECT id, asset_id, source_tool, title
        FROM findings
        WHERE source_tool = 'web_server_scanner'
          AND (title LIKE 'Missing %' OR title LIKE 'Present %')
        """
    ):
        finding_id, asset_id, source_tool, finding_title = row
        raw = f"{asset_id}|{source_tool}|{finding_title.strip().lower()}"
        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        try:
            conn.execute(
                "UPDATE findings SET fingerprint = ? WHERE id = ?",
                (fingerprint, finding_id),
            )
        except sqlite3.IntegrityError:
            existing = conn.execute(
                """
                SELECT id FROM findings
                WHERE fingerprint = ? AND id != ?
                """,
                (fingerprint, finding_id),
            ).fetchone()
            if existing:
                canonical_id = existing[0]
                conn.execute(
                    "UPDATE finding_observations SET finding_id = ? WHERE finding_id = ?",
                    (canonical_id, finding_id),
                )
                conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))


def create_engagement_tables(conn: sqlite3.Connection) -> None:
    """Create engagement and work-graph persistence tables."""
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
            strict_sequential INTEGER NOT NULL DEFAULT 0,
            failure_policy TEXT NOT NULL DEFAULT 'block_downstream',
            concurrency_limits_json TEXT,
            cancelled INTEGER NOT NULL DEFAULT 0,
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
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_work_graphs_engagement ON work_graphs(engagement_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_work_graphs_status ON work_graphs(status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_run_step_summaries_session ON run_step_summaries(session_id)"
    )
    _create_worker_tables(conn)


def _create_worker_tables(conn: sqlite3.Connection) -> None:
    """Worker task persistence for parallel orchestration."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS worker_tasks (
            task_id TEXT PRIMARY KEY,
            graph_id TEXT NOT NULL,
            step_id TEXT NOT NULL,
            engagement_id TEXT NOT NULL,
            run_id TEXT,
            kind TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            target TEXT,
            status TEXT NOT NULL,
            attempt INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS worker_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            worker_instance_id TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            FOREIGN KEY(task_id) REFERENCES worker_tasks(task_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS worker_results (
            task_id TEXT PRIMARY KEY,
            step_id TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT,
            evidence_paths_json TEXT,
            finding_ids_json TEXT,
            structured_json TEXT,
            finished_at TEXT NOT NULL,
            FOREIGN KEY(task_id) REFERENCES worker_tasks(task_id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_worker_tasks_graph ON worker_tasks(graph_id)"
    )

def create_audit_log_table(conn: sqlite3.Connection) -> None:
    """
    Create the audit_log table with schema from section 10 of requirements.
    
    Schema:
    - id: INTEGER PRIMARY KEY AUTOINCREMENT
    - ts: TEXT DEFAULT CURRENT_TIMESTAMP
    - actor: TEXT
    - event_type: TEXT
    - data: JSON (stored as TEXT in SQLite)
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT CURRENT_TIMESTAMP,
            actor TEXT,
            event_type TEXT,
            data TEXT  -- JSON data stored as TEXT
        )
    """)

def create_sessions_table(conn: sqlite3.Connection) -> None:
    """
    Create the sessions table for chat history persistence.
    
    Schema:
    - id: TEXT PRIMARY KEY (UUID)
    - title: TEXT
    - created_at: TEXT DEFAULT CURRENT_TIMESTAMP
    - last_active: TEXT DEFAULT CURRENT_TIMESTAMP
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            title TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_active TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

def create_chat_messages_table(conn: sqlite3.Connection) -> None:
    """
    Create the chat_messages table for storing conversation history.
    
    Schema:
    - id: INTEGER PRIMARY KEY AUTOINCREMENT
    - session_id: TEXT (foreign key to sessions.id)
    - role: TEXT (user, assistant, system)
    - content: TEXT NOT NULL
    - timestamp: TEXT DEFAULT CURRENT_TIMESTAMP
    - llm_response_metadata: TEXT (JSON)
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            llm_response_metadata TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        )
    """)


def create_agent_runs_table(conn: sqlite3.Connection) -> None:
    """Create agent_runs table for orchestration trace."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_runs (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            query TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            started_at TEXT NOT NULL,
            finished_at TEXT,
            final_answer TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
        )
    """)


def create_agent_events_table(conn: sqlite3.Connection) -> None:
    """Create agent_events table for per-run activity trace."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            agent TEXT NOT NULL,
            type TEXT NOT NULL,
            content TEXT,
            params_json TEXT,
            details_json TEXT,
            ts TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES agent_runs(id)
        )
    """)
    _migrate_agent_events_columns(conn)


def _migrate_agent_events_columns(conn: sqlite3.Connection) -> None:
    cursor = conn.execute("PRAGMA table_info(agent_events)")
    existing = {row[1] for row in cursor.fetchall()}
    if "details_json" not in existing:
        conn.execute("ALTER TABLE agent_events ADD COLUMN details_json TEXT")

def get_db_connection() -> sqlite3.Connection:
    """
    Get a database connection with WAL mode and busy timeout.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def remove_asset(conn: sqlite3.Connection, asset_id: int) -> bool:
    """
    Remove an asset from the database by ID.
    
    Args:
        conn: Database connection
        asset_id: ID of the asset to remove
        
    Returns:
        bool: True if asset was removed, False if not found
    """
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    rows_affected = cursor.rowcount
    conn.commit()
    return rows_affected > 0

def archive_asset(conn: sqlite3.Connection, asset_id: int) -> bool:
    """
    Archive an asset instead of deleting it (soft delete).
    This function would require adding an 'archived' column to the assets table.
    
    Args:
        conn: Database connection
        asset_id: ID of the asset to archive
        
    Returns:
        bool: True if asset was archived, False if not found
    """
    cursor = conn.cursor()
    cursor.execute("UPDATE assets SET archived = 1 WHERE id = ?", (asset_id,))
    rows_affected = cursor.rowcount
    conn.commit()
    return rows_affected > 0

def run_migrations() -> None:
    """
    Handle schema migrations for future updates.
    Creates any missing tables idempotently.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            create_assets_table(conn)
            create_findings_table(conn)
            create_audit_log_table(conn)
            create_sessions_table(conn)
            create_chat_messages_table(conn)
            create_agent_runs_table(conn)
            create_agent_events_table(conn)
            create_engagement_tables(conn)
            _migrate_findings_columns(conn)
            _migrate_agent_events_columns(conn)
            _create_worker_tables(conn)
            create_finding_observations_table(conn)
            _supersede_stale_scan_completed_findings(conn)
            _merge_duplicate_header_findings(conn)
    finally:
        conn.close()

# Example usage:
# if __name__ == "__main__":
#     init_db()
#     print(f"Database initialized at: {DB_PATH}")
