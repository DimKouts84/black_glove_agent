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
    
    Schema:
    - id: INTEGER PRIMARY KEY AUTOINCREMENT
    - asset_id: INTEGER NOT NULL (foreign key to assets.id)
    - title: TEXT NOT NULL
    - severity: TEXT CHECK(severity IN ('low','medium','high','critical'))
    - confidence: REAL
    - evidence_path: TEXT
    - recommended_fix: TEXT
    - created_at: TEXT DEFAULT CURRENT_TIMESTAMP
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

def get_db_connection() -> sqlite3.Connection:
    """
    Get a database connection.
    
    Returns:
        sqlite3.Connection: Database connection object
    """
    return sqlite3.connect(DB_PATH)

def run_migrations() -> None:
    """
    Handle schema migrations for future updates.
    Currently a placeholder for future use.
    """
    # TODO: Implement migration system when schema changes are needed
    pass

# Example usage:
# if __name__ == "__main__":
#     init_db()
#     print(f"Database initialized at: {DB_PATH}")
