import sqlite3
from unittest.mock import MagicMock

from src.agent.command_handlers import handle_generate_report
from src.agent.command_parser import ParsedCommand, CommandIntent


def test_handle_generate_report_uses_real_newlines(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE assets (id INTEGER PRIMARY KEY, name TEXT, type TEXT, value TEXT, created_at TEXT)"
    )
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, title TEXT, severity TEXT, "
        "confidence REAL, evidence_path TEXT, recommended_fix TEXT, created_at TEXT, asset_id INTEGER)"
    )
    conn.execute(
        "INSERT INTO assets (id, name, type, value, created_at) VALUES (1, 'target', 'domain', 'example.com', 'now')"
    )
    conn.execute(
        "INSERT INTO findings (title, severity, confidence, evidence_path, recommended_fix, created_at, asset_id) "
        "VALUES ('Test', 'high', 0.9, '/ev.txt', 'fix it', 'now', 1)"
    )
    conn.commit()

    parsed = ParsedCommand(
        intent=CommandIntent.GENERATE_REPORT,
        parameters={"target": "target"},
        raw_input="generate_report target",
    )
    report = handle_generate_report(conn, parsed)
    assert "\\n" not in report
    assert "## Findings" in report
    assert "### Test" in report
