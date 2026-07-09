"""Tests for ReportingManager SQLite thread safety."""

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.db import init_db
from agent.models import AssetModel, AssetType, DatabaseManager, SeverityLevel
from agent.reporting import Finding, ReportingManager


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "homepentest.db"
    monkeypatch.setattr("agent.db.DB_PATH", db_path)
    init_db()
    return db_path


class TestReportingManagerThreadSafety:
    def test_db_methods_from_different_thread(self, isolated_db):
        db = DatabaseManager()
        asset_id = db.add_asset(
            AssetModel(name="example.com", type=AssetType.DOMAIN, value="example.com")
        )

        manager = ReportingManager()
        result = {"error": None}

        def worker():
            try:
                manager.save_findings_to_database([
                    Finding(
                        title="Thread-safe finding",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.9,
                        asset_id=asset_id,
                        recommended_fix="Review",
                    )
                ])
                findings = manager.get_findings_from_database()
                assets = manager.get_assets_from_database()

                result["findings"] = findings
                result["assets"] = assets
            except Exception as exc:
                result["error"] = exc

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        assert result["error"] is None, f"Cross-thread DB access failed: {result['error']}"
        assert len(result["findings"]) >= 1
        assert any(f.title == "Thread-safe finding" for f in result["findings"])
        assert len(result["assets"]) >= 1
        assert any(a.name == "example.com" for a in result["assets"])
