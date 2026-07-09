import sqlite3
import pytest
from pathlib import Path

from src.adapters.asset_manager import AssetManagerAdapter, create_asset_manager_adapter
from src.adapters.interface import AdapterResultStatus


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = tmp_path / "homepentest.db"
    monkeypatch.setattr("src.adapters.asset_manager.DB_PATH", path)
    monkeypatch.setattr("src.adapters.asset_manager.init_db", lambda: _init_db(path))
    return path


def _init_db(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, name TEXT, type TEXT, value TEXT, created_at TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, title TEXT, severity TEXT, "
        "confidence REAL, evidence_path TEXT, recommended_fix TEXT, created_at TEXT, asset_id INTEGER)"
    )
    conn.commit()
    conn.close()


class TestAssetManagerAdapter:
    def test_add_and_list(self, db_path):
        adapter = create_asset_manager_adapter()
        add = adapter.execute({
            "command": "add",
            "name": "web",
            "type": "domain",
            "value": "example.com",
        })
        assert add.status == AdapterResultStatus.SUCCESS
        listed = adapter.execute({"command": "list"})
        assert "example.com" in listed.data

    def test_add_duplicate_fails(self, db_path):
        adapter = create_asset_manager_adapter()
        params = {"command": "add", "name": "a", "type": "domain", "value": "dup.com"}
        adapter.execute(params)
        dup = adapter.execute({"command": "add", "name": "b", "type": "domain", "value": "dup.com"})
        assert dup.status == AdapterResultStatus.FAILURE

    def test_remove_missing_fails(self, db_path):
        adapter = create_asset_manager_adapter()
        result = adapter.execute({"command": "remove", "name": "missing"})
        assert result.status == AdapterResultStatus.FAILURE

    def test_validate_rejects_unknown_command(self):
        adapter = create_asset_manager_adapter()
        with pytest.raises(ValueError, match="Unknown command"):
            adapter.validate_params({"command": "report"})

    def test_validate_rejects_invalid_type(self):
        adapter = create_asset_manager_adapter()
        with pytest.raises(ValueError, match="Invalid asset type"):
            adapter.validate_params({
                "command": "add",
                "name": "x",
                "type": "webapp",
                "value": "example.com",
            })

    def test_interpret_result(self, db_path):
        adapter = create_asset_manager_adapter()
        result = adapter.execute({"command": "list"})
        text = adapter.interpret_result(result)
        assert "asset" in text.lower()
