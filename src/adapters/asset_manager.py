"""
Asset Management Adapter for Black Glove pentest agent.
Provides a safe interface for the LLM to manage assets through tool calls.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from agent.db import DB_PATH, init_db

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus


class AssetManagerAdapter(BaseAdapter):
    """
    Asset Management Adapter for Black Glove pentest agent.
    Provides CRUD operations for engagement scope assets.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config or {})
        self._required_params = ["command"]
        init_db()

    def _get_db_connection(self):
        init_db()
        import sqlite3
        return sqlite3.connect(DB_PATH)

    def _validate_asset_data(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        required_fields = ["name", "type", "value"]
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"

        valid_types = ["host", "domain", "vm"]
        if data["type"] not in valid_types:
            return False, f"Invalid asset type: {data['type']}. Must be one of {valid_types}"

        if data["type"] == "host":
            if not re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", data["value"]):
                return False, "Invalid IP address format for host"
        elif data["type"] == "domain":
            if not re.match(
                r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$",
                data["value"],
            ):
                return False, "Invalid domain format"

        return True, ""

    def validate_params(self, params: Dict[str, Any]) -> bool:
        if "command" not in params:
            params["command"] = "list"
        super().validate_params(params)
        command = params.get("command", "list")
        valid_commands = {"add", "list", "remove", "delete"}
        if command not in valid_commands:
            raise ValueError(f"Unknown command: {command}. Must be one of {sorted(valid_commands)}")
        if command == "add":
            is_valid, error = self._validate_asset_data(params)
            if not is_valid:
                raise ValueError(error)
        if command in ("remove", "delete") and not params.get("name"):
            raise ValueError("Missing required parameter: name")
        return True

    def _run_add_asset(self, params: Dict[str, Any]) -> AdapterResult:
        is_valid, error = self._validate_asset_data(params)
        if not is_valid:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={"error": error},
                error_message=error,
            )

        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, type FROM assets WHERE value = ?",
                (params["value"],),
            )
            existing = cursor.fetchone()
            if existing:
                asset_id, existing_name, existing_type = existing
                conn.close()
                msg = (
                    f"Asset '{existing_name}' ({params['value']}) "
                    f"already registered (ID {asset_id})"
                )
                return AdapterResult(
                    status=AdapterResultStatus.SUCCESS,
                    data=msg,
                    metadata={
                        "asset_id": asset_id,
                        "name": existing_name,
                        "type": existing_type,
                        "value": params["value"],
                        "action": "exists",
                    },
                )

            cursor.execute(
                "INSERT INTO assets (name, type, value, created_at) VALUES (?, ?, ?, ?)",
                (params["name"], params["type"], params["value"], datetime.now().isoformat()),
            )
            asset_id = cursor.lastrowid
            conn.commit()
            conn.close()

            msg = f"Asset '{params['name']}' ({params['value']}) added successfully with ID {asset_id}"
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=msg,
                metadata={
                    "asset_id": asset_id,
                    "name": params["name"],
                    "type": params["type"],
                    "value": params["value"],
                    "action": "add",
                },
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=f"Database error: {str(e)}",
            )

    def _run_list_assets(self, params: Dict[str, Any]) -> AdapterResult:
        try:
            conn = self._get_db_connection()
            conn.row_factory = __import__("sqlite3").Row
            cursor = conn.cursor()

            query = "SELECT * FROM assets"
            args: List[Any] = []
            if params.get("type"):
                query += " WHERE type = ?"
                args.append(params["type"])

            cursor.execute(query, args)
            rows = cursor.fetchall()

            assets = [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "type": row["type"],
                    "value": row["value"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
            conn.close()

            if assets:
                asset_list = "\n".join(
                    [f"  - [{a['type']}] {a['name']}: {a['value']}" for a in assets]
                )
                output = f"Found {len(assets)} asset(s):\n{asset_list}"
            else:
                output = "No assets found in database."

            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=output,
                metadata={"assets": assets, "count": len(assets), "action": "list"},
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=f"Database error: {str(e)}",
            )

    def _run_remove_asset(self, params: Dict[str, Any]) -> AdapterResult:
        name = params.get("name")
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM assets WHERE name = ?", (name,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return AdapterResult(
                    status=AdapterResultStatus.FAILURE,
                    data=None,
                    metadata={"error": "Asset not found"},
                    error_message=f"Asset with name '{name}' not found",
                )

            asset_id = row[0]
            cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            conn.commit()
            conn.close()

            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=f"Asset '{name}' removed successfully",
                metadata={"asset_id": asset_id, "name": name, "action": "removed"},
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=f"Database error: {str(e)}",
            )

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        command = params.get("command", "list")
        if command == "add":
            return self._run_add_asset(params)
        if command == "list":
            return self._run_list_assets(params)
        if command in ("remove", "delete"):
            return self._run_remove_asset(params)
        return AdapterResult(
            status=AdapterResultStatus.FAILURE,
            data=None,
            metadata={"error": f"Unknown command: {command}"},
            error_message=f"Unknown asset command: {command}",
        )

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Asset manager failed: {result.error_message}"
        if isinstance(result.data, str):
            return result.data
        return "Asset manager completed."

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update({
            "name": "AssetManagerAdapter",
            "description": "Manage engagement scope assets (add, list, remove)",
            "capabilities": base_info.get("capabilities", []) + ["asset_crud"],
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "enum": ["add", "list", "remove"],
                        "description": "Operation to perform",
                    },
                    "name": {"type": "string", "description": "Asset name (add/remove)"},
                    "type": {
                        "type": "string",
                        "enum": ["host", "domain", "vm"],
                        "description": "Asset type (add only)",
                    },
                    "value": {"type": "string", "description": "IP or domain (add only)"},
                },
                "required": ["command"],
            },
        })
        return base_info


def create_asset_manager_adapter(config: Dict[str, Any] = None) -> AssetManagerAdapter:
    if config is None:
        config = {}
    return AssetManagerAdapter(config)
