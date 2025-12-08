"""
Asset Management Adapter for Black Glove pentest agent.
Provides a safe interface for the LLM to manage assets through tool calls.
"""

import json
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import re

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus

# Database path - stored in user's home directory
DB_PATH = Path.home() / ".homepentest" / "homepentest.db"

class AssetManagerAdapter(BaseAdapter):
    """
    Asset Management Adapter for Black Glove pentest agent.
    Provides a safe interface for the LLM to manage assets through tool calls.
    """

    def _get_db_connection(self):
        """Get connection to the database."""
        if not DB_PATH.exists():
            # Ensure directory exists
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(DB_PATH)

    def _validate_asset_data(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate asset data before creation.
        """
        # Required fields
        required_fields = ['name', 'type', 'value']
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
        
        # Validate asset type
        valid_types = ['host', 'domain', 'vm']
        if data['type'] not in valid_types:
            return False, f"Invalid asset type: {data['type']}. Must be one of {valid_types}"
        
        # Validate value based on type
        if data['type'] == 'host':
            # Basic IP validation (simplified)
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', data['value']):
                return False, "Invalid IP address format for host"
        elif data['type'] == 'domain':
            # Basic domain validation
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', data['value']):
                return False, "Invalid domain format"
        
        return True, ""

    def run_add_asset(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Handle add-asset command.
        """
        is_valid, error = self._validate_asset_data(params)
        if not is_valid:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={"error": error},
                error_message=error
            )
        
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            # Check if asset already exists
            cursor.execute("SELECT id FROM assets WHERE value = ?", (params['value'],))
            if cursor.fetchone():
                conn.close()
                return AdapterResult(
                    status=AdapterResultStatus.FAILURE,
                    data=None,
                    metadata={"error": "Duplicate asset"},
                    error_message=f"Asset with value {params['value']} already exists"
                )
                
            # Insert new asset
            cursor.execute(
                "INSERT INTO assets (name, type, value, created_at) VALUES (?, ?, ?, ?)",
                (params['name'], params['type'], params['value'], datetime.now().isoformat())
            )
            asset_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=f"Asset '{params['name']}' ({params['value']}) added successfully with ID {asset_id}",
                metadata={
                    "asset_id": asset_id,
                    "name": params['name'],
                    "type": params['type'],
                    "value": params['value'],
                    "created_at": datetime.now().isoformat()
                }
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=f"Database error: {str(e)}"
            )

    def run_list_assets(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Handle list-assets command.
        """
        try:
            conn = self._get_db_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM assets"
            args = []
            
            # Apply filters if present
            if params.get('type'):
                query += " WHERE type = ?"
                args.append(params['type'])
                
            cursor.execute(query, args)
            rows = cursor.fetchall()
            
            assets = []
            for row in rows:
                assets.append({
                    "id": row['id'],
                    "name": row['name'],
                    "type": row['type'],
                    "value": row['value'],
                    "created_at": row['created_at']
                })
                
            conn.close()
            
            # Format as readable string for LLM
            if assets:
                asset_list = "\n".join([f"  - [{a['type']}] {a['name']}: {a['value']}" for a in assets])
                output = f"Found {len(assets)} asset(s):\n{asset_list}"
            else:
                output = "No assets found in database."
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=output,
                metadata={"assets": assets, "count": len(assets)}
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=f"Database error: {str(e)}"
            )

    def run_remove_asset(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Handle remove-asset command.
        """
        name = params.get('name')
        if not name:
             return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={"error": "Missing name"},
                error_message="Missing required parameter: name"
            )

        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            # Check if asset exists
            cursor.execute("SELECT id FROM assets WHERE name = ?", (name,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return AdapterResult(
                    status=AdapterResultStatus.FAILURE,
                    data=None,
                    metadata={"error": "Asset not found"},
                    error_message=f"Asset with name '{name}' not found"
                )
            
            asset_id = row[0]
            
            # Delete asset
            cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            conn.commit()
            conn.close()
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=f"Asset '{name}' removed successfully",
                metadata={"asset_id": asset_id, "name": name, "action": "removed"}
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=f"Database error: {str(e)}"
            )

    def run_generate_report(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Handle generate-report command.
        """
        # This is a stub - actual implementation would generate a report
        mock_report = {
            "summary": "Security scan report for asset",
            "findings": [
                {
                    "title": "Open Ports",
                    "severity": "medium",
                    "description": "Several ports detected open on the target",
                    "recommendation": "Review firewall rules and close unnecessary ports"
                }
            ],
            "timestamp": datetime.now().isoformat()
        }
        
        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data=json.dumps(mock_report, indent=2),
            metadata=mock_report
        )

    def execute(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Main entry point for the asset manager adapter.
        Routes to appropriate function based on command.
        """
        command = params.get('command', 'list')
        
        # Default to list if no command specified
        if command == 'add':
            return self.run_add_asset(params)
        elif command == 'list':
            return self.run_list_assets(params)
        elif command == 'report':
            return self.run_generate_report(params)
        elif command == 'remove' or command == 'delete':
            return self.run_remove_asset(params)
        else:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={"error": f"Unknown command: {command}"},
                error_message=f"Unknown asset command: {command}"
            )

    def get_info(self) -> Dict[str, Any]:
        """Return adapter information."""
        return {
            "name": "asset_manager",
            "description": "Helper for managing target assets (add, list, report, remove)",
            "usage": {
                "command": "add | list | report | remove",
                "name": "asset name (for add/remove)",
                "type": "host | domain | vm (for add)",
                "value": "IP or domain (for add)"
            }
        }

    def validate_params(self, params: Dict[str, Any]) -> None:
        """Validate execution parameters."""
        pass # Optional specific validation

