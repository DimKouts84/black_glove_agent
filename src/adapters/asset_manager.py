"""
Asset Management Adapter for Black Glove pentest agent.
Provides a safe interface for the LLM to manage assets through tool calls.
"""

import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from .interface import AdapterResult, run as base_run

def _validate_asset_data(data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate asset data before creation.
    
    Args:
        data: Asset data to validate
        
    Returns:
        Tuple of (is_valid, error_message)
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

def run_add_asset(params: Dict[str, Any]) -> AdapterResult:
    """
    Handle add-asset command.
    
    Args:
        params: Parameters including asset details
        
    Returns:
        AdapterResult with operation status
    """
    # This is a stub - actual implementation would interact with agent's API
    # For the purpose of the LLM, we just validate the request
    
    is_valid, error = _validate_asset_data(params)
    if not is_valid:
        return AdapterResult(
            success=False,
            stdout="",
            stderr=error,
            metadata={"error": error}
        )
    
    # Prepare success response
    return AdapterResult(
        success=True,
        stdout=f"Asset '{params['name']}' added successfully",
        stderr="",
        metadata={
            "asset_id": "temp-id",
            "name": params['name'],
            "type": params['type'],
            "value": params['value'],
            "created_at": datetime.now().isoformat()
        }
    )

def run_list_assets(params: Dict[str, Any]) -> AdapterResult:
    """
    Handle list-assets command.
    
    Args:
        params: Optional filter parameters
        
    Returns:
        AdapterResult with asset list
    """
    # This is a stub - actual implementation would query the database
    mock_assets = [
        {
            "id": 1,
            "name": "home-router",
            "type": "host",
            "value": "192.168.1.1",
            "created_at": "2025-12-03T10:00:00Z"
        },
        {
            "id": 2,
            "name": "personal-website",
            "type": "domain",
            "value": "example.com",
            "created_at": "2025-12-03T10:15:00Z"
        }
    ]
    
    return AdapterResult(
        success=True,
        stdout=json.dumps({"assets": mock_assets}),
        stderr="",
        metadata={"assets": mock_assets}
    )

def run_generate_report(params: Dict[str, Any]) -> AdapterResult:
    """
    Handle generate-report command.
    
    Args:
        params: Report generation parameters
        
    Returns:
        AdapterResult with report data
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
        success=True,
        stdout=json.dumps(mock_report),
        stderr="",
        metadata=mock_report
    )

def run(params: Dict[str, Any]) -> AdapterResult:
    """
    Main entry point for the asset manager adapter.
    Routes to appropriate function based on command.
    
    Args:
        params: Parameters including:
                - command: (add, list, report)
                - asset data (for add)
                - filters (for list)
                
    Returns:
        AdapterResult with operation result
    """
    command = params.get('command', 'list')
    
    # Default to list if no command specified
    if command == 'add':
        return run_add_asset(params)
    elif command == 'list':
        return run_list_assets(params)
    elif command == 'report':
        return run_generate_report(params)
    else:
        return AdapterResult(
            success=False,
            stdout="",
            stderr=f"Unknown asset command: {command}",
            metadata={"error": f"Unknown command: {command}"}
        )
