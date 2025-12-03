"""
Natural language command handlers for ChatHandler.

This module contains handler methods for processing natural language commands.
"""

import sqlite3
import json
from typing import Dict, Any, List
from .command_parser import CommandIntent, ParsedCommand


def handle_add_asset(db_conn: sqlite3.Connection, parsed: ParsedCommand) -> str:
    """
    Handle add_asset command.
    
    Args:
        db_conn: Database connection
        parsed: Parsed command with parameters
        
    Returns:
        Result message
    """
    try:
        params = parsed.parameters
        cursor = db_conn.cursor()
        cursor.execute(
            "INSERT INTO assets (name, type, value) VALUES (?, ?, ?)",
            (params["name"], params["type"], params["value"])
        )
        db_conn.commit()
        asset_id = cursor.lastrowid
        
        return f"✅ Added asset '{params['name']}' ({params['type']}: {params['value']}) with ID {asset_id}"
    except Exception as e:
        return f"❌ Failed to add asset: {e}"


def handle_list_assets(db_conn: sqlite3.Connection) -> str:
    """
    Handle list_assets command.
    
    Args:
        db_conn: Database connection
        
    Returns:
        Formatted asset list
    """
    try:
        cursor = db_conn.cursor()
        cursor.execute("SELECT id, name, type, value, created_at FROM assets ORDER BY id")
        assets = cursor.fetchall()
        
        if not assets:
            return "📋 No assets found."
        
        result = f"📋 **Assets ({len(assets)} found)**:\n\n"
        for asset_id, name, asset_type, value, created_at in assets:
            result += f"- **{name}** (ID: {asset_id}) - {asset_type}: {value}\n"
        
        return result
    except Exception as e:
        return f"❌ Failed to list assets: {e}"


def handle_remove_asset(db_conn: sqlite3.Connection, parsed: ParsedCommand) -> str:
    """
    Handle remove_asset command.
    
    Args:
        db_conn: Database connection
        parsed: Parsed command with parameters
        
    Returns:
        Result message
    """
    try:
        # Find asset by name or ID
        name = parsed.parameters.get("name")
        cursor = db_conn.cursor()
        
        # Try to find by name first
        cursor.execute("SELECT id, name FROM assets WHERE name = ?", (name,))
        asset = cursor.fetchone()
        
        if not asset:
            return f"❌ Asset '{name}' not found."
        
        asset_id, asset_name = asset
        cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        db_conn.commit()
        
        return f"✅ Removed asset '{asset_name}' (ID: {asset_id})"
    except Exception as e:
        return f"❌ Failed to remove asset: {e}"


def handle_run_tool(plugin_manager, db_conn: sqlite3.Connection, parsed: ParsedCommand, console) -> str:
    """
    Handle run_tool command.
    
    Args:
        plugin_manager: Plugin manager for tool execution
        db_conn: Database connection
        parsed: Parsed command with parameters
        console: Rich console for output
        
    Returns:
        Result message
    """
    try:
        tool = parsed.parameters["tool"]
        target = parsed.parameters["target"]
        
        # Check if tool is available
        available_adapters = plugin_manager.discover_adapters()
        if tool not in available_adapters:
            return f"❌ Tool '{tool}' not found. Available tools: {', '.join(available_adapters)}"
        
        # Execute tool
        console.print(f"🔧 Running {tool} on {target}...")
        result = plugin_manager.execute_adapter(tool, {"target": target})
        
        if result.status == AdapterResultStatus.SUCCESS:
            # Format output
            output = f"✅ **{tool}** completed successfully\n\n"
            if result.data:
                output += f"```\n{json.dumps(result.data, indent=2)}\n```"
            return output
        else:
            return f"❌ **{tool}** failed: {result.error or 'Unknown error'}"
            
    except Exception as e:
        return f"❌ Failed to run tool: {e}"


def handle_generate_report(db_conn: sqlite3.Connection, parsed: ParsedCommand) -> str:
    """
    Handle generate_report command.
    
    Args:
        db_conn: Database connection
        parsed: Parsed command with parameters
        
    Returns:
        Report text
    """
    try:
        target = parsed.parameters.get("target")
        cursor = db_conn.cursor()
        
        # Find asset
        cursor.execute("SELECT id, name, type, value FROM assets WHERE name = ? OR value = ?", (target, target))
        asset = cursor.fetchone()
        
        if not asset:
            return f"❌ Asset '{target}' not found."
        
        asset_id, name, asset_type, value = asset
        
        # Get findings for this asset
        cursor.execute("""
            SELECT title, severity, confidence, evidence_path, recommended_fix, created_at
            FROM findings
            WHERE asset_id = ?
            ORDER BY 
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                created_at DESC
        """, (asset_id,))
        findings = cursor.fetchall()
        
        # Generate report
        report = f"# Security Report: {name}\n\n"
        report += f"**Target**: {asset_type.upper()} - {value}\\n"
        report += f"**Generated**: {findings[0][5] if findings else 'N/A'}\\n\\n"
        
        if findings:
            report += f"## Findings ({len(findings)})\\n\\n"
            for title, severity, confidence, evidence, fix, created in findings:
                report += f"### {title}\\n"
                report += f"- **Severity**: {severity.upper()}\\n"
                report += f"- **Confidence**: {confidence * 100:.0f}%\\n"
                if evidence:
                    report += f"- **Evidence**: `{evidence}`\\n"
                if fix:
                    report += f"- **Recommended Fix**: {fix}\\n"
                report += "\\n"
        else:
            report += "## Findings\\n\\nNo findings recorded for this asset.\\n"
        
        return report
        
    except Exception as e:
        return f"❌ Failed to generate report: {e}"
