"""
Tool risk classification for policy, approval, and phase gating.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Optional, Set


class ToolRisk(str, Enum):
    SAFE = "safe"
    PASSIVE = "passive"
    ACTIVE = "active"
    CREDENTIAL = "credential"
    EXPLOIT = "exploit"
    AGENT = "agent"
    REPORT = "report"


TOOL_RISK_MAP: Dict[str, ToolRisk] = {
    "complete_task": ToolRisk.SAFE,
    "public_ip": ToolRisk.PASSIVE,
    "dns_lookup": ToolRisk.PASSIVE,
    "whois": ToolRisk.PASSIVE,
    "ssl_check": ToolRisk.PASSIVE,
    "passive_recon": ToolRisk.PASSIVE,
    "viewdns": ToolRisk.PASSIVE,
    "wappalyzer": ToolRisk.PASSIVE,
    "sublist3r": ToolRisk.PASSIVE,
    "osint_harvester": ToolRisk.PASSIVE,
    "asset_manager": ToolRisk.SAFE,
    "generate_report": ToolRisk.REPORT,
    "planner_agent": ToolRisk.AGENT,
    "researcher_agent": ToolRisk.AGENT,
    "analyst_agent": ToolRisk.AGENT,
    "nmap": ToolRisk.ACTIVE,
    "gobuster": ToolRisk.ACTIVE,
    "web_server_scanner": ToolRisk.ACTIVE,
    "dns_recon": ToolRisk.ACTIVE,
    "camera_security": ToolRisk.ACTIVE,
    "credential_tester": ToolRisk.CREDENTIAL,
    "sqli_scanner": ToolRisk.EXPLOIT,
    "web_vuln_scanner": ToolRisk.EXPLOIT,
}

PHASE_ORDER = ("passive", "active", "credential", "exploit", "analysis", "report")

PHASE_ALLOWED_RISKS: Dict[str, Set[ToolRisk]] = {
    "passive": {ToolRisk.SAFE, ToolRisk.PASSIVE, ToolRisk.AGENT, ToolRisk.REPORT},
    "active": {ToolRisk.SAFE, ToolRisk.PASSIVE, ToolRisk.ACTIVE, ToolRisk.AGENT, ToolRisk.REPORT},
    "credential": {
        ToolRisk.SAFE,
        ToolRisk.PASSIVE,
        ToolRisk.ACTIVE,
        ToolRisk.CREDENTIAL,
        ToolRisk.AGENT,
        ToolRisk.REPORT,
    },
    "exploit": set(ToolRisk),
    "analysis": {ToolRisk.SAFE, ToolRisk.AGENT, ToolRisk.REPORT},
    "report": {ToolRisk.SAFE, ToolRisk.REPORT, ToolRisk.AGENT},
}


def get_tool_risk(tool_name: str) -> ToolRisk:
    return TOOL_RISK_MAP.get(tool_name, ToolRisk.ACTIVE)


def requires_approval(tool_name: str, safe_tools: Optional[Set[str]] = None) -> bool:
    if safe_tools and tool_name in safe_tools:
        return False
    risk = get_tool_risk(tool_name)
    return risk in {
        ToolRisk.ACTIVE,
        ToolRisk.CREDENTIAL,
        ToolRisk.EXPLOIT,
        ToolRisk.AGENT,
    }


def is_exploit_tool(tool_name: str) -> bool:
    return get_tool_risk(tool_name) in {ToolRisk.EXPLOIT, ToolRisk.CREDENTIAL}


def phase_allows_tool(phase: str, tool_name: str) -> bool:
    allowed = PHASE_ALLOWED_RISKS.get(phase, set(ToolRisk))
    return get_tool_risk(tool_name) in allowed


def check_exploit_gate(
    tool_name: str,
    *,
    enable_exploit_adapters: bool,
) -> Optional[str]:
    """Return error message if tool is blocked, else None."""
    if not is_exploit_tool(tool_name):
        return None
    if not enable_exploit_adapters:
        return (
            f"Tool '{tool_name}' is blocked: enable_exploit_adapters is false."
        )
    return None
