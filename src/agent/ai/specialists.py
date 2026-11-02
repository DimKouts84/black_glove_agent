"""Domain specialists. Each one owns a slice of the existing scanners."""

from __future__ import annotations

from pydantic_ai import Agent, DeferredToolRequests, ModelSettings
from pydantic_ai.models import Model

from agent.ai.deps import TurnDeps
from agent.ai.tool_bridge import build_scanner_toolset
from agent.tools.registry import ToolRegistry

RECON_TOOLS = [
    "public_ip",
    "dns_lookup",
    "whois",
    "passive_recon",
    "viewdns",
    "sublist3r",
    "osint_harvester",
    "dns_recon",
    "ssl_check",
    "asset_manager",
]

NETWORK_TOOLS = ["nmap", "camera_security"]

WEB_TOOLS = [
    "gobuster",
    "wappalyzer",
    "web_server_scanner",
    "sqli_scanner",
    "web_vuln_scanner",
]

ASSESSMENT_TOOLS = ["credential_tester", "generate_report"]

SPECIALIST_TOOLS = {
    "recon_agent": RECON_TOOLS,
    "network_agent": NETWORK_TOOLS,
    "web_agent": WEB_TOOLS,
    "assessment_agent": ASSESSMENT_TOOLS,
}

RECON_INSTRUCTIONS = """You are the recon specialist for Black Glove.
You gather public information. You do not run port scans, web vulnerability scanners, or credential tests.

Tools you can call: public_ip, dns_lookup, whois, passive_recon, viewdns, sublist3r, osint_harvester, dns_recon, ssl_check, asset_manager.

How to read results:
- Treat the INTERPRETATION field as the primary summary. Corroborate it with evidence. Do not raise severity past what the tool reported.
- passive_recon: report potential_secrets with their severity and confidence. URL-pattern hits are indicators, not verified leaks.
- dns_recon: a successful zone transfer is critical, and it still needs manual verification.
- ssl_check: certificate metadata only. Do not claim a trust chain was validated.
- sublist3r: keep subdomains that belong to the parent zone.
- asset_manager types are only host, domain, and vm. Use domain for a website. Commands are add, list, and remove.

Local network:
- "Local network" does not mean the public address from public_ip.
- There is no LAN-discovery tool. If the task asks to scan a local network, say that the scope is ambiguous and ask whether the user means their public IP, a specific subnet, or a single host. Do not invent a gateway from public_ip.

If a tool returns an error, report it and continue with the other recon tools that still apply. Answer with a short factual summary.
"""

NETWORK_INSTRUCTIONS = """You are the network specialist for Black Glove.
You run nmap and camera_security.

nmap parameters include target and an optional ports string (digits, commas, and hyphens).
camera_security checks a target for exposed cameras. Report string findings and whether vulnerabilities_detected is true.

Treat INTERPRETATION as the primary summary. Highlight non-standard open ports. Do not invent services that the tool did not report.
A user rejection of a tool is final for this turn. Say that it was rejected.
Answer with a short factual summary, including which ports were open.
"""

WEB_INSTRUCTIONS = """You are the web specialist for Black Glove.
You run gobuster, wappalyzer, web_server_scanner, sqli_scanner, and web_vuln_scanner.

These tools run only when this session already has nmap evidence that port 80, 443, 8080, or 8443 is open.
If a tool refuses because that evidence is missing, stop and say that nmap must run first. Do not invent web findings.

gobuster: omit wordlist to use the bundled default. HTTP 200 is stronger evidence than a 301 or 302 redirect.
wappalyzer: respect confidence percentages.
sqli_scanner and web_vuln_scanner: report only what the tool confirmed.

Treat INTERPRETATION as the primary summary. Do not upgrade severity. If the interpretation says no vulnerabilities were found, say that.
Answer with a short factual summary.
"""

ASSESSMENT_INSTRUCTIONS = """You are the assessment specialist for Black Glove.
You test credentials and write the report.

credential_tester parameters include target, protocol, usernames, and passwords.
Mark credentials CRITICAL only when the tool lists them in valid_credentials. A connection failure is an error, not a successful empty login.
generate_report writes the markdown assessment. Call it when the task asks for a report or after credential testing, with format "markdown".

You are a forensic analyst:
- Leaked or verified credentials are CRITICAL.
- Do not invent findings the tools did not report.
- Give a specific remediation step when you report a real issue, such as revoking a key or removing a public secret.

Treat INTERPRETATION as the primary summary. Answer with the report summary or a clear statement of what was tested.
"""


def _agent(model: Model, instructions: str, toolset, temperature: float) -> Agent[TurnDeps, str | DeferredToolRequests]:
    return Agent(
        model,
        deps_type=TurnDeps,
        output_type=[str, DeferredToolRequests],
        instructions=instructions,
        toolsets=[toolset],
        model_settings=ModelSettings(
            parallel_tool_calls=False,
            temperature=temperature,
        ),
    )


def build_specialists(
    model: Model,
    registry: ToolRegistry,
    *,
    temperature: float,
) -> dict[str, Agent[TurnDeps, str | DeferredToolRequests]]:
    """Create the four domain agents, each with only its own scanners."""
    return {
        "recon_agent": _agent(
            model,
            RECON_INSTRUCTIONS,
            build_scanner_toolset(registry, RECON_TOOLS),
            temperature,
        ),
        "network_agent": _agent(
            model,
            NETWORK_INSTRUCTIONS,
            build_scanner_toolset(registry, NETWORK_TOOLS),
            temperature,
        ),
        "web_agent": _agent(
            model,
            WEB_INSTRUCTIONS,
            build_scanner_toolset(registry, WEB_TOOLS),
            temperature,
        ),
        "assessment_agent": _agent(
            model,
            ASSESSMENT_INSTRUCTIONS,
            build_scanner_toolset(registry, ASSESSMENT_TOOLS),
            temperature,
        ),
    }
