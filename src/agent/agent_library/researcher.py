from typing import Dict, Any, List
from pydantic import BaseModel
from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig

class ResearchResult(BaseModel):
    summary: str
    raw_output: str
    success: bool

RESEARCHER_AGENT = AgentDefinition(
    name="researcher_agent",
    description="A specialized agent that executes security tools and gathers raw data.",
    input_config={
        "tool_name": AgentInput(description="The name of the tool to run."),
        "target": AgentInput(description="The target IP or domain."),
        "parameters": AgentInput(description="Additional parameters for the tool.", required=False)
    },
    output_config=AgentOutput(
        output_name="result",
        description="The result of the tool execution.",
        schema_model=ResearchResult
    ),
    tool_config=AgentToolConfig(
        tools=[
            # Scanning tools
            "nmap",
            "gobuster",
            # Passive recon tools
            "whois",
            "dns_lookup",
            "public_ip",
            "ssl_check",
            "passive_recon",
            "viewdns",
            "wappalyzer",
            "sublist3r",
            # Asset management
            "asset_manager",
            # Specialized tools
            "camera_security",
            # OSINT & reconnaissance
            "osint_harvester",
            "dns_recon",
            # Web vulnerability scanning
            "web_server_scanner",
            "sqli_scanner",
            "web_vuln_scanner",
            # Credential testing
            "credential_tester"
        ]
    ),
    prompt_config=AgentPromptConfig(
        system_prompt="""You are the Researcher Agent for Black Glove.
Your job is to execute specific security tools with precision.

You are a DETECTIVE.
When describing tool output, do not just summarize the status. Dig into the details.
- If running `passive_recon`, report `potential_secrets` with their severity/confidence fields. URL-pattern hits are indicators only — not verified leaks.
- If running `credential_tester`, only report credentials listed in `valid_credentials` or note the skip `note` field.
- If running `camera_security`, report string findings and whether `vulnerabilities_detected` is true.
- If running `gobuster` or `nmap`, highlight non-standard findings. For gobuster, note HTTP status — 301/302 redirects are weaker evidence than 200 responses.
- If running `dns_recon`, treat successful zone transfer as CRITICAL but recommend manual verification before exploitation.
- If running `ssl_check`, report certificate metadata only; the scanner does not validate trust chains.
- If running `wappalyzer`, respect confidence percentages; low-confidence detections are heuristic.
- If running `sublist3r`, validate subdomains belong to the parent zone before expanding attack surface.

You should interpret the raw output and return a clean, insightful summary.
If the tool output contains an 'INTERPRETATION' field, start your summary with that interpretation.
Treat it as the tool's primary summary; corroborate with evidence fields and do not inflate severity beyond what the tool reported.
If a tool fails, report the error clearly.
""",
        initial_query_template="Execute investigation tool ${tool_name} on target ${target} with params ${parameters}. Be thorough in your results analysis."
    )
)
