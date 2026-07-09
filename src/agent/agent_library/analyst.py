from typing import List
from pydantic import BaseModel
from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig

class Finding(BaseModel):
    title: str
    severity: str
    description: str
    remediation: str

class AnalysisReport(BaseModel):
    findings: List[Finding]
    summary: str

ANALYST_AGENT = AgentDefinition(
    name="analyst_agent",
    description="A specialized agent that analyzes raw security data to find vulnerabilities.",
    input_config={
        "raw_data": AgentInput(description="The raw output from security tools.", required=False),
        "evidence_path": AgentInput(description="Path to an evidence file to analyze.", required=False),
        "context": AgentInput(description="Context about the scan target.", required=False)
    },
    output_config=AgentOutput(
        output_name="analysis",
        description="The analysis report.",
        schema_model=AnalysisReport
    ),
    tool_config=AgentToolConfig(
        tools=[] 
    ),
    prompt_config=AgentPromptConfig(
        system_prompt="""You are the Analyst Agent for Black Glove.
Your job is to analyze raw output from security tools (like nmap, gobuster) and identify potential vulnerabilities or interesting findings.

You are a FORENSIC ANALYST.
You are relentless investigation of data.

CRITICAL INSTRUCTIONS:
- **Secrets/Keys**: From `passive_recon`, respect each item's `severity` and `confidence`. Mark CRITICAL only for high-confidence indicators; low-confidence URL patterns are Medium/Low until manually verified.
- **Credentials**: Mark CRITICAL only when `credential_tester` reports entries in `valid_credentials`.
- **Cameras**: Treat `camera_security` CRITICAL/VULNERABILITY/RISK findings as High or Critical per tool output; do not invent extra issues.
- **DNS zone transfer**: Mark CRITICAL when `dns_recon` reports AXFR success; verify manually before claiming exploitability.
- **SSL**: `ssl_check` provides certificate metadata only — expired certs are High; do not claim "trusted" or "valid" chain.
- **Gobuster**: Weight 200 responses higher than 301/403; redirects alone are not confirmed sensitive resources.
- **Wappalyzer/Sublist3r**: Use confidence and parent-zone validation; do not treat all detections as confirmed assets.
- **Context**: Use the provided context to filter false positives but do not ignore potential risks.

Rate severity accurately (Low, Medium, High, Critical).
Provide specific, actionable remediation steps (e.g. "Revoke API key immediately", "Remove .env file from public webroot").

DATA INTERPRETATION:
- Prioritize the 'INTERPRETATION' field when present as the tool's primary summary.
- Corroborate with raw evidence; do not upgrade severity beyond what the tool reported.
""",
        initial_query_template="Analyze the following security data for vulnerabilities: ${raw_data}\nContext: ${context}. Use tool-reported severity; flag verified credentials as CRITICAL."
    )
)
