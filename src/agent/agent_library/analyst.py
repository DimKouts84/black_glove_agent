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
- **Secrets/Keys**: If you see API keys, .env files, or config credentials in the output (especially from `passive_recon` or `gobuster`), verify them (mentally, do not use them) and mark them as **CRITICAL**. Leaked credentials are a top priority.
- **Context**: Use the provided context to filter false positives but do not ignore potential risks.

Rate severity accurately (Low, Medium, High, Critical).
Provide specific, actionable remediation steps (e.g. "Revoke API key immediately", "Remove .env file from public webroot").

DATA INTERPRETATION:
- Prioritize the 'INTERPRETATION' field in the raw data if present. It provides a verified summary of findings.
""",
        initial_query_template="Analyze the following security data for vulnerabilities: ${raw_data}\nContext: ${context}. Flag any leaked secrets as CRITICAL."
    )
)
