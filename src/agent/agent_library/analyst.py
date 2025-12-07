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
Rate severity accurately (Low, Medium, High, Critical).
Provide actionable remediation steps.
""",
        initial_query_template="Analyze the following data: ${raw_data}\nContext: ${context}"
    )
)
