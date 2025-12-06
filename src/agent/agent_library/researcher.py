from typing import Dict, Any, List
from pydantic import BaseModel
from src.agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig

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
            "camera_security"
        ]
    ),
    prompt_config=AgentPromptConfig(
        system_prompt="""You are the Researcher Agent for Black Glove.
Your job is to execute specific security tools with precision.
You should interpret the raw output and return a clean summary.
If a tool fails, report the error clearly.
""",
        initial_query_template="Execute tool ${tool_name} on target ${target} with params ${parameters}"
    )
)
