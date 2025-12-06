from typing import List, Dict, Any
from pydantic import BaseModel
from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig

class ScanStep(BaseModel):
    tool: str
    target: str
    parameters: Dict[str, Any]
    rationale: str

class ScanPlan(BaseModel):
    goal: str
    steps: List[ScanStep]
    reasoning: str

PLANNER_AGENT = AgentDefinition(
    name="planner_agent",
    description="A specialized agent that creates detailed, step-by-step security scan plans.",
    input_config={
        "goal": AgentInput(description="The high-level security objective."),
        "context": AgentInput(description="Current knowledge about the target.", required=False)
    },
    output_config=AgentOutput(
        output_name="scan_plan",
        description="The structured scan plan.",
        schema_model=ScanPlan
    ),
    tool_config=AgentToolConfig(
        tools=[] 
    ),
    prompt_config=AgentPromptConfig(
        system_prompt="""You are the Planner Agent for Black Glove.
Your job is to break down high-level security goals into specific, actionable technical steps.
You understand the capabilities of tools like nmap, gobuster, whois, dns_lookup, etc.
Prioritize reconnaissance first, then active scanning.
Ensure all steps are safe and authorization is implied for this context.
""",
        initial_query_template="Create a scan plan for the following goal: ${goal}\nContext: ${context}"
    )
)
