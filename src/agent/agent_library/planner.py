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
        "context": AgentInput(description="Current knowledge about the target.", required=False),
        "executor_tools": AgentInput(description="List of available tools to use in the plan.", required=False)
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

You are a RELENTLESS INVESTIGATOR.
You do not just tick boxes; you look for the smoking gun.
Your plans must go beyond basic scanning and include deep-dive reconnaissance.

You are a PLANNER. You do not execute tools yourself.
You create a plan for the Root Agent to execute.

The user will provide a list of "EXECUTOR TOOLS".
These are the tools that the Root Agent has access to.
You MUST include these tools in your plan where appropriate.

STRATEGY:
1.  **Passive Recon is Key**: Always start with `passive_recon`, `whois`, and `dns_lookup`. Look for historical secrets in Wayback Machine (exposed .env, .sql, API keys).
2.  **Active Recon**: Use `nmap` and `gobuster`. For `gobuster`, consider multiple wordlists if available.
3.  **Investigate Findings**: If a previous step found something interesting (e.g. a weird port, a git repo), add a specific step to investigate it further.

IMPORTANT:
Do NOT try to execute these tools directly (e.g. do not output {"tool": "nmap"}).
You do not have access to them. Only the Root Agent does.
Instead, you must construct a `ScanPlan` object and submit it using the `complete_task` tool.

Your output must be a call to `complete_task` with the `scan_plan` parameter containing your plan.

Prioritize reconnaissance first, then active scanning.
Ensure all steps are safe and authorization is implied for this context.
""",
        initial_query_template="EXECUTOR TOOLS:\n${executor_tools}\n\nGoal: ${goal}\nContext: ${context}\n\nCreate a detailed, investigative scan plan using the tools listed above. Be thorough. Submit it via complete_task."
    )
)
