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

You are a PLANNER. You do not execute tools yourself.
You create a plan for the Root Agent to execute.

The user will provide a list of "EXECUTOR TOOLS".
These are the tools that the Root Agent has access to.
You MUST include these tools in your plan where appropriate.

IMPORTANT:
Do NOT try to execute these tools directly (e.g. do not output {"tool": "nmap"}).
You do not have access to them. Only the Root Agent does.
Instead, you must construct a `ScanPlan` object and submit it using the `complete_task` tool.

Your output must be a call to `complete_task` with the `scan_plan` parameter containing your plan.

Prioritize reconnaissance first, then active scanning.
Ensure all steps are safe and authorization is implied for this context.
""",
        initial_query_template="EXECUTOR TOOLS:\n${executor_tools}\n\nGoal: ${goal}\nContext: ${context}\n\nCreate a detailed scan plan using the tools listed above and submit it via complete_task."
    )
)