from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig

class ScanStep(BaseModel):
    step_key: Optional[str] = None
    tool: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    depends_on: List[str] = Field(default_factory=list)
    phase: Optional[str] = None
    worker_kind: str = "adapter"
    parallel_group: Optional[str] = None
    analysis_shard_key: Optional[str] = None
    timeout_seconds: float = 600.0
    max_retries: int = 1
    continue_on_failure: bool = False

class ScanPlan(BaseModel):
    goal: str
    steps: List[ScanStep]
    reasoning: str
    strict_sequential: bool = False
    failure_policy: str = "block_downstream"

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

WEBSITE FULL-SCAN CHECKLIST (when goal mentions website, domain, full scan, all tools, or every tool):
  Required recon: whois, passive_recon, osint_harvester, dns_lookup, sublist3r, ssl_check
  Required scanning: wappalyzer (https URL), web_server_scanner (https URL), nmap, web_vuln_scanner, sqli_scanner, gobuster (dir mode on https URL)
  Final step: generate_report
  Do NOT omit ssl_check, sublist3r, nmap, or gobuster for all-tools / comprehensive website assessments.
  For narrower goals (single-tool or focused checks), omit nmap/gobuster only when not requested.

IMPORTANT:
Do NOT try to execute these tools directly (e.g. do not output {"tool": "nmap"}).
You do not have access to them. Only the Root Agent does.
Instead, you must construct a `ScanPlan` object and submit it using the `complete_task` tool.

Your output must be a call to `complete_task` with the `scan_plan` parameter containing your plan.

Example complete_task format:
{
    "tool": "complete_task",
    "parameters": {
        "scan_plan": {
            "goal": "Comprehensive scan of example.com",
            "reasoning": "Start passive, then active scanning",
            "steps": [
                {
                    "tool": "whois",
                    "target": "example.com",
                    "parameters": {"domain": "example.com"},
                    "rationale": "Domain registration baseline"
                }
            ]
        }
    },
    "rationale": "Submitting investigative scan plan"
}

Prioritize reconnaissance first, then active scanning.
Ensure all steps are safe and authorization is implied for this context.
""",
        initial_query_template="EXECUTOR TOOLS:\n${executor_tools}\n\nGoal: ${goal}\nContext: ${context}\n\nCreate a detailed, investigative scan plan using the tools listed above. Be thorough. Submit it via complete_task."
    )
)
