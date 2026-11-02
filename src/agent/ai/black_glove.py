"""Black Glove coordinator. Its only tools are the domain specialists."""

from __future__ import annotations

from pydantic_ai import Agent, DeferredToolRequests, ModelSettings, RunContext
from pydantic_ai.models import Model

from agent.ai.deps import TurnDeps
from agent.ai.loop import summon
from agent.ai.specialists import build_specialists
from agent.tools.registry import ToolRegistry

BLACK_GLOVE_INSTRUCTIONS = """You are BLACK GLOVE, an elite penetration testing assistant for authorized security testing.
When someone greets you, introduce yourself as Black Glove and do not run a scan.

You do not call scanners yourself. You summon one or more domain specialists, then answer from their summaries.

Specialists:
- recon_agent: public IP, DNS, WHOIS, passive OSINT, certificates, and saved assets.
- network_agent: nmap and exposed-camera checks.
- web_agent: directory enumeration and web vulnerability checks. These run only after nmap has shown an open HTTP port (80, 443, 8080, or 8443).
- assessment_agent: credential testing and the written report. Verified leaked credentials are CRITICAL.

Call the specialists whose domain matches the request. A question that spans domains should call each relevant specialist. A greeting or a question about earlier work needs no specialist.
Do not treat a public IP as a local-network gateway. There is no LAN-discovery tool. If the user asks to scan "the local network", explain the ambiguity and ask whether they mean their public IP, a subnet, or a single host before any scan.
Use each specialist summary as the evidence. Do not invent findings. If the user rejected a tool, say so and do not ask for it again.
"""


def build_coordinator(
    model: Model,
    registry: ToolRegistry,
    *,
    temperature: float,
) -> Agent[TurnDeps, str | DeferredToolRequests]:
    """Coordinator whose tools are recon, network, web, and assessment."""
    specialists = build_specialists(model, registry, temperature=temperature)
    agent: Agent[TurnDeps, str | DeferredToolRequests] = Agent(
        model,
        deps_type=TurnDeps,
        output_type=[str, DeferredToolRequests],
        instructions=BLACK_GLOVE_INSTRUCTIONS,
        model_settings=ModelSettings(
            parallel_tool_calls=False,
            temperature=temperature,
        ),
    )

    @agent.tool
    async def recon_agent(ctx: RunContext[TurnDeps], task: str) -> str:
        """Summon recon for DNS, WHOIS, passive OSINT, certificates, assets, or public IP."""
        return await summon(ctx, "recon_agent", specialists["recon_agent"], task)

    @agent.tool
    async def network_agent(ctx: RunContext[TurnDeps], task: str) -> str:
        """Summon network scanning for nmap or exposed-camera checks."""
        return await summon(ctx, "network_agent", specialists["network_agent"], task)

    @agent.tool
    async def web_agent(ctx: RunContext[TurnDeps], task: str) -> str:
        """Summon web checks. They run only after nmap shows an open HTTP port."""
        return await summon(ctx, "web_agent", specialists["web_agent"], task)

    @agent.tool
    async def assessment_agent(ctx: RunContext[TurnDeps], task: str) -> str:
        """Summon credential testing or the written security report."""
        return await summon(ctx, "assessment_agent", specialists["assessment_agent"], task)

    return agent
