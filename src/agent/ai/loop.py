"""Run a PydanticAI agent until it answers, pausing for tool approval."""

from __future__ import annotations

import logging

from pydantic_ai import Agent, DeferredToolRequests, ModelSettings, RunContext, ToolDenied
from pydantic_ai.messages import ModelMessage

from agent.ai.deps import TurnDeps, emit_activity

logger = logging.getLogger("black_glove.ai.loop")

_MAX_APPROVAL_ROUNDS = 12


def _parameters_of(call) -> dict:
    raw = call.args_as_dict()
    parameters = raw.get("parameters", raw)
    if not isinstance(parameters, dict):
        return {"value": parameters}
    return parameters


async def drive_agent(
    agent: Agent[TurnDeps, str | DeferredToolRequests],
    prompt: str | None,
    deps: TurnDeps,
    *,
    message_history: list[ModelMessage] | None = None,
    usage=None,
) -> str:
    """Run one agent. Tool calls stay sequential. Approval uses the existing callback."""
    settings = ModelSettings(
        parallel_tool_calls=False,
        temperature=deps.temperature,
    )
    try:
        result = await agent.run(
            prompt,
            deps=deps,
            message_history=message_history,
            model_settings=settings,
            usage=usage,
        )
    except Exception:
        emit_activity(deps, "llm_error", "The language model request failed.")
        raise

    rounds = 0
    while isinstance(result.output, DeferredToolRequests):
        rounds += 1
        if rounds > _MAX_APPROVAL_ROUNDS:
            return "Stopped because too many tools were still waiting for approval."
        approvals = {}
        for call in result.output.approvals:
            parameters = _parameters_of(call)
            emit_activity(
                deps,
                "approval_request",
                f"Approve execution of {call.tool_name}?",
                tool=call.tool_name,
                params=parameters,
            )
            approved = False
            callback = deps.approval_callback
            if callback is not None:
                try:
                    approved = bool(await callback(call.tool_name, parameters))
                except Exception:
                    logger.exception("Approval callback failed for %s", call.tool_name)
                    approved = False
            else:
                logger.warning(
                    "Approval required for %s but no callback is configured; denying.",
                    call.tool_name,
                )
            emit_activity(
                deps,
                "approval_resolved",
                "approved" if approved else "rejected",
                tool=call.tool_name,
                approved=approved,
            )
            if approved:
                approvals[call.tool_call_id] = True
            else:
                approvals[call.tool_call_id] = ToolDenied(
                    "The user rejected this tool. Choose another approach and do not retry it."
                )
        try:
            result = await agent.run(
                message_history=result.all_messages(),
                deferred_tool_results=result.output.build_results(approvals=approvals),
                deps=deps,
                model_settings=settings,
                usage=usage,
            )
        except Exception:
            emit_activity(deps, "llm_error", "The language model request failed.")
            raise

    return str(result.output)


async def summon(
    ctx: RunContext[TurnDeps],
    specialist_name: str,
    agent: Agent[TurnDeps, str | DeferredToolRequests],
    task: str,
) -> str:
    """Run one specialist and return its summary to the coordinator."""
    previous = ctx.deps.agent_name
    ctx.deps.agent_name = specialist_name
    emit_activity(ctx.deps, "thinking", f"Summoning {specialist_name}")
    emit_activity(
        ctx.deps,
        "tool_call",
        specialist_name,
        tool=specialist_name,
        params={"task": task},
    )
    try:
        summary = await drive_agent(agent, task, ctx.deps, usage=ctx.usage)
    finally:
        ctx.deps.agent_name = previous
    emit_activity(
        ctx.deps,
        "tool_result",
        summary[:500],
        tool=specialist_name,
        status="success",
    )
    return summary
