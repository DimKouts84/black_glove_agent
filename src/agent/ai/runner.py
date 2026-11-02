"""One chat turn through the Black Glove coordinator."""

from __future__ import annotations

from typing import Any, Optional, Sequence, Set

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import Model

from agent.ai.black_glove import build_coordinator
from agent.ai.deps import (
    ActivityCallback,
    ApprovalCallback,
    TurnDeps,
    emit_activity,
    session_scan_state,
)
from agent.ai.loop import drive_agent
from agent.ai.model_factory import build_model
from agent.llm_client import LLMMessage
from agent.models import ConfigModel
from agent.tools.registry import ToolRegistry


def history_to_model_messages(history: Optional[Sequence[LLMMessage]]) -> list[ModelMessage]:
    """Convert stored chat messages into PydanticAI history.

    System notes, including the engagement summary, are passed as user context
    so the coordinator still sees them beside its own instructions.
    """
    messages: list[ModelMessage] = []
    if not history:
        return messages
    for message in history:
        content = str(getattr(message, "content", "") or "")
        if not content:
            continue
        role = getattr(message, "role", "user")
        if role == "assistant":
            messages.append(ModelResponse(parts=[TextPart(content=content)]))
        elif role == "system":
            messages.append(
                ModelRequest(parts=[UserPromptPart(content=f"[context]\n{content}")])
            )
        else:
            messages.append(ModelRequest(parts=[UserPromptPart(content=content)]))
    return messages


async def run_chat_turn(
    *,
    config: ConfigModel,
    tool_registry: ToolRegistry,
    user_query: str,
    history: Optional[Sequence[LLMMessage]] = None,
    session_id: str,
    require_approval: bool,
    safe_tools: Set[str],
    on_activity: Optional[ActivityCallback] = None,
    approval_callback: Optional[ApprovalCallback] = None,
    model: Optional[Model] = None,
) -> dict[str, Any]:
    """Answer one user message. Returns the final_answer shape the UI already reads."""
    selected = model or build_model(config)
    deps = TurnDeps(
        config=config,
        tool_registry=tool_registry,
        session_id=session_id,
        scan_state=session_scan_state(session_id),
        require_approval=require_approval,
        safe_tools=set(safe_tools),
        approval_callback=approval_callback,
        on_activity=on_activity,
        agent_name="black_glove",
        temperature=config.llm_temperature,
    )
    coordinator = build_coordinator(
        selected,
        tool_registry,
        temperature=config.llm_temperature,
    )
    answer = await drive_agent(
        coordinator,
        user_query,
        deps,
        message_history=history_to_model_messages(history),
    )
    emit_activity(deps, "answer", answer)
    return {"final_answer": {"answer": answer}}
