"""Tests for sub-agent activity event propagation."""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, "src")

from agent.agent_library.planner import PLANNER_AGENT
from agent.subagent_tool import SubagentTool
from agent.tools.registry import ToolRegistry


@pytest.mark.anyio
async def test_subagent_tool_passes_on_activity_to_nested_executor():
    captured = []
    registry = ToolRegistry()
    sub = SubagentTool(PLANNER_AGENT, MagicMock(), registry)
    sub.on_activity = captured.append

    with patch("agent.subagent_tool.AgentExecutor") as MockExecutor:
        mock_exec = MockExecutor.return_value
        mock_exec.run = AsyncMock(return_value={"scan_plan": {"goal": "test"}})

        await sub.execute({"goal": "Scan target"})

        MockExecutor.assert_called_once()
        on_act = MockExecutor.call_args.kwargs["on_activity"]
        assert on_act is not None
        on_act({"type": "thinking", "agent": "planner_agent", "content": "test"})
        assert len(captured) == 1


@pytest.mark.anyio
async def test_executor_forwards_on_activity_to_subagent_tool():
    from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig
    from agent.executor import AgentExecutor
    from agent.llm_client import LLMMessage, LLMResponse

    parent_events = []

    registry = ToolRegistry()
    sub = SubagentTool(PLANNER_AGENT, MagicMock(), registry)

    async def sub_execute(params):
        if sub.on_activity:
            sub.on_activity({
                "agent": "planner_agent",
                "type": "thinking",
                "content": "Building plan",
            })
        return {"scan_plan": {"goal": params.get("goal", "")}}

    sub.execute = sub_execute
    registry.register(sub)

    definition = AgentDefinition(
        name="root_agent",
        description="Root",
        input_config={"user_query": AgentInput(description="Query")},
        output_config=AgentOutput(
            output_name="final_answer",
            description="Answer",
            schema_model=__import__(
                "agent.agent_library.root", fromlist=["FinalResponse"]
            ).FinalResponse,
        ),
        tool_config=AgentToolConfig(tools=["planner_agent"]),
        prompt_config=AgentPromptConfig(
            system_prompt="You are root.",
            initial_query_template="${user_query}",
        ),
    )

    mock_llm = MagicMock()
    complete = (
        '{"tool": "complete_task", "parameters": {"final_answer": {"answer": "ok"}}, '
        '"rationale": "done"}'
    )
    tool_call = (
        '{"tool": "planner_agent", "parameters": {"goal": "scan"}, '
        '"rationale": "delegate"}'
    )
    mock_llm.generate = MagicMock(
        side_effect=[
            LLMResponse(content=tool_call, usage={}),
            LLMResponse(content=complete, usage={}),
        ]
    )

    executor = AgentExecutor(
        definition,
        mock_llm,
        registry,
        on_activity=parent_events.append,
    )

    with patch("agent.executor.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
        mock_thread.side_effect = lambda fn, *args, **kwargs: fn(*args, **kwargs)
        await executor.run({"user_query": "scan example.com"})

    agents = [e["agent"] for e in parent_events]
    assert "root_agent" in agents
    assert "planner_agent" in agents
    assert any(e["type"] == "thinking" and e["agent"] == "planner_agent" for e in parent_events)
