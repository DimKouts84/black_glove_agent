"""Tests for non-blocking LLM calls in AgentExecutor."""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, "src")

from agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig
from agent.executor import AgentExecutor
from agent.llm_client import LLMResponse


@pytest.mark.anyio
async def test_executor_calls_llm_via_to_thread():
    definition = AgentDefinition(
        name="test_agent",
        description="Test",
        input_config={"query": AgentInput(description="Query")},
        output_config=None,
        tool_config=AgentToolConfig(tools=[]),
        prompt_config=AgentPromptConfig(
            system_prompt="System",
            initial_query_template="${query}",
        ),
    )

    mock_llm = MagicMock()
    mock_llm.generate = MagicMock(
        return_value=LLMResponse(
            content='{"tool": "complete_task", "parameters": {}, "rationale": "done"}',
            usage={},
        )
    )

    executor = AgentExecutor(definition, mock_llm, MagicMock())

    with patch("agent.executor.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
        mock_thread.return_value = mock_llm.generate.return_value
        await executor.run({"query": "hello"})

        mock_thread.assert_called_once()
        assert mock_thread.call_args.args[0] is mock_llm.generate


@pytest.mark.anyio
async def test_executor_emits_llm_error_on_response_parse_failure():
    """LLM failures must not be misattributed as tool failures."""
    from agent.llm_client import LLMResponseError

    definition = AgentDefinition(
        name="test_agent",
        description="Test",
        input_config={"query": AgentInput(description="Query")},
        output_config=None,
        tool_config=AgentToolConfig(tools=[]),
        prompt_config=AgentPromptConfig(
            system_prompt="System",
            initial_query_template="${query}",
        ),
    )

    mock_llm = MagicMock()
    mock_llm.generate = MagicMock(
        side_effect=[
            LLMResponseError("API error: Rate limited"),
            LLMResponse(
                content='{"tool": "complete_task", "parameters": {}, "rationale": "done"}',
                usage={},
            ),
        ]
    )

    events = []
    executor = AgentExecutor(
        definition,
        mock_llm,
        MagicMock(),
        on_activity=lambda e: events.append(e),
    )

    with patch("agent.executor.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
        mock_thread.side_effect = lambda fn, *args, **kwargs: fn(*args, **kwargs)
        await executor.run({"query": "hello"})

    llm_errors = [e for e in events if e.get("type") == "llm_error"]
    assert len(llm_errors) == 1
    assert "Rate limited" in llm_errors[0]["content"]
    assert mock_llm.generate.call_count == 2


@pytest.mark.anyio
async def test_executor_warns_when_scan_tools_run_without_report():
    from pydantic import BaseModel

    class FinalResponse(BaseModel):
        answer: str

    definition = AgentDefinition(
        name="test_agent",
        description="Test",
        input_config={"query": AgentInput(description="Query")},
        output_config=AgentOutput(
            output_name="final_answer",
            description="Answer",
            schema_model=FinalResponse,
        ),
        tool_config=AgentToolConfig(tools=["web_server_scanner"]),
        prompt_config=AgentPromptConfig(
            system_prompt="System",
            initial_query_template="${query}",
        ),
    )

    tool_calls = [
        '{"tool": "web_server_scanner", "parameters": {"target_url": "https://example.com"}}',
    ]
    call_idx = {"i": 0}

    def next_response(*_args, **_kwargs):
        idx = call_idx["i"]
        call_idx["i"] += 1
        if idx < len(tool_calls):
            return LLMResponse(content=tool_calls[idx], usage={})
        return LLMResponse(
            content='{"tool": "complete_task", "parameters": {"final_answer": {"answer": "done"}}, "rationale": "done"}',
            usage={},
        )

    mock_llm = MagicMock()
    mock_llm.generate = MagicMock(side_effect=next_response)

    mock_tool = MagicMock()
    mock_tool.execute.return_value = {"interpretation": "ok"}
    registry = MagicMock()
    registry.has_tool.return_value = True
    registry.get_tool.return_value = mock_tool
    registry.list_tools.return_value = ["web_server_scanner"]

    events = []
    executor = AgentExecutor(
        definition,
        mock_llm,
        registry,
        max_turns=1,
        on_activity=lambda e: events.append(e),
    )

    with patch("agent.executor.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
        mock_thread.side_effect = lambda fn, *args, **kwargs: fn(*args, **kwargs)
        with patch("agent.tools.report_tool.ReportTool") as mock_report_cls:
            mock_report_cls.return_value.execute.return_value = "# Report\n\nFindings here."
            await executor.run({"query": "scan example.com"})

    warnings = [e for e in events if e.get("type") == "warning"]
    assert any("generate_report" in (e.get("content") or "") for e in warnings)
