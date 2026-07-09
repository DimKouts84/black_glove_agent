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
