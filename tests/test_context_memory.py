import pytest
from unittest.mock import MagicMock, AsyncMock
from src.agent.executor import AgentExecutor
from src.agent.definitions import AgentDefinition, AgentInput, AgentOutput, AgentToolConfig, AgentPromptConfig
from src.agent.llm_client import LLMMessage, LLMResponse

@pytest.mark.anyio
async def test_executor_history_persistence():
    # 1. Setup Mock Agent
    definition = AgentDefinition(
        name="test_agent",
        description="Test Agent",
        input_config={"query": AgentInput(description="User query")},
        output_config=None,
        tool_config=AgentToolConfig(tools=[]),
        prompt_config=AgentPromptConfig(
            system_prompt="System Prompt",
            initial_query_template="${query}"
        )
    )
    
    mock_llm = MagicMock()
    mock_llm.generate = MagicMock(return_value=LLMResponse(
        content='{"tool": "complete_task", "parameters": {}, "rationale": "Done"}', 
        usage={}
    ))
    
    executor = AgentExecutor(definition, mock_llm, MagicMock())
    
    # 2. Define History
    history = [
        LLMMessage(role="user", content="My name is TestUser."),
        LLMMessage(role="assistant", content="Hello TestUser.")
    ]
    
    # 3. Run Executor with History
    await executor.run({"query": "What is my name?"}, conversation_history=history)
    
    # 4. Verify LLM Call
    # Expectation: System + User(History) + Assistant(History) + User(Current)
    calls = mock_llm.generate.call_args_list
    assert len(calls) > 0
    last_call_args = calls[0][0][0] # First arg of first call is history list
    
    # Verify content
    roles = [msg.role for msg in last_call_args]
    contents = [msg.content for msg in last_call_args]
    
    print(f"Roles: {roles}")
    print(f"Contents: {contents}")

    assert "system" in roles[0] # System prompt
    assert "My name is TestUser." in contents[1] # History 1
    assert "Hello TestUser." in contents[2] # History 2
    assert "What is my name?" in contents[3] # Current query
