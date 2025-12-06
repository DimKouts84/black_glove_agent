import pytest
from unittest.mock import Mock, patch, AsyncMock
from typer.testing import CliRunner
from src.agent.cli import app

runner = CliRunner()

class TestCLIChatRefactored:
    
    @patch('src.agent.cli.init_db')
    @patch('src.agent.session_manager.SessionManager')
    @patch('src.agent.cli.load_config')
    @patch('src.agent.plugin_manager.create_plugin_manager')
    @patch('src.agent.llm_client.create_llm_client')
    @patch('src.agent.executor.AgentExecutor')
    @patch('rich.prompt.Prompt.ask')
    def test_chat_command_flow(
        self, 
        mock_prompt, 
        mock_executor_cls, 
        mock_create_llm, 
        mock_create_pm, 
        mock_load_config,
        mock_session_manager,
        mock_init_db
    ):
        # Setup Mocks
        mock_config = Mock()
        mock_config.dict.return_value = {}
        mock_load_config.return_value = mock_config

        # Plugin Manager Mock
        mock_pm = Mock()
        mock_pm.discover_adapters.return_value = ["nmap", "whois"] # Mock some adapters
        mock_create_pm.return_value = mock_pm

        # Session Manager Mock
        mock_session_instance = mock_session_manager.return_value
        mock_session_instance.create_session.return_value = "test_session_id"
        mock_session_instance.get_session_info.return_value = None

        # Executor Mock
        mock_executor_instance = AsyncMock() # run is async
        # Mock run return value - needs to look like what we expect
        mock_executor_instance.run.return_value = {"final_answer": {"answer": "I have scanned the target."}}
        mock_executor_cls.return_value = mock_executor_instance

        # User Input Mock: 1. query, 2. exit
        mock_prompt.side_effect = ["scan local", "exit"]

        # Run command
        result = runner.invoke(app, ["chat"])

        # Debug Output
        if result.exit_code != 0:
            print(f"CLI Output:\n{result.output}")
            print(f"Exception: {result.exception}")
            import traceback
            if result.exc_info:
                traceback.print_exception(*result.exc_info)

        # Verification
        assert result.exit_code == 0
        assert "BLACK GLOVE AGENT CHAT" in result.output
        assert "Refactored agentic workflow active" in result.output

        # Verify Executor Initialized
        assert mock_executor_cls.called
        # Check that ROOT_AGENT was passed (first arg or kwarg)
        args, kwargs = mock_executor_cls.call_args
        # agent_definition is first arg
        agent_def = kwargs.get('agent_definition') or args[0]
        assert agent_def.name == "root_agent"

        # Verify run called with user input
        mock_executor_instance.run.assert_called_with({"user_query": "scan local"})

        # Verify output contains the answer
        assert "I have scanned the target." in result.output
