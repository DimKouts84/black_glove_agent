import pytest
from unittest.mock import Mock, patch, AsyncMock
from typer.testing import CliRunner
from src.agent.cli import app
from src.agent.llm_client import LLMResponse

runner = CliRunner()

class TestCLIUXScenarios:
    
    @patch('src.agent.cli.init_db')
    @patch('src.agent.session_manager.SessionManager')
    @patch('src.agent.cli.load_config')
    @patch('src.agent.plugin_manager.create_plugin_manager')
    @patch('src.agent.llm_client.create_llm_client')
    @patch('rich.prompt.Prompt.ask')
    def test_json_recovery_flow(
        self, 
        mock_prompt, 
        mock_create_llm, 
        mock_create_pm, 
        mock_load_config,
        mock_session_manager,
        mock_init_db
    ):
        """Test that the agent recovers from invalid JSON responses."""
        
        # Mocks
        mock_config = Mock()
        mock_config.dict.return_value = {}
        mock_load_config.return_value = mock_config
        
        mock_pm = Mock()
        mock_pm.discover_adapters.return_value = []
        mock_create_pm.return_value = mock_pm
        
        mock_session_instance = mock_session_manager.return_value
        mock_session_instance.create_session.return_value = "test_sess"
        mock_session_instance.get_session_info.return_value = None

        # LLM Mocking
        mock_llm_instance = Mock()
        mock_create_llm.return_value = mock_llm_instance
        
        # Sequence of LLM responses:
        # 1. User: "Who are you?"
        # 2. LLM: "I am Black Glove." (Invalid JSON)
        # 3. System: Error prompt...
        # 4. LLM: Correct JSON
        
        mock_llm_instance.generate.side_effect = [
            LLMResponse(content="I am a pentesting agent."), # Invalid
            LLMResponse(content='{"tool": "complete_task", "parameters": {"final_answer": {"answer": "I am a pentesting agent detected."}}}') # Valid
        ]
        
        # Input
        mock_prompt.side_effect = ["Who are you?", "exit"]
        
        # Run
        result = runner.invoke(app, ["chat"])
        
        # Check Output
        assert result.exit_code == 0
        assert "Agent response was not valid JSON" in result.output # Should see the warning/retry
        assert "I am a pentesting agent detected" in result.output # Should see final answer

    @patch('src.agent.cli.init_db')
    @patch('src.agent.session_manager.SessionManager')
    @patch('src.agent.cli.load_config')
    @patch('src.agent.plugin_manager.create_plugin_manager')
    @patch('src.agent.llm_client.create_llm_client')
    @patch('rich.prompt.Prompt.ask')
    def test_tool_none_recovery(
        self, 
        mock_prompt, 
        mock_create_llm, 
        mock_create_pm, 
        mock_load_config,
        mock_session_manager,
        mock_init_db
    ):
        """Test that the agent recovers from tool='None'."""
        
        mock_config = Mock()
        mock_config.dict.return_value = {}
        mock_load_config.return_value = mock_config
        
        mock_pm = Mock()
        mock_pm.discover_adapters.return_value = []
        mock_create_pm.return_value = mock_pm
        
        mock_session_instance = mock_session_manager.return_value
        mock_session_instance.create_session.return_value = "test_sess"
        
        mock_llm_instance = Mock()
        mock_create_llm.return_value = mock_llm_instance
        
        # Responses:
        # 1. Tool: None (Hallucination)
        # 2. Tool: complete_task (Correction)
        mock_llm_instance.generate.side_effect = [
            LLMResponse(content='{"tool": "None", "parameters": {}}'),
            LLMResponse(content='{"tool": "complete_task", "parameters": {"final_answer": {"answer": "Fixed."}}}')
        ]
        
        mock_prompt.side_effect = ["Do something", "exit"]
        
        result = runner.invoke(app, ["chat"])
        
        # Debug
        if result.exit_code != 0:
            print(result.output)

        assert "Agent returned invalid tool 'None'" in result.output or "Error: Tool 'None' not found" in result.output or "Invalid tool" in result.output
        assert "Fixed." in result.output
