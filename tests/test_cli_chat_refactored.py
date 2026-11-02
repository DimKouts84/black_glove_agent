from unittest.mock import AsyncMock, patch
from typer.testing import CliRunner

from agent.models import ConfigModel
from src.agent.cli import app

runner = CliRunner()


class TestCLIChatRefactored:
    @patch("src.agent.ui.get_user_input_async", new_callable=AsyncMock)
    @patch("src.agent.runtime.AgentRuntime")
    @patch("src.agent.cli.load_config")
    @patch("src.agent.session_manager.SessionManager")
    @patch("src.agent.db.init_db")
    def test_chat_command_flow(
        self,
        mock_init_db,
        mock_session_manager,
        mock_load_config,
        mock_runtime_cls,
        mock_input,
    ):
        config = ConfigModel()
        mock_load_config.return_value = config

        session = mock_session_manager.return_value
        session.create_session.return_value = "test_session_id"
        session.get_session_info.return_value = None
        session.load_session.return_value = []

        runtime = mock_runtime_cls.return_value
        runtime.config = config
        runtime.run_turn = AsyncMock(
            return_value={"final_answer": {"answer": "I have scanned the target."}}
        )

        mock_input.side_effect = ["scan local", "exit"]

        result = runner.invoke(app, ["chat"])

        if result.exit_code != 0:
            print(f"CLI Output:\n{result.output}")
            print(f"Exception: {result.exception}")

        assert result.exit_code == 0
        assert "Type exit to quit" in result.output
        assert "I have scanned the target." in result.output
        runtime.run_turn.assert_awaited()
        assert runtime.run_turn.await_args.args[1] == "scan local"
