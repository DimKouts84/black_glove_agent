"""
UAT-focused CLI usability tests:
- --version flag
- adapters list command
- recon --dry-run with adapter filtering
"""
import sys
from pathlib import Path
from unittest.mock import Mock, patch
from typer.testing import CliRunner

# Ensure package imports resolve in test env
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.cli import app  # noqa: E402

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "black-glove" in result.output


@patch("src.agent.plugin_manager.create_plugin_manager")
def test_adapters_list_command(mock_create_pm):
    mock_pm = Mock()
    mock_pm.discover_adapters.return_value = ["nmap", "gobuster"]

    def _info_for(name: str):
        return {
            "category": "active",
            "requires_docker": True,
            "description": f"{name} adapter",
        }

    mock_pm.get_adapter_info.side_effect = _info_for
    mock_create_pm.return_value = mock_pm

    result = runner.invoke(app, ["adapters", "list"])
    assert result.exit_code == 0
    assert "Available Adapters (2)" in result.output
    assert "nmap" in result.output
    assert "gobuster" in result.output


@patch("src.agent.db.init_db")
@patch("src.agent.models.Asset")
@patch("src.agent.models.DatabaseManager")
@patch("src.agent.orchestrator.create_orchestrator")
def test_recon_active_dry_run_filters(
    mock_create_orchestrator, mock_db_manager_cls, mock_asset_cls, mock_init_db
):
    mock_orchestrator = Mock()
    mock_orchestrator.plan_active_scans.return_value = [
        {"tool": "nmap", "target": "scanme.nmap.org", "params": {"ports": "22,80,443"}},
        {"tool": "gobuster", "target": "example.com", "params": {"mode": "dns"}},
    ]
    mock_create_orchestrator.return_value = mock_orchestrator

    mock_db_manager = Mock()
    asset_model = Mock()
    asset_model.id = 1
    asset_model.name = "ex"
    asset_model.value = "example.com"
    mock_db_manager.list_assets.return_value = [asset_model]
    mock_db_manager_cls.return_value = mock_db_manager

    result = runner.invoke(
        app, ["recon", "active", "--dry-run", "--adapters", "nmap"]
    )
    assert result.exit_code == 0
    assert "Planned active steps (dry-run)" in result.output
    assert "nmap" in result.output
    assert "gobuster" not in result.output
