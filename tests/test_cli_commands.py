"""
Tests for CLI Commands

This module contains tests for the CLI commands including recon and report commands.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

from src.agent.cli import app
from typer.testing import CliRunner

runner = CliRunner()


class TestCLICommands:
    """Test cases for CLI commands."""
    
    def test_recon_command_help(self):
        """Test recon command help text."""
        result = runner.invoke(app, ["recon", "--help"])
        assert result.exit_code == 0
        assert "Run reconnaissance on specified assets" in result.output
        assert "passive" in result.output
        assert "active" in result.output
        assert "lab" in result.output
    
    def test_report_command_help(self):
        """Test report command help text."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "Generate security assessment report" in result.output
        assert "format" in result.output
        assert "output" in result.output
    
    @patch('src.agent.db.init_db')
    @patch('src.agent.cli.load_config')
    @patch('src.agent.orchestrator.create_orchestrator')
    def test_recon_passive_command(self, mock_create_orchestrator, mock_load_config, mock_init_db):
        """Test recon passive command execution."""
        # Mock orchestrator
        mock_orchestrator = Mock()
        mock_orchestrator.run_passive_recon.return_value = []
        mock_orchestrator.generate_report.return_value = {
            'summary': {'total_findings': 0}
        }
        mock_create_orchestrator.return_value = mock_orchestrator
        
        # Mock config
        mock_config = Mock()
        mock_config.model_dump.return_value = {}
        mock_load_config.return_value = mock_config
        
        result = runner.invoke(app, ["recon", "passive"])
        
        # Should fail due to no assets, but should call the right functions
        assert mock_init_db.called
        assert mock_create_orchestrator.called
    
    @patch('src.agent.db.init_db')
    @patch('src.agent.reporting.create_reporting_manager')
    def test_report_command(self, mock_create_reporting_manager, mock_init_db):
        """Test report command execution."""
        # Mock reporting manager
        mock_reporting_manager = Mock()
        mock_reporting_manager.generate_assessment_report.return_value = "Test Report Content"
        mock_create_reporting_manager.return_value = mock_reporting_manager
        
        result = runner.invoke(app, ["report", "--format", "json"])
        
        # Should call the right functions
        assert mock_init_db.called
        assert mock_create_reporting_manager.called
    
    def test_recon_invalid_mode(self):
        """Test recon command with invalid mode."""
        with patch('src.agent.db.init_db'):
            with patch('src.agent.models.DatabaseManager') as mock_db_manager:
                # Mock database manager to return assets so we get to the mode check
                mock_db_manager_instance = Mock()
                mock_db_manager_instance.list_assets.return_value = [Mock()]
                mock_db_manager.return_value = mock_db_manager_instance
                
                with patch('src.agent.cli.load_config'):
                    with patch('src.agent.orchestrator.create_orchestrator'):
                        result = runner.invoke(app, ["recon", "invalid"])
                        assert result.exit_code == 1
                        assert "Invalid recon mode" in result.output
    
    def test_report_invalid_format(self):
        """Test report command with invalid format."""
        with patch('src.agent.cli.init_db'):
            with patch('src.agent.cli.create_reporting_manager') as mock_create:
                mock_manager = Mock()
                mock_manager.generate_assessment_report.side_effect = ValueError("Unsupported report format")
                mock_create.return_value = mock_manager
                
                result = runner.invoke(app, ["report", "--format", "invalid"])
                assert result.exit_code == 1
                assert "Report generation failed" in result.output


if __name__ == "__main__":
    pytest.main([__file__])
