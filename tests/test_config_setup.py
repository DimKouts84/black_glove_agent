"""
Tests for configuration setup and validation.
"""
import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch

# Add src to path for imports
sys.path.insert(0, 'src')

from agent.models import ConfigModel, AssetModel, AssetType, SeverityLevel, EventType
from agent.cli import setup_config_file

class TestConfiguration:
    """Test suite for configuration functionality."""
    
    def test_config_model_default_values(self):
        """Test ConfigModel default values."""
        config = ConfigModel()
        
        # Test LLM settings
        assert config.llm_provider == "lmstudio"
        assert config.llm_endpoint == "http://localhost:1234/v1"
        assert config.llm_model == "local-model"
        assert config.llm_temperature == 0.7
        
        # Test scan settings
        assert config.default_rate_limit == 50
        assert config.max_rate_limit == 100
        assert config.scan_timeout == 300
        
        # Test logging settings
        assert config.log_level == "INFO"
        assert config.log_retention_days == 90
        
        # Test safety settings
        assert config.require_lab_mode_for_exploits is True
        assert config.enable_exploit_adapters is False
        
        # Test evidence storage
        assert config.evidence_storage_path == "~/.homepentest/evidence"
    
    def test_config_model_custom_values(self):
        """Test ConfigModel with custom values."""
        config = ConfigModel(
            llm_provider="ollama",
            llm_endpoint="http://localhost:11434/api",
            llm_model="llama2",
            llm_temperature=0.8,
            default_rate_limit=100,
            max_rate_limit=200,
            scan_timeout=600,
            log_level="DEBUG",
            log_retention_days=180,
            require_lab_mode_for_exploits=False,
            enable_exploit_adapters=True,
            evidence_storage_path="/custom/evidence/path"
        )
        
        # Test custom LLM settings
        assert config.llm_provider == "ollama"
        assert config.llm_endpoint == "http://localhost:11434/api"
        assert config.llm_model == "llama2"
        assert config.llm_temperature == 0.8
        
        # Test custom scan settings
        assert config.default_rate_limit == 100
        assert config.max_rate_limit == 200
        assert config.scan_timeout == 600
        
        # Test custom logging settings
        assert config.log_level == "DEBUG"
        assert config.log_retention_days == 180
        
        # Test custom safety settings
        assert config.require_lab_mode_for_exploits is False
        assert config.enable_exploit_adapters is True
        
        # Test custom evidence storage
        assert config.evidence_storage_path == "/custom/evidence/path"
    
    def test_config_model_validation(self):
        """Test ConfigModel validation."""
        # Test temperature validation (should be between 0.0 and 1.0)
        with pytest.raises(ValueError):
            ConfigModel(llm_temperature=1.5)
        
        with pytest.raises(ValueError):
            ConfigModel(llm_temperature=-0.1)
        
        # Test rate limit validation (should be >= 1)
        with pytest.raises(ValueError):
            ConfigModel(default_rate_limit=0)
        
        with pytest.raises(ValueError):
            ConfigModel(max_rate_limit=-1)
        
        # Test scan timeout validation (should be >= 1)
        with pytest.raises(ValueError):
            ConfigModel(scan_timeout=0)
        
        # Test log retention validation (should be >= 1)
        with pytest.raises(ValueError):
            ConfigModel(log_retention_days=0)
    
    def test_asset_model_creation(self):
        """Test AssetModel creation and validation."""
        # Test valid asset creation
        asset = AssetModel(
            name="test-host",
            type=AssetType.HOST,
            value="192.168.1.1"
        )
        
        assert asset.name == "test-host"
        assert asset.type == AssetType.HOST
        assert asset.value == "192.168.1.1"
        assert asset.id is None
        
        # Test with ID
        asset_with_id = AssetModel(
            name="test-domain",
            type=AssetType.DOMAIN,
            value="example.com",
            id=1
        )
        
        assert asset_with_id.id == 1
    
    def test_asset_type_enum(self):
        """Test AssetType enum values."""
        assert AssetType.HOST.value == "host"
        assert AssetType.DOMAIN.value == "domain"
        assert AssetType.VM.value == "vm"
        
        # Test that all expected values are present
        expected_values = {"host", "domain", "vm"}
        actual_values = {member.value for member in AssetType}
        assert actual_values == expected_values
    
    def test_severity_level_enum(self):
        """Test SeverityLevel enum values."""
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.CRITICAL.value == "critical"
        
        # Test that all expected values are present
        expected_values = {"low", "medium", "high", "critical"}
        actual_values = {member.value for member in SeverityLevel}
        assert actual_values == expected_values
    
    def test_event_type_enum(self):
        """Test EventType enum values."""
        expected_events = {
            "approval", "llm_failure", "adapter_invocation",
            "scan_start", "scan_complete", "finding_created",
            "error", "info"
        }
        actual_values = {member.value for member in EventType}
        assert actual_values == expected_events

class TestConfigSetup:
    """Test suite for configuration file setup."""
    
    def test_setup_config_file_creates_file(self):
        """Test that setup_config_file creates the config file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / ".homepentest" / "config.yaml"
            with patch('agent.cli.Path.home', return_value=Path(temp_dir)):
                with patch('typer.echo'):  # Mock echo to avoid output
                    # Create the directory first
                    config_path.parent.mkdir(parents=True, exist_ok=True)
                    setup_config_file()
                    
                    # Check that config file was created
                    assert config_path.exists()
                    
                    # Check that content is not empty
                    content = config_path.read_text()
                    assert len(content) > 0
    
    def test_setup_config_file_existing_file(self):
        """Test that setup_config_file handles existing files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / ".homepentest" / "config.yaml"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create existing config file
            config_path.write_text("existing: config")
            
            with patch('agent.cli.Path.home', return_value=Path(temp_dir)):
                with patch('typer.echo'):  # Mock echo to avoid output
                    setup_config_file()
                    
                    # Check that existing file was not overwritten
                    content = config_path.read_text()
                    assert content == "existing: config"

if __name__ == "__main__":
    pytest.main([__file__])
