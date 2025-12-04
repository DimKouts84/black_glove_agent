"""
Tests for Asset Management Implementation

This module contains tests for the asset management functionality including
CLI commands, validation, and database operations.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.models import AssetModel, AssetType, ConfigModel
from src.agent.asset_validator import AssetValidator, ValidationResult, ValidationStatus
from src.agent.db import init_db, get_db_connection, remove_asset


class TestAssetValidator:
    """Test cases for the AssetValidator implementation."""
    
    def test_asset_validator_initialization(self):
        """Test AssetValidator initialization."""
        config = ConfigModel()
        validator = AssetValidator(config)
        
        assert validator.config == config
        assert validator.allowlist_manager is not None
    
    def test_validate_authorized_ip(self):
        """Test validation of authorized IP address."""
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            authorized_domains=[],
            blocked_targets=[]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_ip("192.168.1.100")
        
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
        assert "authorized" in result.message.lower()
    
    def test_validate_unauthorized_ip(self):
        """Test validation of unauthorized IP address."""
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            authorized_domains=[],
            blocked_targets=[]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_ip("10.0.0.1")
        
        assert result.status == ValidationStatus.UNAUTHORIZED
        assert result.is_authorized is False
        assert "not in authorized networks" in result.message
    
    def test_validate_blocked_ip(self):
        """Test validation of blocked IP address."""
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            authorized_domains=[],
            blocked_targets=["192.168.1.100"]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_ip("192.168.1.100")
        
        assert result.status == ValidationStatus.BLOCKED
        assert result.is_authorized is False
        assert "blocked" in result.message.lower()
    
    def test_validate_invalid_ip_format(self):
        """Test validation of invalid IP format."""
        config = ConfigModel()
        validator = AssetValidator(config)
        
        result = validator.validate_ip("invalid.ip.address")
        
        assert result.status == ValidationStatus.INVALID_FORMAT
        assert result.is_authorized is False
        assert "invalid ip address format" in result.message.lower()
    
    def test_validate_authorized_domain(self):
        """Test validation of authorized domain."""
        config = ConfigModel(
            authorized_networks=[],
            authorized_domains=["example.com"],
            blocked_targets=[]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_domain("example.com")
        
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
        assert "authorized" in result.message.lower()
    
    def test_validate_subdomain_authorization(self):
        """Test validation of subdomain authorization."""
        config = ConfigModel(
            authorized_networks=[],
            authorized_domains=["example.com"],
            blocked_targets=[]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_domain("sub.example.com")
        
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
    
    def test_validate_unauthorized_domain(self):
        """Test validation of unauthorized domain."""
        config = ConfigModel(
            authorized_networks=[],
            authorized_domains=["example.com"],
            blocked_targets=[]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_domain("unauthorized.com")
        
        assert result.status == ValidationStatus.UNAUTHORIZED
        assert result.is_authorized is False
        assert "not in authorized domains" in result.message
    
    def test_validate_asset_host_type(self):
        """Test validation of host-type asset."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        validator = AssetValidator(config)
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
        
        result = validator.validate_asset(asset)
        
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
    
    def test_validate_asset_domain_type(self):
        """Test validation of domain-type asset."""
        config = ConfigModel(authorized_domains=["example.com"])
        validator = AssetValidator(config)
        asset = AssetModel(name="test", type=AssetType.DOMAIN, value="example.com")
        
        result = validator.validate_asset(asset)
        
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
    
    def test_is_authorized_target_ip(self):
        """Test is_authorized_target for IP addresses."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        validator = AssetValidator(config)
        
        assert validator.is_authorized_target("192.168.1.50") is True
        assert validator.is_authorized_target("10.0.0.1") is False
    
    def test_is_authorized_target_domain(self):
        """Test is_authorized_target for domains."""
        config = ConfigModel(authorized_domains=["example.com"])
        validator = AssetValidator(config)
        
        assert validator.is_authorized_target("example.com") is True
        assert validator.is_authorized_target("unauthorized.com") is False


class TestDatabaseAssetOperations:
    """Test cases for database asset operations."""
    
    @pytest.fixture(autouse=True)
    def setup_database(self):
        """Set up temporary database for testing."""
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            tmp_db_path = tmp_db.name
        
        # Set database path
        import src.agent.db as db_module
        original_path = db_module.DB_PATH
        db_module.DB_PATH = Path(tmp_db_path)
        
        # Initialize database
        init_db()
        
        yield tmp_db_path
        
        # Cleanup
        db_module.DB_PATH = original_path
        try:
            os.unlink(tmp_db_path)
        except:
            pass
    
    def test_remove_asset_success(self):
        """Test successful asset removal."""
        from src.agent.models import DatabaseManager, AssetModel, AssetType
        
        # Add an asset first
        db_manager = DatabaseManager()
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.1")
        asset_id = db_manager.add_asset(asset)
        
        # Verify asset exists
        retrieved_asset = db_manager.get_asset(asset_id)
        assert retrieved_asset is not None
        
        # Remove asset
        success = db_manager.remove_asset(asset_id)
        assert success is True
        
        # Verify asset is removed
        retrieved_asset = db_manager.get_asset(asset_id)
        assert retrieved_asset is None
    
    def test_remove_asset_not_found(self):
        """Test removal of non-existent asset."""
        from src.agent.models import DatabaseManager
        
        db_manager = DatabaseManager()
        success = db_manager.remove_asset(999999)  # Non-existent ID
        
        assert success is False
    
    def test_add_asset_with_validation(self):
        """Test adding asset with validation."""
        from src.agent.models import DatabaseManager, AssetModel, AssetType
        
        db_manager = DatabaseManager()
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
        asset_id = db_manager.add_asset(asset)
        
        assert asset_id > 0
        
        # Retrieve and verify by ID
        retrieved_asset = db_manager.get_asset(asset_id)
        assert retrieved_asset is not None
        assert retrieved_asset.name == "test"
        assert retrieved_asset.type == AssetType.HOST
        assert retrieved_asset.value == "192.168.1.50"
    
    def test_get_asset_by_name(self):
        """Test retrieving asset by name."""
        from src.agent.models import DatabaseManager, AssetModel, AssetType
        
        db_manager = DatabaseManager()
        asset = AssetModel(name="test-host", type=AssetType.HOST, value="192.168.1.50")
        asset_id = db_manager.add_asset(asset)
        
        # Retrieve by name
        retrieved_asset = db_manager.get_asset_by_name("test-host")
        assert retrieved_asset is not None
        assert retrieved_asset.id == asset_id
        assert retrieved_asset.name == "test-host"
        assert retrieved_asset.type == AssetType.HOST
        assert retrieved_asset.value == "192.168.1.50"
    
    def test_get_asset_by_name_not_found(self):
        """Test retrieving non-existent asset by name."""
        from src.agent.models import DatabaseManager
        
        db_manager = DatabaseManager()
        retrieved_asset = db_manager.get_asset_by_name("non-existent")
        assert retrieved_asset is None


class TestCLIAssetCommands:
    """Test cases for CLI asset commands."""
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment with temporary database."""
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            tmp_db_path = tmp_db.name
        
        # Set database path
        import src.agent.db as db_module
        original_path = db_module.DB_PATH
        db_module.DB_PATH = Path(tmp_db_path)
        
        # Initialize database
        init_db()
        
        yield tmp_db_path
        
        # Cleanup
        db_module.DB_PATH = original_path
        try:
            os.unlink(tmp_db_path)
        except:
            pass
    
    def test_add_asset_command_success(self):
        """Test successful add-asset command."""
        from src.agent.cli import app
        from typer.testing import CliRunner

        runner = CliRunner()

        # Mock configuration to allow the IP
        with patch('src.agent.models.ConfigModel') as mock_config:
            mock_config_instance = MagicMock()
            mock_config_instance.authorized_networks = ["192.168.1.0/24"]
            mock_config_instance.authorized_domains = []
            mock_config_instance.blocked_targets = []
            mock_config.return_value = mock_config_instance

            result = runner.invoke(
                app, 
                ["add-asset", "test-host", "host", "192.168.1.50"],
                input="I AGREE\n"  # For legal notice
            )

            assert result.exit_code == 0
            assert "added successfully" in result.stdout
    
    def test_add_asset_command_unauthorized(self):
        """Test add-asset command with unauthorized target."""
        from src.agent.cli import app
        from typer.testing import CliRunner
        from src.agent.asset_validator import ValidationResult, ValidationStatus
        from src.agent.models import ConfigModel

        runner = CliRunner()

        # Mock load_config to return a config that doesn't authorize 10.0.0.1
        mock_config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],  # 10.0.0.1 is not in this range
            authorized_domains=[],
            blocked_targets=[]
        )
        
        with patch('src.agent.cli.load_config', return_value=mock_config):
            result = runner.invoke(
                app, 
                ["add-asset", "test-host", "host", "10.0.0.1"],
            )

            assert result.exit_code == 1
            assert "validation failed" in result.stdout.lower() or "not in authorized" in result.stdout.lower()
    
    def test_add_asset_command_invalid_type(self):
        """Test add-asset command with invalid asset type."""
        from src.agent.cli import app
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(
            app, 
            ["add-asset", "test-host", "invalid-type", "192.168.1.50"],
            input="I AGREE\n"  # For legal notice
        )

        # The CLI validates asset type first, so should exit with code 1
        # and show an error about invalid asset type
        assert result.exit_code == 1
        assert "invalid" in result.stdout.lower() and "type" in result.stdout.lower()
    
    def test_list_assets_command_empty(self):
        """Test list-assets command with no assets."""
        from src.agent.cli import app
        from typer.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(app, ["list-assets"])

        assert result.exit_code == 0
        assert "no assets found" in result.stdout.lower()
    
    def test_remove_asset_command_success(self):
        """Test successful remove-asset command."""
        from src.agent.cli import app
        from src.agent.models import DatabaseManager, AssetModel, AssetType
        from typer.testing import CliRunner

        # First add an asset
        db_manager = DatabaseManager()
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
        asset_id = db_manager.add_asset(asset)

        runner = CliRunner()
        # Provide input for confirmation prompt
        result = runner.invoke(app, ["remove-asset", str(asset_id)], input="y\n")

        assert result.exit_code == 0
        assert "removed successfully" in result.stdout.lower()
    
    def test_remove_asset_command_not_found(self):
        """Test remove-asset command with non-existent asset."""
        from src.agent.cli import app
        from typer.testing import CliRunner

        runner = CliRunner()
        # Use a very high ID that doesn't exist
        result = runner.invoke(app, ["remove-asset", "999999"])

        # The CLI should indicate asset not found
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()
    
    def test_remove_asset_command_cancelled(self):
        """Test remove-asset command with user cancellation."""
        from src.agent.cli import app
        from src.agent.models import DatabaseManager, AssetModel, AssetType
        from typer.testing import CliRunner

        # First add an asset
        db_manager = DatabaseManager()
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
        asset_id = db_manager.add_asset(asset)

        runner = CliRunner()
        # Provide input for confirmation prompt (n for no)
        result = runner.invoke(app, ["remove-asset", str(asset_id)], input="n\n")

        assert result.exit_code == 0
        assert "cancelled" in result.stdout.lower()


# Integration tests
class TestAssetManagementIntegration:
    """Integration tests for asset management components."""
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment with temporary database."""
        # Create temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            tmp_db_path = tmp_db.name
        
        # Set database path
        import src.agent.db as db_module
        original_path = db_module.DB_PATH
        db_module.DB_PATH = Path(tmp_db_path)
        
        # Initialize database
        init_db()
        
        yield tmp_db_path
        
        # Cleanup
        db_module.DB_PATH = original_path
        try:
            os.unlink(tmp_db_path)
        except:
            pass
    
    def test_complete_asset_lifecycle(self):
        """Test complete asset lifecycle: add -> list -> remove -> list."""
        from src.agent.models import DatabaseManager, AssetModel, AssetType, ConfigModel
        from src.agent.asset_validator import AssetValidator
        
        db_manager = DatabaseManager()
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        validator = AssetValidator(config)
        
        # 1. Add asset
        asset = AssetModel(name="test-host", type=AssetType.HOST, value="192.168.1.50")
        validation_result = validator.validate_asset(asset)
        assert validation_result.is_authorized is True
        
        asset_id = db_manager.add_asset(asset)
        assert asset_id > 0
        
        # 2. List assets (should have 1)
        assets = db_manager.list_assets()
        assert len(assets) == 1
        assert assets[0].name == "test-host"
        assert assets[0].value == "192.168.1.50"
        
        # 3. Remove asset
        success = db_manager.remove_asset(asset_id)
        assert success is True
        
        # 4. List assets (should be empty)
        assets = db_manager.list_assets()
        assert len(assets) == 0
    
    def test_multiple_assets_management(self):
        """Test management of multiple assets."""
        from src.agent.models import DatabaseManager, AssetModel, AssetType, ConfigModel
        from src.agent.asset_validator import AssetValidator
        
        db_manager = DatabaseManager()
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            authorized_domains=["example.com"]
        )
        validator = AssetValidator(config)
        
        # Add multiple assets
        assets_data = [
            ("host1", AssetType.HOST, "192.168.1.10"),
            ("host2", AssetType.HOST, "192.168.1.20"),
            ("domain1", AssetType.DOMAIN, "example.com")
        ]
        
        asset_ids = []
        for name, asset_type, value in assets_data:
            asset = AssetModel(name=name, type=asset_type, value=value)
            validation_result = validator.validate_asset(asset)
            if validation_result.is_authorized:
                asset_id = db_manager.add_asset(asset)
                asset_ids.append(asset_id)
        
        # Verify all assets added (should be 3 now with proper domain config)
        assets = db_manager.list_assets()
        assert len(assets) == 3
        
        # Remove one asset
        success = db_manager.remove_asset(asset_ids[0])
        assert success is True
        
        # Verify remaining assets
        assets = db_manager.list_assets()
        assert len(assets) == 2


if __name__ == "__main__":
    pytest.main([__file__])
