"""
Tests for Asset Validator Implementation

This module contains focused tests for the asset validation logic and allowlist management.
"""

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.asset_validator import (
    AssetValidator, AllowlistManager, ValidationResult, ValidationStatus
)
from src.agent.models import ConfigModel, AssetModel, AssetType


class TestValidationResult:
    """Test cases for ValidationResult dataclass."""
    
    def test_validation_result_creation(self):
        """Test ValidationResult creation and default values."""
        result = ValidationResult(
            status=ValidationStatus.VALID,
            message="Test message",
            suggestions=["suggestion1", "suggestion2"],
            is_authorized=True
        )
        
        assert result.status == ValidationStatus.VALID
        assert result.message == "Test message"
        assert result.suggestions == ["suggestion1", "suggestion2"]
        assert result.is_authorized is True


class TestAllowlistManager:
    """Test cases for AllowlistManager implementation."""
    
    def test_allowlist_manager_initialization(self):
        """Test AllowlistManager initialization with default config."""
        config = ConfigModel()
        manager = AllowlistManager(config)
        
        assert manager.config == config
        assert len(manager._authorized_networks) > 0  # Should have default networks
        assert isinstance(manager._authorized_domains, set)
        assert isinstance(manager._blocked_targets, set)
    
    def test_allowlist_manager_custom_config(self):
        """Test AllowlistManager with custom configuration."""
        config = ConfigModel(
            authorized_networks=["10.0.0.0/8"],
            authorized_domains=["test.com"],
            blocked_targets=["10.0.0.1"]
        )
        manager = AllowlistManager(config)
        
        assert len(manager._authorized_networks) == 1
        assert "test.com" in manager._authorized_domains
        assert "10.0.0.1" in manager._blocked_targets
    
    def test_is_ip_authorized_success(self):
        """Test successful IP authorization check."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        manager = AllowlistManager(config)
        
        assert manager.is_ip_authorized("192.168.1.100") is True
        assert manager.is_ip_authorized("192.168.1.1") is True
    
    def test_is_ip_authorized_failure(self):
        """Test failed IP authorization check."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        manager = AllowlistManager(config)
        
        assert manager.is_ip_authorized("10.0.0.1") is False
        assert manager.is_ip_authorized("172.16.0.1") is False
    
    def test_is_ip_authorized_blocked(self):
        """Test blocked IP authorization check."""
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            blocked_targets=["192.168.1.100"]
        )
        manager = AllowlistManager(config)
        
        assert manager.is_ip_authorized("192.168.1.100") is False  # Blocked
        assert manager.is_ip_authorized("192.168.1.101") is True   # Authorized
    
    def test_is_ip_authorized_invalid_format(self):
        """Test IP authorization with invalid format."""
        config = ConfigModel()
        manager = AllowlistManager(config)
        
        assert manager.is_ip_authorized("invalid.ip") is False
        assert manager.is_ip_authorized("") is False
    
    def test_is_domain_authorized_success(self):
        """Test successful domain authorization check."""
        config = ConfigModel(authorized_domains=["example.com"])
        manager = AllowlistManager(config)
        
        assert manager.is_domain_authorized("example.com") is True
        assert manager.is_domain_authorized("sub.example.com") is True
    
    def test_is_domain_authorized_failure(self):
        """Test failed domain authorization check."""
        config = ConfigModel(authorized_domains=["example.com"])
        manager = AllowlistManager(config)
        
        assert manager.is_domain_authorized("unauthorized.com") is False
        assert manager.is_domain_authorized("example.org") is False
    
    def test_is_domain_authorized_blocked(self):
        """Test blocked domain authorization check."""
        config = ConfigModel(
            authorized_domains=["example.com"],
            blocked_targets=["blocked.example.com"]
        )
        manager = AllowlistManager(config)
        
        assert manager.is_domain_authorized("blocked.example.com") is False  # Blocked
        assert manager.is_domain_authorized("example.com") is True           # Authorized
    
    def test_is_target_authorized_ip(self):
        """Test target authorization for IP addresses."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        manager = AllowlistManager(config)
        
        assert manager.is_target_authorized("192.168.1.50") is True
        assert manager.is_target_authorized("10.0.0.1") is False
    
    def test_is_target_authorized_domain(self):
        """Test target authorization for domains."""
        config = ConfigModel(authorized_domains=["example.com"])
        manager = AllowlistManager(config)
        
        assert manager.is_target_authorized("example.com") is True
        assert manager.is_target_authorized("unauthorized.com") is False


class TestAssetValidator:
    """Test cases for AssetValidator implementation."""
    
    def test_asset_validator_factory(self):
        """Test asset validator factory function."""
        from src.agent.asset_validator import create_asset_validator
        
        validator = create_asset_validator()
        assert isinstance(validator, AssetValidator)
        assert validator.config is not None
    
    def test_asset_validator_with_custom_config(self):
        """Test asset validator with custom configuration."""
        config = ConfigModel(authorized_networks=["10.0.0.0/8"])
        validator = AssetValidator(config)
        
        assert validator.config == config
        assert validator.allowlist_manager is not None
    
    def test_validate_ip_valid_authorized(self):
        """Test validation of valid and authorized IP."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        validator = AssetValidator(config)
        
        result = validator.validate_ip("192.168.1.100")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
        assert "authorized" in result.message.lower()
    
    def test_validate_ip_valid_unauthorized(self):
        """Test validation of valid but unauthorized IP."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        validator = AssetValidator(config)
        
        result = validator.validate_ip("10.0.0.1")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.UNAUTHORIZED
        assert result.is_authorized is False
        assert "not in authorized networks" in result.message
    
    def test_validate_ip_blocked(self):
        """Test validation of blocked IP."""
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            blocked_targets=["192.168.1.100"]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_ip("192.168.1.100")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.BLOCKED
        assert result.is_authorized is False
        assert "blocked" in result.message.lower()
    
    def test_validate_ip_invalid_format(self):
        """Test validation of invalid IP format."""
        config = ConfigModel()
        validator = AssetValidator(config)
        
        result = validator.validate_ip("not.an.ip.address")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.INVALID_FORMAT
        assert result.is_authorized is False
        assert "invalid ip address format" in result.message.lower()
    
    def test_validate_domain_valid_authorized(self):
        """Test validation of valid and authorized domain."""
        config = ConfigModel(authorized_domains=["example.com"])
        validator = AssetValidator(config)
        
        result = validator.validate_domain("example.com")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
        assert "authorized" in result.message.lower()
    
    def test_validate_domain_valid_unauthorized(self):
        """Test validation of valid but unauthorized domain."""
        config = ConfigModel(authorized_domains=["example.com"])
        validator = AssetValidator(config)
        
        result = validator.validate_domain("unauthorized.com")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.UNAUTHORIZED
        assert result.is_authorized is False
        assert "not in authorized domains" in result.message
    
    def test_validate_domain_blocked(self):
        """Test validation of blocked domain."""
        config = ConfigModel(
            authorized_domains=["example.com"],
            blocked_targets=["blocked.com"]
        )
        validator = AssetValidator(config)
        
        result = validator.validate_domain("blocked.com")
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.BLOCKED
        assert result.is_authorized is False
        assert "blocked" in result.message.lower()
    
    def test_validate_domain_invalid_format(self):
        """Test validation of invalid domain format."""
        config = ConfigModel()
        validator = AssetValidator(config)
        
        result = validator.validate_domain("invalid-domain")  # No dot
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.INVALID_FORMAT
        assert result.is_authorized is False
        assert "invalid domain format" in result.message.lower()
    
    def test_validate_asset_host_type(self):
        """Test validation of host-type asset."""
        config = ConfigModel(authorized_networks=["192.168.1.0/24"])
        validator = AssetValidator(config)
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
        
        result = validator.validate_asset(asset)
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
    
    def test_validate_asset_domain_type(self):
        """Test validation of domain-type asset."""
        config = ConfigModel(authorized_domains=["example.com"])
        validator = AssetValidator(config)
        asset = AssetModel(name="test", type=AssetType.DOMAIN, value="example.com")
        
        result = validator.validate_asset(asset)
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
    
    def test_validate_asset_vm_type(self):
        """Test validation of VM-type asset."""
        config = ConfigModel(authorized_domains=["vm.example.com"])
        validator = AssetValidator(config)
        asset = AssetModel(name="test", type=AssetType.VM, value="vm.example.com")
        
        result = validator.validate_asset(asset)
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True
    
    def test_validate_asset_invalid_type(self):
        """Test validation of asset with invalid type."""
        config = ConfigModel()
        validator = AssetValidator(config)
        
        # For testing purposes, let's test the validator's response to invalid types
        # by directly calling the validation method with an invalid type
        class MockAsset:
            def __init__(self, type_value, value):
                self.type = MockType(type_value)
                self.value = value
                self.name = "test"
        
        class MockType:
            def __init__(self, value):
                self.value = value
        
        mock_asset = MockAsset("invalid_type", "test")
        result = validator.validate_asset(mock_asset)
        
        assert isinstance(result, ValidationResult)
        assert result.status == ValidationStatus.INVALID_FORMAT
        assert result.is_authorized is False
        assert "invalid asset type" in result.message.lower()
    
    def test_is_authorized_target(self):
        """Test is_authorized_target method."""
        config = ConfigModel(
            authorized_networks=["192.168.1.0/24"],
            authorized_domains=["example.com"]
        )
        validator = AssetValidator(config)
        
        assert validator.is_authorized_target("192.168.1.50") is True
        assert validator.is_authorized_target("example.com") is True
        assert validator.is_authorized_target("10.0.0.1") is False
        assert validator.is_authorized_target("unauthorized.com") is False


if __name__ == "__main__":
    pytest.main([__file__])
