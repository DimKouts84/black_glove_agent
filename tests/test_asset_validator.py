"""Tests for format-only asset validation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.asset_validator import AssetValidator, ValidationResult, ValidationStatus, create_asset_validator
from src.agent.models import AssetModel, AssetType, ConfigModel


class TestValidationResult:
    def test_validation_result_creation(self):
        result = ValidationResult(
            status=ValidationStatus.VALID,
            message="Test message",
            suggestions=["suggestion1"],
            is_authorized=True,
        )
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True


class TestAssetValidator:
    def test_asset_validator_factory(self):
        validator = create_asset_validator()
        assert isinstance(validator, AssetValidator)

    def test_validate_ip_valid(self):
        validator = AssetValidator(ConfigModel())
        result = validator.validate_ip("192.168.1.100")
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True

    def test_validate_ip_invalid_format(self):
        validator = AssetValidator(ConfigModel())
        result = validator.validate_ip("not.an.ip.address")
        assert result.status == ValidationStatus.INVALID_FORMAT
        assert result.is_authorized is False

    def test_validate_domain_valid(self):
        validator = AssetValidator(ConfigModel())
        result = validator.validate_domain("example.com")
        assert result.status == ValidationStatus.VALID
        assert result.is_authorized is True

    def test_validate_domain_invalid_format(self):
        validator = AssetValidator(ConfigModel())
        result = validator.validate_domain("invalid-domain")
        assert result.status == ValidationStatus.INVALID_FORMAT
        assert result.is_authorized is False

    def test_validate_asset_host_type(self):
        validator = AssetValidator(ConfigModel())
        asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
        result = validator.validate_asset(asset)
        assert result.status == ValidationStatus.VALID

    def test_validate_asset_domain_type(self):
        validator = AssetValidator(ConfigModel())
        asset = AssetModel(name="test", type=AssetType.DOMAIN, value="example.com")
        result = validator.validate_asset(asset)
        assert result.status == ValidationStatus.VALID

    def test_validate_asset_invalid_type(self):
        validator = AssetValidator(ConfigModel())

        class MockType:
            def __init__(self, value):
                self.value = value

        class MockAsset:
            def __init__(self):
                self.type = MockType("invalid_type")
                self.value = "test"
                self.name = "test"

        result = validator.validate_asset(MockAsset())
        assert result.status == ValidationStatus.INVALID_FORMAT


if __name__ == "__main__":
    pytest.main([__file__])
