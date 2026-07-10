"""
Asset validation for Black Glove pentest agent.
Provides format validation for assets (no allowlist enforcement).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import Enum
from typing import List

from .models import AssetModel, ConfigModel
from .target_scope import is_valid_domain_format, strip_host


class ValidationStatus(str, Enum):
    """Enumeration of validation statuses."""

    VALID = "valid"
    INVALID_FORMAT = "invalid_format"


@dataclass
class ValidationResult:
    """Standardized validation result structure."""

    status: ValidationStatus
    message: str
    suggestions: List[str]
    is_authorized: bool


class AssetValidator:
    """Validate asset format before persistence or scanning."""

    def __init__(self, config: ConfigModel):
        self.config = config
        self.logger = logging.getLogger("black_glove.asset.validator")

    def validate_ip(self, ip_address: str) -> ValidationResult:
        try:
            ipaddress.ip_address(strip_host(ip_address))
        except ValueError:
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                message=f"Invalid IP address format: {ip_address}",
                suggestions=["Ensure the IP address is in valid format (e.g., 192.168.1.1)"],
                is_authorized=False,
            )

        return ValidationResult(
            status=ValidationStatus.VALID,
            message=f"IP address {ip_address} is valid",
            suggestions=[],
            is_authorized=True,
        )

    def validate_domain(self, domain: str) -> ValidationResult:
        if not domain or not is_valid_domain_format(domain):
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                message=f"Invalid domain format: {domain}",
                suggestions=["Ensure the domain includes at least one dot (e.g., example.com)"],
                is_authorized=False,
            )

        return ValidationResult(
            status=ValidationStatus.VALID,
            message=f"Domain {domain} is valid",
            suggestions=[],
            is_authorized=True,
        )

    def validate_asset(self, asset: AssetModel) -> ValidationResult:
        self.logger.debug(f"Validating asset: {asset.name} ({asset.type.value}: {asset.value})")

        if asset.type.value == "host":
            return self.validate_ip(asset.value)
        if asset.type.value in ["domain", "vm"]:
            return self.validate_domain(asset.value)

        return ValidationResult(
            status=ValidationStatus.INVALID_FORMAT,
            message=f"Invalid asset type: {asset.type.value}",
            suggestions=["Use 'host', 'domain', or 'vm'"],
            is_authorized=False,
        )


def create_asset_validator(config: ConfigModel = None) -> AssetValidator:
    if config is None:
        from .models import load_config_from_file

        config = load_config_from_file()
    return AssetValidator(config)
