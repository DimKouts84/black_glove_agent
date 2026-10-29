"""
Asset validation for Black Glove pentest agent.
Provides format validation for assets (no allowlist enforcement).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

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
    scope_warning: Optional[str] = None


class AssetValidator:
    """Validate asset format before persistence or scanning."""

    def __init__(self, config: ConfigModel):
        self.config = config
        self.logger = logging.getLogger("black_glove.asset.validator")

    def _ip_in_authorized_networks(self, ip_address: str) -> bool:
        networks = self.config.authorized_networks or []
        if not networks:
            return True
        try:
            addr = ipaddress.ip_address(strip_host(ip_address))
        except ValueError:
            return True
        for net_str in networks:
            try:
                if "/" in net_str:
                    if addr in ipaddress.ip_network(net_str, strict=False):
                        return True
                elif addr == ipaddress.ip_address(strip_host(net_str)):
                    return True
            except ValueError:
                continue
        return False

    def _target_is_blocked(self, target: str) -> bool:
        blocked = self.config.blocked_targets or []
        if not blocked:
            return False
        host = strip_host(target)
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return any(host.lower() == strip_host(b).lower() for b in blocked)
        for entry in blocked:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(strip_host(entry)):
                    return True
            except ValueError:
                if host.lower() == strip_host(entry).lower():
                    return True
        return False

    def check_target_scope(self, target: str) -> Optional[str]:
        """Return a warn-only scope message when target is blocked or out of scope."""
        if not target:
            return None
        host = strip_host(target)
        if self._target_is_blocked(host):
            return f"Target {host} is in blocked_targets; proceeding with warn-only scope policy."
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        if self.config.authorized_networks and not self._ip_in_authorized_networks(host):
            nets = ", ".join(self.config.authorized_networks)
            return (
                f"Target {host} is outside authorized_networks ({nets}); "
                "proceeding with warn-only scope policy."
            )
        return None

    def warn_scope_if_needed(
        self,
        target: str,
        *,
        adapter: str,
        params: Optional[dict] = None,
    ) -> Optional[str]:
        """Emit audit event and log when target is out of scope (non-blocking)."""
        warning = self.check_target_scope(target)
        if not warning:
            return None
        from .audit import write_audit

        write_audit(
            "scope_warning",
            {
                "adapter": adapter,
                "target": strip_host(target),
                "message": warning,
                "params": params or {},
            },
        )
        self.logger.warning(warning)
        return warning

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

        scope_warning = self.check_target_scope(ip_address)
        suggestions = []
        if scope_warning:
            suggestions.append(scope_warning)

        return ValidationResult(
            status=ValidationStatus.VALID,
            message=f"IP address {ip_address} is valid",
            suggestions=suggestions,
            is_authorized=True,
            scope_warning=scope_warning,
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
