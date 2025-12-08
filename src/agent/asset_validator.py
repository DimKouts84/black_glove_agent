"""
Asset validation for Black Glove pentest agent.
Provides validation logic for assets against authorized allowlists.
"""

import logging
import ipaddress
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from .models import AssetModel, ConfigModel


class ValidationStatus(Enum):
    """Enumeration of validation statuses."""
    VALID = "valid"
    INVALID_FORMAT = "invalid_format"
    UNAUTHORIZED = "unauthorized"
    BLOCKED = "blocked"


@dataclass
class ValidationResult:
    """
    Standardized validation result structure.
    
    Attributes:
        status: Validation status
        message: Human-readable validation message
        suggestions: Suggested corrections or alternatives
        is_authorized: Whether the asset is authorized for scanning
    """
    status: ValidationStatus
    message: str
    suggestions: List[str]
    is_authorized: bool


class AllowlistManager:
    """
    Manage IP ranges and domain allowlists for asset validation.
    """
    
    def __init__(self, config: ConfigModel):
        """
        Initialize the allowlist manager.
        
        Args:
            config: Configuration model with allowlist settings
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.asset.allowlist")
        self._authorized_networks: List[ipaddress.IPv4Network] = []
        self._authorized_domains: Set[str] = set()
        self._blocked_targets: Set[str] = set()
        
        # Load allowlists from configuration
        self._load_allowlists()
    
    def _load_allowlists(self) -> None:
        """Load allowlists from configuration."""
        # Load authorized networks
        networks = getattr(self.config, 'authorized_networks', ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'])
        for network_str in networks:
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                self._authorized_networks.append(network)
                self.logger.debug(f"Added authorized network: {network}")
            except ValueError as e:
                self.logger.warning(f"Invalid network in config: {network_str} - {e}")
        
        # Load authorized domains
        domains = getattr(self.config, 'authorized_domains', [])
        self._authorized_domains.update(domains)
        for domain in domains:
            self.logger.debug(f"Added authorized domain: {domain}")
        
        # Load blocked targets
        blocked = getattr(self.config, 'blocked_targets', [])
        self._blocked_targets.update(blocked)
        for target in blocked:
            self.logger.debug(f"Added blocked target: {target}")
    
    def is_ip_authorized(self, ip_address: str) -> bool:
        """
        Check if an IP address is authorized.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if authorized, False otherwise
        """
        # Always return True as per user request to remove authorization restrictions
        return True
    
    def is_domain_authorized(self, domain: str) -> bool:
        """
        Check if a domain is authorized.
        
        Args:
            domain: Domain name to check
            
        Returns:
            bool: True if authorized, False otherwise
        """
        # Always return True as per user request to remove authorization restrictions
        return True
    
    def is_target_authorized(self, target: str) -> bool:
        """
        Check if a target (IP or domain) is authorized.
        
        Args:
            target: Target to check
            
        Returns:
            bool: True if authorized, False otherwise
        """
        # Always return True as per user request to remove authorization restrictions
        return True


class AssetValidator:
    """
    Main validation class for asset management with allowlist checking.
    """
    
    def __init__(self, config: ConfigModel):
        """
        Initialize the asset validator.
        
        Args:
            config: Configuration model with validation settings
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.asset.validator")
        self.allowlist_manager = AllowlistManager(config)
    
    def validate_ip(self, ip_address: str) -> ValidationResult:
        """
        Validate an IP address.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            ValidationResult: Validation result
        """
        # Validate IP format
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                message=f"Invalid IP address format: {ip_address}",
                suggestions=["Ensure the IP address is in valid format (e.g., 192.168.1.1)"],
                is_authorized=False
            )
        
        # Always return authorized
        return ValidationResult(
            status=ValidationStatus.VALID,
            message=f"IP address {ip_address} is valid and authorized",
            suggestions=[],
            is_authorized=True
        )
    
    def validate_domain(self, domain: str) -> ValidationResult:
        """
        Validate a domain name.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            ValidationResult: Validation result
        """
        # Basic domain format validation
        if not domain or '.' not in domain:
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                message=f"Invalid domain format: {domain}",
                suggestions=["Ensure the domain includes at least one dot (e.g., example.com)"],
                is_authorized=False
            )
        
        # Always return authorized
        return ValidationResult(
            status=ValidationStatus.VALID,
            message=f"Domain {domain} is valid and authorized",
            suggestions=[],
            is_authorized=True
        )
    
    def validate_asset(self, asset: AssetModel) -> ValidationResult:
        """
        Validate an asset comprehensively.
        
        Args:
            asset: Asset model to validate
            
        Returns:
            ValidationResult: Validation result
        """
        self.logger.debug(f"Validating asset: {asset.name} ({asset.type.value}: {asset.value})")
        
        # Validate based on asset type
        if asset.type.value == "host":
            # For hosts, validate as IP
            return self.validate_ip(asset.value)
        elif asset.type.value in ["domain", "vm"]:
            # For domains and VMs, validate as domain
            return self.validate_domain(asset.value)
        else:
            return ValidationResult(
                status=ValidationStatus.INVALID_FORMAT,
                message=f"Invalid asset type: {asset.type.value}",
                suggestions=["Use 'host', 'domain', or 'vm'"],
                is_authorized=False
            )
    
    def is_authorized_target(self, target: str) -> bool:
        """
        Check if a target is authorized for scanning.
        
        Args:
            target: Target to check
            
        Returns:
            bool: True if authorized, False otherwise
        """
        return self.allowlist_manager.is_target_authorized(target)


# Factory function for creating asset validator instances
def create_asset_validator(config: ConfigModel = None) -> AssetValidator:
    """
    Factory function to create an asset validator instance.
    
    Args:
        config: Optional configuration model
        
    Returns:
        AssetValidator: Configured asset validator instance
    """
    if config is None:
        config = ConfigModel()
    return AssetValidator(config)
