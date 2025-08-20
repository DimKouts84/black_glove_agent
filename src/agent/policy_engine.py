"""
Policy Engine for Black Glove Pentest Agent

This module implements the safety and compliance rule enforcement system
that ensures all operations adhere to defined security policies and constraints.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import re

from .models import Asset


class PolicyViolationType(Enum):
    """Enumeration of policy violation types."""
    UNAUTHORIZED_TARGET = "unauthorized_target"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    EXPLOIT_NOT_ALLOWED = "exploit_not_allowed"
    INVALID_ASSET = "invalid_asset"
    CONFIGURATION_ERROR = "configuration_error"


@dataclass
class PolicyRule:
    """
    Represents a safety policy rule.
    
    Attributes:
        name: Rule name for identification
        description: Human-readable rule description
        enabled: Whether the rule is active
        priority: Rule priority (higher numbers = higher priority)
        conditions: Conditions that trigger the rule
        actions: Actions to take when rule is violated
        violation_type: Type of violation this rule detects
    """
    name: str
    description: str
    enabled: bool = True
    priority: int = 0
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[str] = field(default_factory=list)
    violation_type: PolicyViolationType = PolicyViolationType.UNAUTHORIZED_TARGET


@dataclass
class PolicyViolation:
    """
    Represents a policy violation event.
    
    Attributes:
        rule_name: Name of the violated rule
        violation_type: Type of violation
        target: Target that violated the policy
        timestamp: When the violation occurred
        details: Additional violation details
        severity: Violation severity level
    """
    rule_name: str
    violation_type: PolicyViolationType
    target: str
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "medium"


class RateLimiter:
    """
    Implements rate limiting controls for scan operations.
    
    Tracks request rates per adapter and globally to prevent
    overwhelming targets or violating service agreements.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the rate limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.policy.rate_limiter")
        self._request_counts: Dict[str, List[float]] = {}
        self._global_requests: List[float] = []
    
    def check_rate_limit(self, adapter_name: str = None) -> bool:
        """
        Check if rate limit would be exceeded for an adapter.
        
        Args:
            adapter_name: Name of the adapter to check, or None for global limit
            
        Returns:
            bool: True if request is allowed, False if rate limited
        """
        now = time.time()
        window_size = self.config.get("window_size", 60)  # seconds
        max_requests = self.config.get("max_requests", 10)
        
        if adapter_name:
            # Check adapter-specific rate limit
            key = f"adapter_{adapter_name}"
            requests = self._request_counts.setdefault(key, [])
        else:
            # Check global rate limit
            requests = self._global_requests
            max_requests = self.config.get("global_max_requests", 100)
        
        # Remove old requests outside the window
        cutoff_time = now - window_size
        requests[:] = [req_time for req_time in requests if req_time > cutoff_time]
        
        # Check if we're within limits
        return len(requests) < max_requests
    
    def record_request(self, adapter_name: str = None) -> None:
        """
        Record a request for rate limiting purposes.
        
        Args:
            adapter_name: Name of the adapter that made the request
        """
        now = time.time()
        
        if adapter_name:
            key = f"adapter_{adapter_name}"
            requests = self._request_counts.setdefault(key, [])
            requests.append(now)
        
        self._global_requests.append(now)
    
    def get_current_rate(self, adapter_name: str = None) -> float:
        """
        Get current request rate for an adapter or globally.
        
        Args:
            adapter_name: Name of the adapter, or None for global rate
            
        Returns:
            float: Requests per second
        """
        now = time.time()
        window_size = self.config.get("window_size", 60)
        cutoff_time = now - window_size
        
        if adapter_name:
            key = f"adapter_{adapter_name}"
            requests = self._request_counts.get(key, [])
        else:
            requests = self._global_requests
        
        recent_requests = [req_time for req_time in requests if req_time > cutoff_time]
        return len(recent_requests) / window_size


class TargetValidator:
    """
    Validates scan targets against authorized asset lists and IP ranges.
    
    Ensures that only authorized targets are scanned to prevent
    accidental scanning of unauthorized systems.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the target validator.
        
        Args:
            config: Target validation configuration
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.policy.target_validator")
        self._authorized_networks: List[ipaddress.IPv4Network] = []
        self._authorized_domains: Set[str] = set()
        self._blocked_targets: Set[str] = set()
        
        # Load authorized networks
        self._load_authorized_networks()
        self._load_authorized_domains()
        self._load_blocked_targets()
    
    def _load_authorized_networks(self) -> None:
        """Load authorized IP networks from configuration."""
        networks = self.config.get("authorized_networks", [])
        for network_str in networks:
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                self._authorized_networks.append(network)
                self.logger.debug(f"Added authorized network: {network}")
            except ValueError as e:
                self.logger.warning(f"Invalid network in config: {network_str} - {e}")
    
    def _load_authorized_domains(self) -> None:
        """Load authorized domains from configuration."""
        domains = self.config.get("authorized_domains", [])
        self._authorized_domains.update(domains)
        for domain in domains:
            self.logger.debug(f"Added authorized domain: {domain}")
    
    def _load_blocked_targets(self) -> None:
        """Load explicitly blocked targets from configuration."""
        blocked = self.config.get("blocked_targets", [])
        self._blocked_targets.update(blocked)
        for target in blocked:
            self.logger.debug(f"Added blocked target: {target}")
    
    def validate_ip_target(self, ip_address: str) -> bool:
        """
        Validate an IP address target.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            bool: True if target is authorized, False otherwise
        """
        # Check if explicitly blocked
        if ip_address in self._blocked_targets:
            return False
        
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            self.logger.warning(f"Invalid IP address format: {ip_address}")
            return False
        
        # Check if in authorized networks
        for network in self._authorized_networks:
            if ip in network:
                return True
        
        self.logger.warning(f"IP address not in authorized networks: {ip_address}")
        return False
    
    def validate_domain_target(self, domain: str) -> bool:
        """
        Validate a domain target.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            bool: True if target is authorized, False otherwise
        """
        # Check if explicitly blocked
        if domain in self._blocked_targets:
            return False
        
        # Check if in authorized domains
        if domain in self._authorized_domains:
            return True
        
        # Check for subdomain matches
        for authorized_domain in self._authorized_domains:
            if domain.endswith(f".{authorized_domain}") or domain == authorized_domain:
                return True
        
        self.logger.warning(f"Domain not in authorized list: {domain}")
        return False
    
    def validate_target(self, target: str) -> bool:
        """
        Validate a target (IP or domain).
        
        Args:
            target: Target to validate
            
        Returns:
            bool: True if target is authorized, False otherwise
        """
        # Try to parse as IP first
        try:
            ipaddress.ip_address(target)
            return self.validate_ip_target(target)
        except ValueError:
            # Not an IP, treat as domain
            return self.validate_domain_target(target)


class PolicyEngine:
    """
    Central safety rule enforcement system for the pentest agent.
    
    Manages policy rules, validates assets, enforces rate limits,
    and handles exploit permissions with comprehensive audit logging.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the policy engine.
        
        Args:
            config: Policy engine configuration
        """
        self.config = config
        self.logger = logging.getLogger("black_glove.policy.engine")
        self.rules: List[PolicyRule] = []
        self.violations: List[PolicyViolation] = []
        
        # Initialize components
        self.rate_limiter = RateLimiter(config.get("rate_limiting", {}))
        self.target_validator = TargetValidator(config.get("target_validation", {}))
        
        # Load default rules
        self._load_default_rules()
        
        self.logger.info("Policy engine initialized")
    
    def _load_default_rules(self) -> None:
        """Load default safety policy rules."""
        default_rules = [
            PolicyRule(
                name="authorized_target_check",
                description="Ensure all targets are in authorized networks/domains",
                priority=100,
                violation_type=PolicyViolationType.UNAUTHORIZED_TARGET
            ),
            PolicyRule(
                name="rate_limit_check",
                description="Prevent exceeding rate limits for scans",
                priority=90,
                violation_type=PolicyViolationType.RATE_LIMIT_EXCEEDED
            ),
            PolicyRule(
                name="exploit_permission_check",
                description="Validate exploit usage permissions",
                priority=80,
                violation_type=PolicyViolationType.EXPLOIT_NOT_ALLOWED
            )
        ]
        self.rules.extend(default_rules)
        self.logger.debug(f"Loaded {len(default_rules)} default policy rules")
    
    def validate_asset(self, asset: Asset) -> bool:
        """
        Check asset authorization and safety.
        
        Args:
            asset: Asset to validate
            
        Returns:
            bool: True if asset is valid and authorized, False otherwise
        """
        self.logger.debug(f"Validating asset: {asset.target}")
        
        # Check if target is authorized
        if not self.target_validator.validate_target(asset.target):
            violation = PolicyViolation(
                rule_name="authorized_target_check",
                violation_type=PolicyViolationType.UNAUTHORIZED_TARGET,
                target=asset.target,
                timestamp=datetime.now(),
                details={"reason": "Target not in authorized networks/domains"},
                severity="high"
            )
            self.log_violation(violation)
            return False
        
        # Check rate limits
        if not self.enforce_rate_limits(adapter_name=asset.tool_name):
            violation = PolicyViolation(
                rule_name="rate_limit_check",
                violation_type=PolicyViolationType.RATE_LIMIT_EXCEEDED,
                target=asset.target,
                timestamp=datetime.now(),
                details={"reason": "Rate limit would be exceeded"},
                severity="medium"
            )
            self.log_violation(violation)
            return False
        
        self.logger.info(f"Asset validation passed for: {asset.target}")
        return True
    
    def enforce_rate_limits(self, adapter_name: str = None) -> bool:
        """
        Apply rate limiting to scans.
        
        Args:
            adapter_name: Name of the adapter to check limits for
            
        Returns:
            bool: True if request is allowed, False if rate limited
        """
        allowed = self.rate_limiter.check_rate_limit(adapter_name)
        
        if not allowed:
            self.logger.warning(
                f"Rate limit exceeded for adapter: {adapter_name or 'global'}"
            )
        
        return allowed
    
    def check_exploit_permissions(self, exploit_name: str, lab_mode: bool = False) -> bool:
        """
        Validate lab mode for exploits.
        
        Args:
            exploit_name: Name of the exploit to check
            lab_mode: Whether agent is in lab/controlled environment mode
            
        Returns:
            bool: True if exploit is allowed, False otherwise
        """
        # In lab mode, all exploits are allowed
        if lab_mode:
            self.logger.debug(f"Exploit {exploit_name} allowed in lab mode")
            return True
        
        # Check if exploit is in allowed list
        allowed_exploits = self.config.get("allowed_exploits", [])
        if exploit_name in allowed_exploits:
            self.logger.debug(f"Exploit {exploit_name} found in allowed list")
            return True
        
        # Log violation for unauthorized exploit
        violation = PolicyViolation(
            rule_name="exploit_permission_check",
            violation_type=PolicyViolationType.EXPLOIT_NOT_ALLOWED,
            target=exploit_name,
            timestamp=datetime.now(),
            details={"reason": "Exploit not in allowed list and not in lab mode"},
            severity="high"
        )
        self.log_violation(violation)
        
        self.logger.warning(f"Unauthorized exploit attempt: {exploit_name}")
        return False
    
    def validate_target(self, target: str) -> bool:
        """
        Ensure target is in allowed ranges.
        
        Args:
            target: Target to validate
            
        Returns:
            bool: True if target is authorized, False otherwise
        """
        return self.target_validator.validate_target(target)
    
    def log_violation(self, violation: PolicyViolation) -> None:
        """
        Record policy violations in audit log.
        
        Args:
            violation: Policy violation to log
        """
        self.violations.append(violation)
        
        # Log to audit system
        self.logger.warning(
            f"Policy violation: {violation.rule_name} - "
            f"Target: {violation.target} - "
            f"Type: {violation.violation_type.value} - "
            f"Severity: {violation.severity}"
        )
        
        # Additional logging for high severity violations
        if violation.severity == "high":
            self.logger.error(
                f"HIGH SEVERITY VIOLATION: {violation.rule_name} on {violation.target}"
            )
    
    def get_violation_report(self) -> List[Dict[str, Any]]:
        """
        Get a report of all policy violations.
        
        Returns:
            List of violation dictionaries for reporting
        """
        return [
            {
                "rule_name": violation.rule_name,
                "violation_type": violation.violation_type.value,
                "target": violation.target,
                "timestamp": violation.timestamp.isoformat(),
                "details": violation.details,
                "severity": violation.severity
            }
            for violation in self.violations
        ]
    
    def get_current_rates(self) -> Dict[str, float]:
        """
        Get current request rates for monitoring.
        
        Returns:
            Dict mapping adapter names to request rates
        """
        rates = {
            "global": self.rate_limiter.get_current_rate()
        }
        
        # Add adapter-specific rates
        for key in self.rate_limiter._request_counts.keys():
            if key.startswith("adapter_"):
                adapter_name = key[8:]  # Remove "adapter_" prefix
                rates[adapter_name] = self.rate_limiter.get_current_rate(adapter_name)
        
        return rates
    
    def add_rule(self, rule: PolicyRule) -> None:
        """
        Add a new policy rule.
        
        Args:
            rule: Policy rule to add
        """
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        self.logger.info(f"Added policy rule: {rule.name}")
    
    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove a policy rule by name.
        
        Args:
            rule_name: Name of the rule to remove
            
        Returns:
            bool: True if rule was removed, False if not found
        """
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                removed_rule = self.rules.pop(i)
                self.logger.info(f"Removed policy rule: {removed_rule.name}")
                return True
        return False


# Factory function for creating policy engine instances
def create_policy_engine(config: Dict[str, Any] = None) -> PolicyEngine:
    """
    Factory function to create a policy engine instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        PolicyEngine: Configured policy engine instance
    """
    if config is None:
        config = {
            "rate_limiting": {
                "window_size": 60,
                "max_requests": 10,
                "global_max_requests": 100
            },
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": ["example.com"],
                "blocked_targets": ["192.168.1.1"]
            },
            "allowed_exploits": ["test_exploit"]
        }
    return PolicyEngine(config)
