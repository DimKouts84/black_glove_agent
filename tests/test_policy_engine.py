"""
Tests for Policy Engine Implementation

This module contains tests for the policy engine, rate limiter, target validator,
and related safety control components.
"""

import pytest
import time
from datetime import datetime
from typing import Dict, Any
import ipaddress

from src.agent.policy_engine import (
    PolicyEngine, PolicyRule, PolicyViolation, PolicyViolationType,
    RateLimiter, TargetValidator, create_policy_engine
)
from src.agent.models import Asset


class TestPolicyViolationTypes:
    """Test cases for policy violation types."""
    
    def test_policy_violation_types_enum(self):
        """Test policy violation type enumeration values."""
        assert PolicyViolationType.UNAUTHORIZED_TARGET.value == "unauthorized_target"
        assert PolicyViolationType.RATE_LIMIT_EXCEEDED.value == "rate_limit_exceeded"
        assert PolicyViolationType.EXPLOIT_NOT_ALLOWED.value == "exploit_not_allowed"
        assert PolicyViolationType.INVALID_ASSET.value == "invalid_asset"
        assert PolicyViolationType.CONFIGURATION_ERROR.value == "configuration_error"


class TestRateLimiter:
    """Test cases for the RateLimiter implementation."""
    
    def test_rate_limiter_initialization(self):
        """Test RateLimiter initialization."""
        config = {"window_size": 60, "max_requests": 10}
        limiter = RateLimiter(config)
        
        assert limiter.config == config
        assert limiter._request_counts == {}
        assert limiter._global_requests == []
    
    def test_rate_limiter_check_rate_limit(self):
        """Test rate limit checking."""
        config = {"window_size": 1, "max_requests": 2}  # 2 requests per second
        limiter = RateLimiter(config)
        
        # Should allow first request
        assert limiter.check_rate_limit("test_adapter") is True
        
        # Record the request
        limiter.record_request("test_adapter")
        
        # Should allow second request
        assert limiter.check_rate_limit("test_adapter") is True
        
        # Record second request
        limiter.record_request("test_adapter")
        
        # Should reject third request (rate limited)
        assert limiter.check_rate_limit("test_adapter") is False
    
    def test_rate_limiter_global_limits(self):
        """Test global rate limiting."""
        config = {"window_size": 1, "global_max_requests": 1}
        limiter = RateLimiter(config)
        
        # Should allow first global request
        assert limiter.check_rate_limit() is True
        
        # Record request
        limiter.record_request()
        
        # Should reject second global request
        assert limiter.check_rate_limit() is False
    
    def test_rate_limiter_get_current_rate(self):
        """Test getting current request rates."""
        config = {"window_size": 1, "max_requests": 10}
        limiter = RateLimiter(config)
        
        # Initially zero rate
        assert limiter.get_current_rate("test_adapter") == 0.0
        assert limiter.get_current_rate() == 0.0
        
        # Record some requests
        limiter.record_request("test_adapter")
        limiter.record_request("test_adapter")
        
        # Rate should be positive
        rate = limiter.get_current_rate("test_adapter")
        assert rate > 0.0


class TestTargetValidator:
    """Test cases for the TargetValidator implementation."""
    
    def test_target_validator_initialization(self):
        """Test TargetValidator initialization."""
        config = {
            "authorized_networks": ["192.168.1.0/24"],
            "authorized_domains": ["example.com"],
            "blocked_targets": ["192.168.1.100"]
        }
        validator = TargetValidator(config)
        
        assert len(validator._authorized_networks) == 1
        assert "example.com" in validator._authorized_domains
        assert "192.168.1.100" in validator._blocked_targets
    
    def test_target_validator_ip_validation(self):
        """Test IP address target validation."""
        config = {
            "authorized_networks": ["192.168.1.0/24"],
            "authorized_domains": [],
            "blocked_targets": ["192.168.1.100"]
        }
        validator = TargetValidator(config)
        
        # Authorized IP
        assert validator.validate_ip_target("192.168.1.50") is True
        
        # Unauthorized IP
        assert validator.validate_ip_target("10.0.0.1") is False
        
        # Blocked IP
        assert validator.validate_ip_target("192.168.1.100") is False
        
        # Invalid IP format
        assert validator.validate_ip_target("invalid.ip") is False
    
    def test_target_validator_domain_validation(self):
        """Test domain target validation."""
        config = {
            "authorized_networks": [],
            "authorized_domains": ["example.com", "test.org"],
            "blocked_targets": ["blocked.example.com"]
        }
        validator = TargetValidator(config)
        
        # Authorized domain
        assert validator.validate_domain_target("example.com") is True
        assert validator.validate_domain_target("sub.example.com") is True
        
        # Unauthorized domain
        assert validator.validate_domain_target("unauthorized.com") is False
        
        # Blocked domain
        assert validator.validate_domain_target("blocked.example.com") is False
    
    def test_target_validator_general_validation(self):
        """Test general target validation."""
        config = {
            "authorized_networks": ["192.168.1.0/24"],
            "authorized_domains": ["example.com"],
            "blocked_targets": []
        }
        validator = TargetValidator(config)
        
        # IP target
        assert validator.validate_target("192.168.1.50") is True
        assert validator.validate_target("10.0.0.1") is False
        
        # Domain target
        assert validator.validate_target("example.com") is True
        assert validator.validate_target("unauthorized.com") is False


class TestPolicyEngine:
    """Test cases for the PolicyEngine implementation."""
    
    def test_policy_engine_initialization(self):
        """Test PolicyEngine initialization."""
        config = {
            "rate_limiting": {"window_size": 60, "max_requests": 10},
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": ["example.com"]
            },
            "allowed_exploits": ["test_exploit"]
        }
        engine = create_policy_engine(config)
        
        assert engine.config == config
        assert len(engine.rules) > 0
        assert isinstance(engine.rate_limiter, RateLimiter)
        assert isinstance(engine.target_validator, TargetValidator)
    
    def test_policy_engine_default_rules(self):
        """Test default policy rules loading."""
        engine = create_policy_engine()
        
        rule_names = [rule.name for rule in engine.rules]
        assert "authorized_target_check" in rule_names
        assert "rate_limit_check" in rule_names
        assert "exploit_permission_check" in rule_names
    
    def test_policy_engine_asset_validation(self):
        """Test asset validation."""
        config = {
            "rate_limiting": {"window_size": 60, "max_requests": 10},
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": ["example.com"]
            },
            "allowed_exploits": []
        }
        engine = create_policy_engine(config)
        
        # Valid asset
        valid_asset = Asset(
            target="192.168.1.50",
            tool_name="nmap",
            parameters={"port": 80}
        )
        assert engine.validate_asset(valid_asset) is True
        
        # Invalid asset (unauthorized target)
        invalid_asset = Asset(
            target="10.0.0.1",
            tool_name="nmap",
            parameters={"port": 80}
        )
        assert engine.validate_asset(invalid_asset) is False
    
    def test_policy_engine_rate_limit_enforcement(self):
        """Test rate limit enforcement."""
        config = {
            "rate_limiting": {"window_size": 1, "max_requests": 1},
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": []
            },
            "allowed_exploits": []
        }
        engine = create_policy_engine(config)
        
        # First request should be allowed
        assert engine.enforce_rate_limits("test_adapter") is True
        engine.rate_limiter.record_request("test_adapter")
        
        # Second request should be rate limited
        assert engine.enforce_rate_limits("test_adapter") is False
    
    def test_policy_engine_exploit_permissions(self):
        """Test exploit permission checking."""
        config = {
            "rate_limiting": {"window_size": 60, "max_requests": 10},
            "target_validation": {
                "authorized_networks": [],
                "authorized_domains": []
            },
            "allowed_exploits": ["allowed_exploit"]
        }
        engine = create_policy_engine(config)
        
        # Allowed exploit
        assert engine.check_exploit_permissions("allowed_exploit") is True
        
        # Unauthorized exploit
        assert engine.check_exploit_permissions("unauthorized_exploit") is False
        
        # Lab mode should allow all exploits
        assert engine.check_exploit_permissions("any_exploit", lab_mode=True) is True
    
    def test_policy_engine_target_validation(self):
        """Test target validation."""
        config = {
            "rate_limiting": {"window_size": 60, "max_requests": 10},
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": ["example.com"]
            },
            "allowed_exploits": []
        }
        engine = create_policy_engine(config)
        
        # Authorized targets
        assert engine.validate_target("192.168.1.50") is True
        assert engine.validate_target("example.com") is True
        
        # Unauthorized targets
        assert engine.validate_target("10.0.0.1") is False
        assert engine.validate_target("unauthorized.com") is False
    
    def test_policy_engine_violation_logging(self):
        """Test policy violation logging."""
        engine = create_policy_engine()
        
        violation = PolicyViolation(
            rule_name="test_rule",
            violation_type=PolicyViolationType.UNAUTHORIZED_TARGET,
            target="10.0.0.1",
            timestamp=datetime.now(),
            details={"reason": "test violation"},
            severity="medium"
        )
        
        initial_violations = len(engine.violations)
        engine.log_violation(violation)
        
        assert len(engine.violations) == initial_violations + 1
        assert engine.violations[-1] == violation
    
    def test_policy_engine_violation_report(self):
        """Test violation report generation."""
        engine = create_policy_engine()
        
        violation = PolicyViolation(
            rule_name="test_rule",
            violation_type=PolicyViolationType.UNAUTHORIZED_TARGET,
            target="10.0.0.1",
            timestamp=datetime.now(),
            details={"reason": "test violation"},
            severity="high"
        )
        engine.log_violation(violation)
        
        report = engine.get_violation_report()
        assert len(report) == 1
        assert report[0]["rule_name"] == "test_rule"
        assert report[0]["target"] == "10.0.0.1"
        assert report[0]["severity"] == "high"
    
    def test_policy_engine_rate_monitoring(self):
        """Test rate monitoring functionality."""
        config = {
            "rate_limiting": {"window_size": 1, "max_requests": 10},
            "target_validation": {
                "authorized_networks": [],
                "authorized_domains": []
            },
            "allowed_exploits": []
        }
        engine = create_policy_engine(config)
        
        # Record some requests
        engine.rate_limiter.record_request("test_adapter")
        engine.rate_limiter.record_request()
        
        rates = engine.get_current_rates()
        assert "global" in rates
        assert "test_adapter" in rates
    
    def test_policy_engine_rule_management(self):
        """Test policy rule management."""
        engine = create_policy_engine()
        initial_rule_count = len(engine.rules)
        
        # Add a new rule with highest priority
        new_rule = PolicyRule(
            name="test_rule",
            description="Test rule for testing",
            priority=150,  # Higher than default rules (100, 90, 80)
            violation_type=PolicyViolationType.INVALID_ASSET
        )
        engine.add_rule(new_rule)
        
        assert len(engine.rules) == initial_rule_count + 1
        assert engine.rules[0].name == "test_rule"  # Should be highest priority
        
        # Remove the rule
        assert engine.remove_rule("test_rule") is True
        assert len(engine.rules) == initial_rule_count
        
        # Try to remove non-existent rule
        assert engine.remove_rule("nonexistent_rule") is False


class TestPolicyEngineIntegration:
    """Integration tests for policy engine components."""
    
    def test_complete_policy_validation_flow(self):
        """Test complete policy validation workflow."""
        config = {
            "rate_limiting": {"window_size": 1, "max_requests": 5},
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": ["example.com"],
                "blocked_targets": ["192.168.1.100"]
            },
            "allowed_exploits": ["safe_exploit"]
        }
        engine = create_policy_engine(config)
        
        # Valid asset should pass all checks
        valid_asset = Asset(
            target="192.168.1.50",
            tool_name="nmap",
            parameters={"port": 80}
        )
        assert engine.validate_asset(valid_asset) is True
        
        # Invalid target should fail
        invalid_asset = Asset(
            target="10.0.0.1",
            tool_name="nmap",
            parameters={"port": 80}
        )
        assert engine.validate_asset(invalid_asset) is False
        
        # Check that violation was logged
        violations = engine.get_violation_report()
        assert len(violations) > 0
        assert violations[-1]["violation_type"] == "unauthorized_target"
    
    def test_rate_limiting_with_actual_delays(self):
        """Test rate limiting with actual time delays."""
        config = {
            "rate_limiting": {"window_size": 1, "max_requests": 2},
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24"],
                "authorized_domains": []
            },
            "allowed_exploits": []
        }
        engine = create_policy_engine(config)
        
        # Should allow first two requests
        assert engine.enforce_rate_limits("delay_test") is True
        engine.rate_limiter.record_request("delay_test")
        
        assert engine.enforce_rate_limits("delay_test") is True
        engine.rate_limiter.record_request("delay_test")
        
        # Third request should be rate limited
        assert engine.enforce_rate_limits("delay_test") is False
    
    def test_exploit_permission_scenarios(self):
        """Test various exploit permission scenarios."""
        config = {
            "rate_limiting": {"window_size": 60, "max_requests": 10},
            "target_validation": {
                "authorized_networks": [],
                "authorized_domains": []
            },
            "allowed_exploits": ["exploit1", "exploit2"]
        }
        engine = create_policy_engine(config)
        
        # Test allowed exploits
        assert engine.check_exploit_permissions("exploit1") is True
        assert engine.check_exploit_permissions("exploit2") is True
        
        # Test unauthorized exploit
        assert engine.check_exploit_permissions("exploit3") is False
        
        # Test lab mode override
        assert engine.check_exploit_permissions("exploit3", lab_mode=True) is True
        
        # Check that unauthorized exploit was logged
        violations = engine.get_violation_report()
        assert len(violations) > 0
        assert violations[-1]["violation_type"] == "exploit_not_allowed"


if __name__ == "__main__":
    pytest.main([__file__])
