"""
Shared target normalization and authorization for Black Glove.

Used by PolicyEngine, AssetValidator, and WorkGraphExecutor.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("black_glove.target_scope")


@dataclass
class TargetScopeConfig:
    """Authorization scope loaded from application config."""

    authorized_networks: List[str]
    authorized_domains: List[str]
    blocked_targets: List[str]
    engagement_targets: Optional[Set[str]] = None

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "TargetScopeConfig":
        tv = config.get("target_validation", config)
        return cls(
            authorized_networks=list(tv.get("authorized_networks", [])),
            authorized_domains=list(tv.get("authorized_domains", [])),
            blocked_targets=list(tv.get("blocked_targets", [])),
            engagement_targets=set(config.get("engagement_targets", []))
            if config.get("engagement_targets")
            else None,
        )


def strip_host(value: str) -> str:
    """Normalize a target string to a bare host or IP."""
    value = str(value).strip()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or value
    if value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    if ":" in value and not value.startswith("["):
        host_part, _, port_part = value.rpartition(":")
        if port_part.isdigit():
            value = host_part
    return value.strip("/").lower()


def normalize_domain(domain: str) -> str:
    """Normalize domain for comparison."""
    host = strip_host(domain)
    if host.startswith("www."):
        host = host[4:]
    return host


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def domain_matches_allowlist(domain: str, allowed: str) -> bool:
    """Check exact or subdomain match against an allowed domain entry."""
    domain = normalize_domain(domain)
    allowed = normalize_domain(allowed)
    if domain == allowed:
        return True
    return domain.endswith(f".{allowed}")


class TargetScopeValidator:
    """Fail-closed target authorization."""

    def __init__(self, config: TargetScopeConfig):
        self.config = config
        self._networks: List[Any] = []
        self._authorized_domains: Set[str] = set()
        self._blocked: Set[str] = set()
        self._load()

    def _load(self) -> None:
        for network_str in self.config.authorized_networks:
            try:
                self._networks.append(ipaddress.ip_network(network_str, strict=False))
            except ValueError:
                try:
                    ip = ipaddress.ip_address(network_str)
                    bits = 32 if isinstance(ip, ipaddress.IPv4Address) else 128
                    self._networks.append(ipaddress.ip_network(f"{ip}/{bits}", strict=False))
                except ValueError as exc:
                    logger.warning("Invalid network in config: %s - %s", network_str, exc)

        for domain in self.config.authorized_domains:
            self._authorized_domains.add(normalize_domain(domain))

        for target in self.config.blocked_targets:
            normalized = strip_host(target)
            self._blocked.add(normalized)
            if not is_valid_ip(normalized):
                self._blocked.add(normalize_domain(normalized))

    def is_blocked(self, target: str) -> bool:
        host = strip_host(target)
        if host in self._blocked:
            return True
        if not is_valid_ip(host) and normalize_domain(host) in self._blocked:
            return True
        return False

    def is_ip_authorized(self, ip_address: str) -> bool:
        if self.is_blocked(ip_address):
            return False
        try:
            ip = ipaddress.ip_address(strip_host(ip_address))
        except ValueError:
            return False

        if self.config.engagement_targets:
            if strip_host(ip_address) in {strip_host(t) for t in self.config.engagement_targets}:
                return True

        if not self._networks:
            return False

        return any(ip in network for network in self._networks)

    def is_domain_authorized(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        if self.is_blocked(normalized):
            return False

        if self.config.engagement_targets:
            for engaged in self.config.engagement_targets:
                if domain_matches_allowlist(normalized, engaged):
                    return True

        if not self._authorized_domains:
            return False

        return any(
            domain_matches_allowlist(normalized, allowed)
            for allowed in self._authorized_domains
        )

    def validate_target(self, target: str) -> bool:
        host = strip_host(target)
        if self.is_blocked(host):
            return False
        if is_valid_ip(host):
            return self.is_ip_authorized(host)
        if re.match(r"^[\w.-]+\.[a-z]{2,}$", host, re.IGNORECASE):
            return self.is_domain_authorized(host)
        return False


def build_policy_target_config(app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Map top-level ConfigModel fields into policy target_validation."""
    policy = dict(app_config.get("policy", {}))
    tv = dict(policy.get("target_validation", {}))
    if "authorized_networks" in app_config and "authorized_networks" not in tv:
        tv["authorized_networks"] = app_config["authorized_networks"]
    if "authorized_domains" in app_config and "authorized_domains" not in tv:
        tv["authorized_domains"] = app_config["authorized_domains"]
    if "blocked_targets" in app_config and "blocked_targets" not in tv:
        tv["blocked_targets"] = app_config["blocked_targets"]
    policy["target_validation"] = tv
    return policy
