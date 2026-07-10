"""
Target string normalization utilities.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


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
    import ipaddress

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


def is_valid_domain_format(domain: str) -> bool:
    host = strip_host(domain)
    return bool(re.match(r"^[\w.-]+\.[a-z]{2,}$", host, re.IGNORECASE))
