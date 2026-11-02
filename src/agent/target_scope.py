"""
Target string normalization utilities.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse


def split_host_port(value: str) -> Tuple[str, Optional[int]]:
    """Split a target into a host and an optional numeric port.

    Bare IPv6 addresses stay intact. A trailing ``:port`` is removed only for
    hostnames, IPv4 addresses, and bracketed IPv6 literals.
    """
    host = str(value).strip()
    if "://" in host:
        parsed = urlparse(host)
        host = parsed.netloc or parsed.path or host
    host = host.strip().strip("/")

    if host.startswith("[") and "]" in host:
        end = host.index("]")
        addr = host[1:end]
        rest = host[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return addr, int(rest[1:])
        return addr, None

    try:
        ipaddress.ip_address(host)
        return host, None
    except ValueError:
        pass

    if ":" in host:
        host_part, _, port_part = host.rpartition(":")
        if port_part.isdigit() and host_part and ":" not in host_part:
            return host_part, int(port_part)
    return host, None


def strip_host(value: str) -> str:
    """Normalize a target string to a bare host or IP."""
    host, _port = split_host_port(value)
    return host.strip("/").lower()


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
