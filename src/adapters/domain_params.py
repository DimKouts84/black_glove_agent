"""Shared domain parameter resolution for OSINT adapters."""

from typing import Any, Dict


def _strip_to_host(value: str) -> str:
    """Strip URL scheme, path, and port from a target string."""
    value = str(value).strip()
    if "://" in value:
        from urllib.parse import urlparse
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path.split("/")[0]
    # Remove port if present (host:port)
    if ":" in value and not value.startswith("["):
        host_part, _, port_part = value.rpartition(":")
        if port_part.isdigit():
            value = host_part
    return value.strip("/")


def resolve_domain(params: Dict[str, Any]) -> str:
    """
    Resolve a domain from common parameter aliases.

    Accepts: domain, target.
    """
    domain = params.get("domain") or params.get("target")
    if not domain or not str(domain).strip():
        raise ValueError("domain or target is required")

    domain = _strip_to_host(str(domain))
    if not domain:
        raise ValueError("Invalid domain")

    return domain


def resolve_host(params: Dict[str, Any]) -> str:
    """
    Resolve a hostname or IP from common parameter aliases.

    Accepts: host, target, domain, target_url, url.
    """
    host = (
        params.get("host")
        or params.get("target")
        or params.get("domain")
        or params.get("target_url")
        or params.get("url")
    )
    if not host or not str(host).strip():
        raise ValueError("host, target, or domain is required")

    host = _strip_to_host(str(host))
    if not host:
        raise ValueError("Invalid host")

    return host
