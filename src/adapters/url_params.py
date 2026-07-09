"""Shared URL parameter resolution for web scanner adapters."""

import urllib.parse
from typing import Any, Dict


def resolve_target_url(params: Dict[str, Any]) -> str:
    """
    Resolve a scan target from common parameter aliases.

    Accepts: target_url, target, url, host, domain.
    Ensures scheme is present when missing (defaults to https).
    """
    target = (
        params.get("target_url")
        or params.get("target")
        or params.get("url")
        or params.get("host")
        or params.get("domain")
    )
    if not target or not str(target).strip():
        raise ValueError("target_url or target is required")

    target = str(target).strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid target URL format (must include scheme and host)")

    return target
