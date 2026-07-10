"""Detect transient adapter failures suitable for automatic retry."""

from __future__ import annotations

import re

_TRANSIENT_PATTERNS = (
    r"no such host",
    r"temporary failure in name resolution",
    r"name or service not known",
    r"connection refused",
    r"connection reset",
    r"i/o timeout",
    r"read timed out",
    r"timed out",
    r"unable to connect",
    r"network is unreachable",
    r"no route to host",
    r"eof",
    r"broken pipe",
    r"502\b",
    r"503\b",
    r"504\b",
    r"bad gateway",
    r"service unavailable",
    r"gateway timeout",
)

_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in _TRANSIENT_PATTERNS)


def is_transient_adapter_error(message: str) -> bool:
    """Return True when an error message looks like a transient network/DNS failure."""
    if not message or not str(message).strip():
        return False
    text = str(message).lower()
    return any(pattern.search(text) for pattern in _COMPILED)
