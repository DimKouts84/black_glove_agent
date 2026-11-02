"""Safe argv assembly for adapter extra flags.

A flag and its value may arrive as one token (``--version-intensity=5``) or as
two tokens (``--version-intensity``, ``5``). Values stay attached to the
preceding flag. Shell metacharacters are rejected.
"""

from __future__ import annotations

import re
from typing import List, Sequence

SAFE_FLAG_RE = re.compile(
    r"^-{1,2}[A-Za-z0-9][A-Za-z0-9\-]*(?:=[A-Za-z0-9_\-\.,:+]+)?$"
)
SAFE_FLAG_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-\.,:+]+$")


def safe_flag_argv(
    flags: Sequence[str] | None,
    *,
    strict: bool = False,
    label: str = "extra flag",
) -> List[str]:
    """Return argv tokens for a flag list.

    When ``strict`` is true, an unsafe token raises ``ValueError``. Otherwise
    unsafe tokens are dropped.
    """
    argv: List[str] = []
    pending = False
    for raw in flags or []:
        if not isinstance(raw, str):
            if strict:
                raise ValueError(f"Unsafe {label}: {raw}")
            pending = False
            continue
        token = raw.strip()
        if SAFE_FLAG_RE.match(token):
            argv.append(token)
            pending = "=" not in token
            continue
        if pending and SAFE_FLAG_VALUE_RE.match(token):
            argv.append(token)
            pending = False
            continue
        if strict:
            raise ValueError(f"Unsafe {label}: {token}")
        pending = False
    return argv
