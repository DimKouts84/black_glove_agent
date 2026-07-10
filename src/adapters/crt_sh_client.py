"""
Shared crt.sh Certificate Transparency client with retries.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, parse, request

logger = logging.getLogger("black_glove.adapters.crt_sh")

DEFAULT_BASE_URL = "https://crt.sh/"
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1.5


def _http_get(
    url: str,
    *,
    timeout: float = 10.0,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
) -> str:
    attempt = 0
    delay = backoff
    last_error: Optional[str] = None

    while attempt <= retries:
        req = request.Request(
            url,
            headers={
                "User-Agent": "BlackGloveCRT/1.0",
                "Accept": "application/json,text/plain;q=0.8,*/*;q=0.5",
            },
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except error.HTTPError as exc:
            code = getattr(exc, "code", None)
            last_error = f"HTTPError {code} for {url}"
            if code == 404:
                raise
            if isinstance(code, int) and (code == 429 or 500 <= code < 600):
                if attempt < retries:
                    time.sleep(delay)
                    delay *= 2
                    attempt += 1
                    continue
            raise
        except Exception as exc:
            last_error = str(exc)
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                attempt += 1
                continue
            raise RuntimeError(last_error or str(exc)) from exc

    raise RuntimeError(last_error or f"Failed to fetch {url}")


def parse_crt_json(raw: str) -> List[Dict[str, Any]]:
    """Parse crt.sh JSON which may be a list or concatenated objects."""
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    entries: List[Dict[str, Any]] = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
        if idx >= len(raw):
            break
        obj, end = decoder.raw_decode(raw, idx)
        if isinstance(obj, dict):
            entries.append(obj)
        elif isinstance(obj, list):
            entries.extend(obj)
        idx = end
    return entries


def fetch_crt_sh_entries(
    domain: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    include_subdomains: bool = True,
    timeout: float = 10.0,
    retries: int = DEFAULT_RETRIES,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Query crt.sh for certificate entries.

    Returns (entries, error_message). HTTP 404 means no certificates (not an error).
    """
    base = base_url.rstrip("/")
    queries: List[str] = []
    if include_subdomains:
        queries.append(f"%.{domain}")
    if domain not in queries:
        queries.append(domain)

    last_error: Optional[str] = None
    for query in queries:
        url = f"{base}/?q={parse.quote(query)}&output=json"
        try:
            raw = _http_get(url, timeout=timeout, retries=retries)
            return parse_crt_json(raw), None
        except error.HTTPError as exc:
            if getattr(exc, "code", None) == 404:
                continue
            last_error = f"HTTPError {exc.code} for {url}"
        except Exception as exc:
            last_error = str(exc)

    if last_error:
        return [], last_error
    return [], None
