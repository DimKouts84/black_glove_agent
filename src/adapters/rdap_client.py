"""
RDAP client for domain registration lookups.

Uses IANA DNS bootstrap (RFC 9224) with Google Registry fallback for .dev/.app TLDs.
"""

from __future__ import annotations

import datetime
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("black_glove.adapters.rdap")

IANA_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
GOOGLE_REGISTRY_BASE = "https://pubapi.registry.google/rdap/domain/"
GOOGLE_TLDS = frozenset({"dev", "app", "page", "how"})

_bootstrap_cache: Dict[str, Any] = {"fetched_at": 0.0, "services": {}}
_BOOTSTRAP_TTL_SECONDS = 86400


def _normalize_bootstrap_url(url: str) -> str:
    url = url.rstrip("/")
    if not url.endswith("/domain"):
        if url.endswith("/rdap"):
            return f"{url}/domain/"
        return f"{url}/domain/"
    return f"{url}/"


def _load_bootstrap_services(timeout: float = 10.0) -> Dict[str, str]:
    now = time.time()
    if _bootstrap_cache["services"] and now - _bootstrap_cache["fetched_at"] < _BOOTSTRAP_TTL_SECONDS:
        return _bootstrap_cache["services"]

    services: Dict[str, str] = {}
    try:
        response = requests.get(IANA_DNS_BOOTSTRAP_URL, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        for entry in payload.get("services", []):
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            tlds, urls = entry[0], entry[1]
            if not urls:
                continue
            base = _normalize_bootstrap_url(str(urls[0]))
            for tld in tlds:
                services[str(tld).lower().lstrip(".")] = base
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.warning("Failed to load IANA RDAP bootstrap: %s", exc)

    for tld in GOOGLE_TLDS:
        services.setdefault(tld, GOOGLE_REGISTRY_BASE)

    _bootstrap_cache["services"] = services
    _bootstrap_cache["fetched_at"] = now
    return services


def resolve_rdap_url(domain: str, timeout: float = 10.0) -> Optional[str]:
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return None
    tld = parts[-1]
    services = _load_bootstrap_services(timeout=timeout)
    base = services.get(tld)
    if not base:
        return None
    return f"{base}{domain.lower()}"


def _vcard_value(vcard: Any, property_name: str) -> Optional[str]:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for row in vcard[1]:
        if not isinstance(row, list) or len(row) < 4:
            continue
        if row[0] == property_name:
            return str(row[3])
    return None


def parse_rdap_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    registrar = None
    for entity in payload.get("entities", []) or []:
        roles = entity.get("roles") or []
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        registrar = (
            _vcard_value(vcard, "fn")
            or _vcard_value(vcard, "org")
            or entity.get("handle")
        )
        if registrar:
            break

    creation = None
    expiration = None
    for event in payload.get("events", []) or []:
        action = event.get("eventAction")
        date_str = event.get("eventDate")
        if not date_str:
            continue
        try:
            parsed = datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            continue
        if action == "registration" and creation is None:
            creation = parsed
        elif action == "expiration" and expiration is None:
            expiration = parsed

    name_servers: List[str] = []
    for ns in payload.get("nameservers", []) or []:
        host = ns.get("ldhName") or ns.get("unicodeName")
        if host:
            name_servers.append(str(host).lower())

    status = payload.get("status") or []
    if isinstance(status, list):
        status_values = [str(s) for s in status]
    else:
        status_values = [str(status)]

    return {
        "registrar": registrar,
        "creation_date": creation,
        "expiration_date": expiration,
        "name_servers": name_servers or None,
        "status": status_values or None,
        "rdap_source": payload.get("port43") or payload.get("ldhName"),
    }


def fetch_rdap_domain(
    domain: str,
    *,
    timeout: float = 10.0,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    Fetch and parse RDAP data for a domain.

    Returns:
        (parsed_data_or_none, warnings)
    """
    warnings: List[str] = []
    url = resolve_rdap_url(domain, timeout=timeout)
    if not url:
        warnings.append(f"No RDAP service discovered for TLD of {domain}")
        return None, warnings

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/rdap+json, application/json"},
        )
    except requests.RequestException as exc:
        warnings.append(f"RDAP request failed for {domain}: {exc}")
        return None, warnings

    if response.status_code != 200:
        warnings.append(
            f"RDAP HTTP {response.status_code} from {url}"
        )
        return None, warnings

    try:
        payload = response.json()
    except ValueError:
        warnings.append(f"RDAP response was not valid JSON from {url}")
        return None, warnings

    if not isinstance(payload, dict):
        warnings.append("RDAP response was not a JSON object")
        return None, warnings

    parsed = parse_rdap_payload(payload)
    if not any((parsed.get("registrar"), parsed.get("creation_date"), parsed.get("expiration_date"))):
        warnings.append("RDAP response contained no registrar or lifecycle dates")
        return None, warnings

    parsed["rdap_url"] = url
    return parsed, warnings
