#!/usr/bin/env python3
"""
Live smoke tests for adapters against example.com.

- Inserts project root into sys.path so imports work without install
- Runs: WHOIS, DNS Lookup, SSL Check, Passive Recon
- Writes a JSON summary under evidence/
"""

import sys
import json
import time
import traceback
from pathlib import Path

# Ensure src/ is importable
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.adapters.whois import create_whois_adapter
from src.adapters.dns_lookup import create_dns_lookup_adapter
from src.adapters.ssl_check import create_ssl_check_adapter
from src.adapters.passive_recon import create_passive_recon_adapter


def status_name(status_obj):
    try:
        return getattr(status_obj, "name", str(status_obj))
    except Exception:
        return str(status_obj)


def run_and_capture(name: str, adapter, params: dict) -> dict:
    try:
        result = adapter.execute(params)
        return {
            "name": name,
            "status": status_name(getattr(result, "status", None)),
            "metadata": getattr(result, "metadata", {}),
            "evidence_path": getattr(result, "evidence_path", None),
            "error_message": getattr(result, "error_message", None),
        }
    except Exception as e:
        return {
            "name": name,
            "status": "ERROR",
            "error_message": str(e),
            "traceback": traceback.format_exc(),
        }


def main():
    domain = "example.com"
    host = "example.com"
    evidence_dir = BASE_DIR / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    results = []

    # WHOIS
    whois_adapter = create_whois_adapter({})
    results.append(
        run_and_capture("whois", whois_adapter, {"domain": domain, "timeout": 20})
    )

    # DNS Lookup
    dns_adapter = create_dns_lookup_adapter({})
    results.append(
        run_and_capture(
            "dns_lookup",
            dns_adapter,
            {"domain": domain, "record_types": ["A", "AAAA", "MX", "NS", "TXT"], "timeout": 10},
        )
    )

    # SSL Check
    ssl_adapter = create_ssl_check_adapter({})
    results.append(
        run_and_capture("ssl_check", ssl_adapter, {"host": host, "port": 443, "timeout": 10})
    )

    # Passive Recon (limit results for speed)
    passive_adapter = create_passive_recon_adapter(
        {"retries": 1, "crt_sh": {"max_results": 50}, "wayback": {"max_results": 50}}
    )
    results.append(
        run_and_capture("passive_recon", passive_adapter, {"domain": domain, "max_results": 50})
    )

    summary = {"timestamp": time.time(), "domain": domain, "results": results}
    summary_file = evidence_dir / f"live_tests_summary_{int(time.time())}.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Summary written: {summary_file}")
    for r in results:
        print(f"{r['name']}: {r.get('status')} ev={r.get('evidence_path')} err={r.get('error_message')}")


if __name__ == "__main__":
    main()
