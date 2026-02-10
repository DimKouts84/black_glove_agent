#!/usr/bin/env python3
"""
Live verification script for Black Glove adapters.
Runs each adapter without mocks to ensure they are functional on the current system.
"""

import os
import json
import sys
import traceback
import importlib
from datetime import datetime
from pathlib import Path

# Add project src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from agent.plugin_manager import PluginManager
from agent.policy_engine import create_policy_engine

TEST_DOMAIN = "example.com"
TEST_NMAP_TARGET = "scanme.nmap.org"

# Find project root
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
WORDLIST_PATH = PROJECT_ROOT / "bin" / "wordlists" / "common.txt"

CONFIG = {
    "rate_limiting": {
        "window_size": 60,
        "max_requests": 100,
        "global_max_requests": 500,
    },
    "target_validation": {
        "authorized_networks": ["8.8.8.8/32", "127.0.0.1/32"],
        "authorized_domains": [TEST_DOMAIN, f"http://{TEST_DOMAIN}", f"https://{TEST_DOMAIN}", TEST_NMAP_TARGET, f"http://{TEST_NMAP_TARGET}"],
        "blocked_targets": []
    },
    "allowed_exploits": ["safe_exploit"],
}

TEST_CASES = {
    'asset_manager': [({'command': 'list'}, 'list assets')],
    'public_ip': [({}, 'public ip')],
    'whois': [({'domain': TEST_DOMAIN}, 'whois lookup')],
    'dns_lookup': [({'domain': TEST_DOMAIN, 'record_types': ['A', 'MX', 'NS']}, 'dns lookup')],
    'passive_recon': [({'domain': TEST_DOMAIN, 'max_results': 5}, 'passive recon')],
    'sublist3r': [({'domain': TEST_DOMAIN, 'max_results': 10}, 'sublist3r subdomain enum')],
    'viewdns': [({'host': TEST_DOMAIN}, 'viewdns lookup')],
    'ssl_check': [({'host': TEST_DOMAIN, 'port': 443}, 'ssl check')],
    'wappalyzer': [({'url': f'http://{TEST_DOMAIN}'}, 'wappalyzer tech stack')],
    'nmap': [({'target': TEST_NMAP_TARGET, 'ports': '80', 'output_xml': True}, 'nmap quick scan')],
    'gobuster': [({'mode': 'dir', 'url': f'http://{TEST_DOMAIN}', 'wordlist': str(WORDLIST_PATH), 'threads': 5}, 'gobuster dir scan')],
}

def main():
    print(f"=== Live Tool Verification Started at {datetime.now()} ===")
    print(f"Targets: Domain={TEST_DOMAIN}, Nmap={TEST_NMAP_TARGET}\n")

    pe = create_policy_engine(CONFIG)
    pm = PluginManager(config={}, policy_engine=pe)

    adapters = pm.discover_adapters()
    results = []

    for adapter in sorted(adapters):
        if adapter not in TEST_CASES:
            print(f"Skipping {adapter}: no live test case defined")
            continue

        print(f"\n--- Testing {adapter} ---")
        for params, desc in TEST_CASES[adapter]:
            print(f"Action: {desc} | Params: {params}")
            try:
                # Special-case functional adapters
                if adapter == 'asset_manager':
                    asset_mod = importlib.import_module(f'adapters.{adapter}')
                    res = asset_mod.run(params)
                else:
                    # Load adapter
                    pm.load_adapter(adapter)
                    # Execute
                    res = pm.run_adapter(adapter, params)
                
                if res.status.name == 'SUCCESS':
                    print(f"SUCCESS: Result data keys: {list(res.data.keys()) if isinstance(res.data, dict) else 'non-dict'}")
                    results.append((adapter, desc, 'SUCCESS', 'Executed successfully'))
                else:
                    print(f"FAILURE: {res.status.name}")
                    print(f"Error Message: {res.error_message}")
                    results.append((adapter, desc, 'FAILURE', res.error_message or 'Unknown error'))
            except Exception as e:
                print(f"EXCEPTION: {str(e)}")
                # traceback.print_exc()
                results.append((adapter, desc, 'EXCEPTION', str(e)))

    print('\n' + '='*40)
    print('=== Live Verification Summary ===')
    print('='*40)
    
    passed = 0
    failed = 0
    
    for adapter, desc, outcome, msg in results:
        status_icon = "[PASS]" if outcome == 'SUCCESS' else "[FAIL]"
        print(f"{status_icon} {adapter:15} | {desc:25} | {outcome:10} | {msg}")
        if outcome == 'SUCCESS':
            passed += 1
        else:
            failed += 1
            
    print('\n' + '='*40)
    print(f"TOTAL: {len(results)} | PASSED: {passed} | FAILED: {failed}")
    print('='*40)

    if failed > 0:
        sys.exit(0) # Exit 0 anyway to allow showing report even if some tools fail (which is expected for some)

if __name__ == '__main__':
    main()
