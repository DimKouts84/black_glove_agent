#!/usr/bin/env python3
"""
Smoke test harness for Black Glove adapters.

Runs each adapter via PluginManager.run_adapter with a conservative set of example parameters
and reports pass/fail/skipped. Avoids destructive operations and respects policy engine.
"""

import os
import json
import sys
import traceback

# Add project src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from agent.plugin_manager import PluginManager
from agent.policy_engine import create_policy_engine
from datetime import datetime
import importlib

TEST_DOMAIN = os.environ.get('TEST_DOMAIN', 'ikarou3.casa')
TEST_NMAP_TARGET = os.environ.get('TEST_NMAP_TARGET', 'scanme.nmap.org')

CONFIG = {
    "rate_limiting": {
        "window_size": 60,
        "max_requests": 100,
        "global_max_requests": 500,
    },
    "target_validation": {
        "authorized_networks": ["8.8.8.8/32", "192.168.1.0/24"],
        "authorized_domains": [TEST_DOMAIN, f"http://{TEST_DOMAIN}", f"https://{TEST_DOMAIN}", TEST_NMAP_TARGET, f"http://{TEST_NMAP_TARGET}", "example.com"],
        "blocked_targets": []
    },
    "allowed_exploits": ["safe_exploit"],
}

TEST_CASES = {
    'asset_manager': [
        ({'command': 'list'}, 'list assets'),
        ({'command': 'add', 'name': 'ikarou3-web', 'type': 'domain', 'value': TEST_DOMAIN}, 'add asset'),
        ({'command': 'list'}, 'list assets after add'),
    ],
    'public_ip': [({}, 'public ip')],
    'whois': [({'domain': TEST_DOMAIN}, 'whois lookup')],
    'dns_lookup': [({'domain': TEST_DOMAIN, 'record_types': ['A', 'MX', 'NS']}, 'dns lookup')],
    'passive_recon': [({'domain': TEST_DOMAIN, 'max_results': 5}, 'passive recon')],
    'sublist3r': [({'domain': TEST_DOMAIN, 'max_results': 50}, 'sublist3r subdomain enum')],
    'viewdns': [({'host': TEST_DOMAIN}, 'viewdns lookup')],
    'ssl_check': [({'host': TEST_DOMAIN, 'port': 443}, 'ssl check')],
    'wappalyzer': [({'url': TEST_DOMAIN}, 'wappalyzer tech stack')],
    'gobuster': [
        ({'mode': 'dir', 'url': f'http://{TEST_DOMAIN}', 'wordlist': '/path/to/wordlist.txt', 'threads': 10}, 'gobuster dir'),
        ({'mode': 'dns', 'domain': TEST_DOMAIN, 'wordlist': '/path/to/subdomains.txt', 'threads': 10}, 'gobuster dns')
    ],
    'nmap': [({'target': TEST_NMAP_TARGET, 'ports': '80,443', 'output_xml': True}, 'nmap quick scan')],
    'example': [({'command': "echo 'Hello, Black Glove!'"}, 'example command')],
}

class FakeRunner:
    def __init__(self, adapter_type:str):
        self.adapter_type = adapter_type
    def run(self, spec: dict):
        # Return different fake outputs based on adapter type and args
        if self.adapter_type == 'nmap':
            xml = '''<?xml version="1.0"?>\n<nmaprun>\n  <host>\n    <status state="up"/>\n    <address addr="93.184.216.34" addrtype="ipv4"/>\n    <ports>\n      <port protocol="tcp" portid="80">\n        <state state="open"/>\n        <service name="http"/>\n      </port>\n    </ports>\n  </host>\n  <runstats>\n    <hosts up="1" down="0"/>\n  </runstats>\n</nmaprun>'''
            return {"status":"success", "exit_code":0, "stdout":xml, "stderr":"", "duration": 0.05}
        elif self.adapter_type == 'gobuster':
            args = spec.get('args', []) or []
            stdout = ''
            if '-u' in args or 'dir' in args:
                stdout = '/admin (Status: 301) [Size: 0]\n/images (Status: 200)\n'
            else:
                stdout = 'Found: admin.ikarou3.casa\nadmin.ikarou3.casa (A) 192.168.1.100\n'
            return {"status":"success", "exit_code":0, "stdout":stdout, "stderr":"", "duration":0.03}
        else:
            return {"status":"error", "exit_code":1, "stdout":"", "stderr":"no fake runner configured", "duration":0.0}

FAKE_RUNNERS = {
    'nmap': FakeRunner('nmap'),
    'gobuster': FakeRunner('gobuster')
}


def main():
    pe = create_policy_engine(CONFIG)
    pm = PluginManager(config={}, policy_engine=pe)

    adapters = pm.discover_adapters()

    results = []

    for adapter in adapters:
        adapter_results = []
        if adapter not in TEST_CASES:
            print(f"Skipping {adapter}: no test case defined")
            results.append((adapter, 'SKIPPED', 'No test case'))
            continue

        for params, desc in TEST_CASES[adapter]:
            print(f"\n--- Testing {adapter} ({desc}) with params: {params} ---")
            try:
                # For command-check: Check param validation only first
                try:
                    # Special-case 'asset_manager' which exposes a run() function instead of a class-based Adapter
                    if adapter == 'asset_manager':
                        # Import the module and call run directly
                        asset_mod = importlib.import_module(f'adapters.{adapter}')
                        # No pm.load_adapter call
                    else:
                        # If we need to inject fake runner config, do it here
                        if adapter in FAKE_RUNNERS:
                            pm.load_adapter(adapter, config={'_runner': FAKE_RUNNERS[adapter]})
                        else:
                            pm.load_adapter(adapter)
                except Exception as e:
                    print(f"Failed to load adapter {adapter}: {e}")
                    adapter_results.append((desc, 'LOAD_FAILED', str(e)))
                    continue

                # Try validate_params only
                try:
                    if adapter == 'asset_manager':
                        # The asset_manager.validate_params path doesn't exist; we just assume run will validate
                        pass
                    else:
                        pm.adapter_manager._loaded_adapters[adapter].validate_params(params)
                except Exception as val_err:
                    print(f"Parameter validation failed for {adapter}: {val_err}")
                    adapter_results.append((desc, 'PARAM_VALIDATION_FAILED', str(val_err)))
                    continue

                # Now attempt to execute via run_adapter (enforces policy)
                try:
                    if adapter == 'asset_manager':
                        # Call the functional interface directly
                        res = asset_mod.run(params)
                    else:
                        res = pm.run_adapter(adapter, params)
                    # Summarize
                    if res.status.name == 'SUCCESS':
                        print(f"SUCCESS: {adapter} -> {res.metadata if res.metadata else res.data}")
                        adapter_results.append((desc, 'SUCCESS', res.data if res.data is not None else str(res.metadata)))
                    else:
                        print(f"ADAPTER RETURNED STATUS {res.status.name}: {res.error_message or res.data}")
                        adapter_results.append((desc, 'ADAPTER_ERROR', res.error_message or str(res.data)))
                except Exception as run_err:
                    print(f"Error during execution of adapter {adapter}: {run_err}")
                    tb = traceback.format_exc()
                    adapter_results.append((desc, 'EXECUTION_ERROR', str(run_err)))

            except Exception as e:
                print(f"Unexpected error testing {adapter}: {e}")
                tb = traceback.format_exc()
                adapter_results.append((desc, 'UNEXPECTED_ERROR', str(e)))

        results.append((adapter, 'RESULTS', adapter_results))

    # Print summary
    print('\n\n=== Adapter Test Summary ===')
    for adapter, status, details in results:
        print(f"- {adapter}: {status}")
        if status == 'RESULTS':
            for entry in details:
                desc, outcome, message = entry
                print(f"    • {desc}: {outcome} -> {message}")


if __name__ == '__main__':
    main()
