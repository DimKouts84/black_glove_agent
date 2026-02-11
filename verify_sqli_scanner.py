"""Verification script for SQLiScannerAdapter."""
import sys, json
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent / "src"))

from adapters.sqli_scanner import SQLiScannerAdapter

def main():
    adapter = SQLiScannerAdapter()
    print(f"Adapter: {adapter.name} v{adapter.version}")
    
    # Target: testphp.vulnweb.com (Acunetix vulnerable site)
    # Known vulnerable endpoint: http://testphp.vulnweb.com/listproducts.php?cat=1
    # 'cat' parameter is vulnerable to SQLi
    target_url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    
    print("=" * 60)
    print(f"TESTING SQLi SCAN against {target_url}")
    print("=" * 60)
    
    result = adapter.execute({
        "target_url": target_url,
        "techniques": ["error", "boolean", "time"],
        "params_to_test": ["cat"]
    })
    
    print(f"\nStatus: {result.status}")
    print(f"Execution time: {result.execution_time:.2f}s")
    
    vulns = result.data.get("vulnerabilities", [])
    print(f"Total vulnerabilities found: {len(vulns)}")
    
    if vulns:
        print("\n--- FINDINGS ---")
        for v in vulns:
            print(f"\nType: {v['type']}")
            print(f"Parameter: {v['parameter']}")
            if "payload" in v:
                print(f"Payload: {v['payload']}")
            if "payloads" in v:
                print(f"Payloads: {v['payloads']}")
            if "database" in v:
                print(f"Database: {v['database']}")
            if "evidence" in v:
                print(f"Evidence: {v['evidence']}")
    else:
        print("No vulnerabilities found (unexpected for this target!)")

    if result.status != "SUCCESS":
        print(f"Errors: {result.error_message}")

if __name__ == "__main__":
    main()
