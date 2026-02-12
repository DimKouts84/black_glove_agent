import sys
import os
from typing import Dict, Any

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from adapters.interface import AdapterResult, AdapterResultStatus
from adapters.osint_harvester import OSINTHarvesterAdapter

def test_osint_interpretation():
    adapter = OSINTHarvesterAdapter({})
    
    # partial_result causing current issue
    # Status is FAILURE because has_data is False (no emails found, subdomains failed)
    # error_message is None because _execute_impl doesn't set it
    result = AdapterResult(
        status=AdapterResultStatus.FAILURE,
        data={
            "domain": "financemagnates.com",
            "emails": [],
            "subdomains": [],
            "metadata": {},
            "errors": {
                "subdomains": "HTTPSConnectionPool(host='crt.sh', port=443): Read timed out."
            }
        },
        metadata={},
        evidence_path=None
    )
    
    print("--- Test Case: OSINT Failure with Errors in Data ---")
    interpretation = adapter.interpret_result(result)
    print(f"Interpretation:\n{interpretation}")
    
    # Check if it says "Error: None"
    if "Error: None" in interpretation:
        print("\n[CONFIRMED] Output contains 'Error: None'. Bug reproduced.")
    else:
        print("\n[FAILED] Could not reproduce 'Error: None'.")

if __name__ == "__main__":
    test_osint_interpretation()
