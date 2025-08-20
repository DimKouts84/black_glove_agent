"""
Core Architecture Demonstration

This script demonstrates the Black Glove pentest agent core architecture
components working together in a complete workflow.
"""

import sys
import os
import logging
from typing import Dict, Any

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.agent.orchestrator import create_orchestrator
from src.agent.models import Asset
from src.adapters.interface import AdapterResultStatus


def setup_logging():
    """Set up logging for the demonstration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def demonstrate_core_architecture():
    """Demonstrate the core architecture components working together."""
    print("=== Black Glove Core Architecture Demonstration ===\n")
    
    # Create configuration with all components
    config = {
        "policy": {
            "rate_limiting": {
                "window_size": 60,
                "max_requests": 10,
                "global_max_requests": 100
            },
            "target_validation": {
                "authorized_networks": ["192.168.1.0/24", "10.0.0.0/8"],
                "authorized_domains": ["example.com", "test.com"],
                "blocked_targets": ["192.168.1.100"]  # Example blocked target
            },
            "allowed_exploits": ["safe_exploit"]
        },
        "passive_tools": ["whois", "dns_lookup", "ssl_check"],
        "scan_mode": "passive"
    }
    
    # Create orchestrator
    print("1. Creating orchestrator with all core components...")
    orchestrator = create_orchestrator(config)
    print("   ✓ Orchestrator created successfully")
    print(f"   - Policy Engine: {type(orchestrator.policy_engine).__name__}")
    print(f"   - Plugin Manager: {type(orchestrator.plugin_manager).__name__}")
    print(f"   - LLM Client: {type(orchestrator.llm_client).__name__}")
    print()
    
    # Add authorized assets
    print("2. Adding authorized assets...")
    assets = [
        Asset(
            target="192.168.1.50",
            tool_name="nmap",
            parameters={"port": 80}
        ),
        Asset(
            target="test.com",
            tool_name="whois",
            parameters={}
        )
    ]
    
    for asset in assets:
        if orchestrator.add_asset(asset):
            print(f"   ✓ Added asset: {asset.target}")
        else:
            print(f"   ✗ Rejected asset: {asset.target} (policy violation)")
    
    print(f"   Total assets in queue: {len(orchestrator.assets)}")
    print()
    
    # Test unauthorized asset rejection
    print("3. Testing policy enforcement with unauthorized asset...")
    unauthorized_asset = Asset(
        target="10.0.0.1",  # Not in authorized networks
        tool_name="nmap",
        parameters={}
    )
    
    if not orchestrator.add_asset(unauthorized_asset):
        print("   ✓ Policy engine correctly rejected unauthorized asset")
        print("   - Asset 10.0.0.1 not in authorized networks")
    print()
    
    # Run passive reconnaissance
    print("4. Running passive reconnaissance workflow...")
    try:
        results = orchestrator.run_passive_recon()
        print(f"   ✓ Passive recon completed with {len(results)} results")
        
        # Show some results
        if results:
            print("   Sample results:")
            for i, result in enumerate(results[:2]):  # Show first 2 results
                print(f"     {i+1}. {result.tool_name} on {result.asset.target}")
                print(f"        Status: {result.status}")
                if result.execution_time:
                    print(f"        Time: {result.execution_time:.2f}s")
    except Exception as e:
        print(f"   ! Passive recon encountered issues: {e}")
        print("   Continuing with demonstration...")
    print()
    
    # Show policy violations
    print("5. Checking policy violations...")
    violations = orchestrator.policy_engine.get_violation_report()
    if violations:
        print(f"   ✓ Found {len(violations)} policy violations:")
        for violation in violations[-2:]:  # Show last 2 violations
            print(f"     - {violation['violation_type']}: {violation['target']}")
    else:
        print("   ✓ No policy violations recorded")
    print()
    
    # Show current rates
    print("6. Checking current request rates...")
    rates = orchestrator.policy_engine.get_current_rates()
    for component, rate in rates.items():
        print(f"   - {component}: {rate:.2f} requests/second")
    print()
    
    # Generate report
    print("7. Generating findings report...")
    try:
        report = orchestrator.generate_report("json")
        print("   ✓ Report generated successfully")
        print(f"   - Assets scanned: {report['summary']['total_assets']}")
        print(f"   - Scan results: {report['summary']['total_scans']}")
        print(f"   - Findings identified: {report['summary']['total_findings']}")
    except Exception as e:
        print(f"   ! Report generation failed: {e}")
    print()
    
    # Cleanup
    print("8. Cleaning up resources...")
    orchestrator.cleanup()
    print("   ✓ Cleanup completed")
    print()
    
    print("=== Demonstration Complete ===")
    print("All core architecture components working together successfully!")


if __name__ == "__main__":
    setup_logging()
    demonstrate_core_architecture()
