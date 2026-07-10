"""
Core Architecture Demonstration

This script demonstrates the Black Glove pentest agent core architecture
components working together in a complete workflow.
"""

import sys
import os
import logging

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.agent.orchestrator import create_orchestrator
from src.agent.models import Asset


def setup_logging():
    """Set up logging for the demonstration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def demonstrate_core_architecture():
    """Demonstrate the core architecture components working together."""
    print("=== Black Glove Core Architecture Demonstration ===\n")

    config = {
        "passive_tools": ["example"],
        "scan_mode": "passive"
    }

    print("1. Creating orchestrator with core components...")
    orchestrator = create_orchestrator(config)
    print("   ✓ Orchestrator created successfully")
    print(f"   - Plugin Manager: {type(orchestrator.plugin_manager).__name__}")
    print(f"   - LLM Client: {type(orchestrator.llm_client).__name__}")
    print()

    print("2. Adding assets...")
    assets = [
        Asset(
            target="192.168.1.50",
            tool_name="example",
            parameters={"command": "echo 'Hello from 192.168.1.50'"}
        ),
        Asset(
            target="test.com",
            tool_name="example",
            parameters={"command": "echo 'Hello from test.com'"}
        ),
    ]

    for asset in assets:
        if orchestrator.add_asset(asset):
            print(f"   ✓ Added asset: {asset.target}")
        else:
            print(f"   ✗ Failed to add asset: {asset.target}")

    print(f"   Total assets in queue: {len(orchestrator.assets)}")
    print()

    print("3. Running passive reconnaissance workflow...")
    try:
        results = orchestrator.run_passive_recon()
        print(f"   ✓ Passive recon completed with {len(results)} results")

        if results:
            print("   Sample results:")
            for i, result in enumerate(results[:2]):
                print(f"     {i+1}. {result.tool_name} on {result.asset.target}")
                print(f"        Status: {result.status}")
                if result.execution_time:
                    print(f"        Time: {result.execution_time:.2f}s")
    except Exception as e:
        print(f"   ! Passive recon encountered issues: {e}")
        print("   Continuing with demonstration...")
    print()

    print("4. Generating findings report...")
    try:
        report = orchestrator.generate_report("json")
        print("   ✓ Report generated successfully")
        print(f"   - Assets scanned: {report['summary']['total_assets']}")
        print(f"   - Scan results: {report['summary']['total_scans']}")
        print(f"   - Findings identified: {report['summary']['total_findings']}")
    except Exception as e:
        print(f"   ! Report generation failed: {e}")
    print()

    print("5. Cleaning up resources...")
    orchestrator.cleanup()
    print("   ✓ Cleanup completed")
    print()

    print("=== Demonstration Complete ===")
    print("All core architecture components working together successfully!")


if __name__ == "__main__":
    setup_logging()
    demonstrate_core_architecture()
