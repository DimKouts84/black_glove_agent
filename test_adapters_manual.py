#!/usr/bin/env python3
"""Test script to verify passive recon adapters work correctly."""
import sys
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

from agent.plugin_manager import create_plugin_manager
from agent.models import load_config_from_file

def test_dns_lookup():
    """Test DNS lookup adapter for gmail.com"""
    print("\n=== Testing DNS Lookup Adapter ===")
    pm = create_plugin_manager()
    
    params = {
        "domain": "gmail.com",
        "record_types": ["A", "MX", "TXT", "NS"]
    }
    
    result = pm.run_adapter("dns_lookup", params)
    print(f"Status: {result.status}")
    if result.data:
        print(f"Data keys: {list(result.data.keys())}")
        for key, value in list(result.data.items())[:5]:  # First 5 items
            if isinstance(value, list):
                print(f"  {key}: {len(value)} items - {value[:2]}")
            else:
                print(f"  {key}: {value}")
    if result.metadata:
        print(f"Metadata: {result.metadata}")
    return result

def test_passive_recon():
    """Test passive recon adapter for gmail.com"""
    print("\n=== Testing Passive Recon Adapter ===")
    pm = create_plugin_manager()
    
    params = {
        "domain": "gmail.com"
    }
    
    result = pm.run_adapter("passive_recon", params)
    print(f"Status: {result.status}")
    if result.data:
        print(f"Data keys: {list(result.data.keys())}")
        for key, value in result.data.items():
            if isinstance(value, list):
                print(f"  {key}: {len(value)} items")
                if value:
                    print(f"    Sample: {value[0]}")
            else:
                print(f"  {key}: {value}")
    if result.metadata:
        print(f"Metadata: {result.metadata}")
    return result

if __name__ == "__main__":
    try:
        dns_result = test_dns_lookup()
        print("\n" + "="*60)
        passive_result = test_passive_recon()
        print("\n" + "="*60)
        print("\n✅ All adapters tested successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
