"""
Manual test script for Camera Security Adapter
Tests against the target IP: 213.149.169.247
"""

from src.agent.plugin_manager import PluginManager
from src.adapters.interface import AdapterResultStatus
import json

def test_camera_security():
    """Test the camera security adapter."""
    
    # Initialize plugin manager
    pm = PluginManager()
    pm.discover_adapters()
    
    target_ip = "213.149.169.247"
    print(f"Testing Camera Security Adapter against {target_ip}")
    print("=" * 60)
    
    # Load the adapter with longer timeout
    adapter = pm.load_adapter('camera_security', {
        'timeout': 10,
        'test_credentials': True,
        'max_credential_tests': 5
    })
    
    print(f"\nAdapter Info:")
    info = adapter.get_info()
    print(f"  Name: {info['name']}")
    print(f"  Version: {info['version']}")
    print(f"  Description: {info['description']}")
    print(f"  Ports checked: {info['ports_checked']}")
    
    # Execute the scan
    print(f"\nExecuting scan...")
    result = pm.run_adapter('camera_security', {'target': target_ip})
    
    print(f"\n{'='*60}")
    print(f"SCAN RESULTS for {target_ip}")
    print(f"{'='*60}")
    
    print(f"\nStatus: {result.status.value}")
    
    if result.status == AdapterResultStatus.SUCCESS:
        data = result.data
        print(f"\nTarget: {data['target']}")
        print(f"\nOpen Ports:")
        if data['open_ports']:
            for port_info in data['open_ports']:
                print(f"  - Port {port_info['port']}: {port_info['service']}")
        else:
            print("  None detected")
        
        print(f"\nFindings:")
        for finding in data['findings']:
            print(f"  {finding}")
        
        print(f"\nVulnerabilities Detected: {data.get('vulnerabilities_detected', False)}")
        
        print(f"\nMetadata:")
        print(f"  Checks performed: {result.metadata.get('checks_performed', [])}")
        print(f"  Ports scanned: {len(result.metadata.get('ports_scanned', []))}")
    
    elif result.status == AdapterResultStatus.ERROR:
        print(f"\nError: {result.data.get('error', 'Unknown error')}")
    
    print(f"\n{'='*60}")

if __name__ == "__main__":
    test_camera_security()
