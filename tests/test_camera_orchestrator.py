"""
Direct test of camera_security adapter with the orchestrator
"""

import logging
from src.agent.orchestrator import Orchestrator
from src.agent.models import ConfigModel

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def main():
    """Test camera security through orchestrator."""
    
    print("="*70)
    print("CAMERA SECURITY ADAPTER - LIVE TEST")
    print("="*70)
    
    # Initialize orchestrator
    print("\n📋 Initializing orchestrator...")
    try:
        from pathlib import Path
        import yaml
        
        # Load config
        config_path = Path.home() / '.homepentest' / 'config.yaml'
        if config_path.exists():
            with open(config_path, 'r') as f:
                config_dict = yaml.safe_load(f)
        else:
            config_dict = {}
        
        orchestrator = Orchestrator(config_dict)
        print("✓ Orchestrator initialized")
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test parameters
    target_ip = "213.149.169.247"
    
    print(f"\n🎯 Target: {target_ip}")
    print(f"\n📡 Executing camera security scan...")
    print("-"*70)
    
    try:
        # Execute the adapter through the plugin manager
        orchestrator.plugin_manager.discover_adapters()
        result = orchestrator.plugin_manager.run_adapter(
            adapter_name="camera_security",
            params={
                "target": target_ip
            }
        )
        
        print(f"\n{'='*70}")
        print(f"SCAN RESULTS")
        print(f"{'='*70}")
        
        print(f"\n📊 Status: {result.status.value.upper()}")
        
        if result.status.value == "success":
            data = result.data
            
            print(f"\n🎯 Target: {data['target']}")
            
            print(f"\n🔌 Open Ports:")
            if data['open_ports']:
                for port_info in data['open_ports']:
                    print(f"   ├─ Port {port_info['port']}: {port_info['service']}")
            else:
                print("   └─ None detected")
            
            print(f"\n🔍 Findings:")
            for i, finding in enumerate(data['findings'], 1):
                prefix = "   ├─" if i < len(data['findings']) else "   └─"
                print(f"{prefix} {finding}")
            
            vuln_status = data.get('vulnerabilities_detected', False)
            if vuln_status:
                print(f"\n⚠️  VULNERABILITIES DETECTED: YES")
            else:
                print(f"\n✅ VULNERABILITIES DETECTED: NO")
            
            print(f"\n📝 Scan Metadata:")
            metadata = result.metadata
            print(f"   ├─ Ports scanned: {len(metadata.get('ports_scanned', []))}")
            print(f"   ├─ Checks performed: {', '.join(metadata.get('checks_performed', []))}")
            print(f"   └─ Timestamp: {metadata.get('timestamp', 'N/A')}")
        
        elif result.status.value == "error":
            print(f"\n❌ Error: {result.data.get('error', 'Unknown error')}")
            if result.error_message:
                print(f"   Details: {result.error_message}")
        
        print(f"\n{'='*70}")
        print("✅ Test completed successfully")
        print(f"{'='*70}\n")
        
    except Exception as e:
        print(f"\n❌ Execution failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
