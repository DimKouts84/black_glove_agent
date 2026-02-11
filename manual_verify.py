
import sys
import os
import json
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path.cwd() / "src"))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def run_osint_harvester():
    print("\n" + "="*50)
    print("Running OSINT Harvester against microsoft.com (PASSIVE)")
    print("="*50)
    
    try:
        from adapters.osint_harvester import OSINTHarvesterAdapter
        # Pass empty config
        adapter = OSINTHarvesterAdapter({})
        
        result = adapter.execute({
            "target": "microsoft.com",
            "modules": ["subdomains", "metadata"] 
        })
        
        print(f"\nStatus: {result.status.value}")
        print(f"Subdomains Found: {len(result.data.get('subdomains', []))}")
        if result.data.get('subdomains'):
            print(f"Sample Subdomains: {result.data['subdomains'][:5]}")
        
    except Exception as e:
        print(f"Error: {e}")

def run_web_server_scanner():
    print("\n" + "="*50)
    print("Running Web Server Scanner against scanme.nmap.org (ACTIVE)")
    print("="*50)
    
    try:
        from adapters.web_server_scanner import WebServerScannerAdapter
        adapter = WebServerScannerAdapter({})
        
        result = adapter.execute({
            "target": "scanme.nmap.org"
        })
        
        print(f"\nStatus: {result.status.value}")
        print(f"Findings: {len(result.data.get('findings', []))}")
        if result.data.get('findings'):
            print(f"Sample Findings: {json.dumps(result.data['findings'][:3], indent=2)}")
            
    except Exception as e:
        print(f"Error: {e}")

def run_sqli_scanner():
    print("\n" + "="*50)
    print("Running SQLi Scanner against testphp.vulnweb.com (ACTIVE)")
    print("="*50)
    
    try:
        # Debug: Check manual injection
        import requests
        print("DEBUG: Testing manual injection...")
        resp = requests.get("http://testphp.vulnweb.com/artists.php?artist=1'")
        if "SQL syntax" in resp.text:
            print("DEBUG: Manual injection successful (Error found)")
        else:
            print("DEBUG: Manual injection failed (No error found)")
            
        from adapters.sqli_scanner import SQLiScannerAdapter
        adapter = SQLiScannerAdapter({})
        
        # Scan a specific endpoint known to be vulnerable or the root
        result = adapter.execute({
            "target_url": "http://testphp.vulnweb.com/artists.php?artist=1",
            "techniques": ["error", "boolean"]
        })
        
        print(f"\nStatus: {result.status.value}")
        print(f"Findings: {len(result.data.get('vulnerabilities', []))}")
        if result.data.get('vulnerabilities'):
            print(f"Details: {json.dumps(result.data['vulnerabilities'], indent=2)}")
            
    except Exception as e:
        print(f"Error: {e}")

def run_web_vuln_scanner():
    print("\n" + "="*50)
    print("Running Web Vulnerability Scanner against testphp.vulnweb.com (ACTIVE)")
    print("="*50)
    
    try:
        from adapters.web_vuln_scanner import WebVulnScannerAdapter
        adapter = WebVulnScannerAdapter({})
        
        result = adapter.execute({
            "target_url": "http://testphp.vulnweb.com/search.php?test=query",
            "scans": ["xss", "lfi"]
        })
        
        print(f"\nStatus: {result.status.value}")
        print(f"Findings: {len(result.data.get('vulnerabilities', []))}")
        if result.data.get('vulnerabilities'):
            print(f"Details: {json.dumps(result.data['vulnerabilities'], indent=2)}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run_osint_harvester()
    run_web_server_scanner()
    run_sqli_scanner()
    run_web_vuln_scanner()
