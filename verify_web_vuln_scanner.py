
import logging
from src.adapters.web_vuln_scanner import create_web_vuln_scanner_adapter

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    adapter = create_web_vuln_scanner_adapter()
    
    # Known XSS target
    target_url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    
    print(f"Running Web Vuln Scanner against: {target_url}")
    
    result = adapter.execute({
        "target_url": target_url,
        "scans": ["xss", "lfi", "ssti", "headers"]
    })
    
    print(f"\nStatus: {result.status}")
    print(f"Message: {result.error_message}")
    
    if result.data and "vulnerabilities" in result.data:
        findings = result.data["vulnerabilities"]
        print(f"\nFound {len(findings)} issues:")
        for f in findings:
            print(f"- [{f['severity'].upper()}] {f['type']}: {f.get('parameter', 'N/A')} - {f.get('evidence', '')}")
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()
