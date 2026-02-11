import sys
import os
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from agent.reporting import ReportGenerator, Finding, SeverityLevel, AssetModel, ReportFormat
from agent.models import AssetType

def test_report_generation():
    print("Setting up test data...")
    
    # Create mock assets
    assets = [
        AssetModel(name="example.com", value="192.168.1.10", type=AssetType.HOST),
        AssetModel(name="api.example.com", value="192.168.1.11", type=AssetType.HOST)
    ]
    
    # Create mock findings
    findings = [
        Finding(
            title="Open SQL Injection Vulnerability",
            description="SQL injection vulnerability detected in /api/login parameter 'username'. This allows an attacker to manipulate SQL queries.",
            severity=SeverityLevel.CRITICAL,
            asset_name="api.example.com",
            recommended_fix="Use parameterized queries or prepared statements.",
            evidence_path="evidence/sqli_poc.txt"
        ),
        Finding(
            title="Outdated SSL Certificate",
            description="The SSL certificate for example.com expired on 2025-01-01.",
            severity=SeverityLevel.HIGH,
            asset_name="example.com",
            recommended_fix="Renew the SSL certificate.",
            evidence_path="evidence/ssl_cert.txt"
        ),
        Finding(
            title="Open Port 21 (FTP)",
            description="FTP service is running on port 21. FTP transmits credentials in cleartext.",
            severity=SeverityLevel.MEDIUM,
            asset_name="example.com",
            recommended_fix="Disable FTP and use SFTP/SCP instead."
        ),
        Finding(
            title="Server Header Disclosure",
            description="Server header reveals 'nginx/1.18.0'.",
            severity=SeverityLevel.INFO,
            asset_name="example.com",
            recommended_fix="Configure server to suppress version information."
        )
    ]
    
    metadata = {
        "scan_id": "test_scan_001",
        "duration": "15 minutes",
        "operator": "Black Glove Agent"
    }
    
    print("Initializing ReportGenerator...")
    generator = ReportGenerator()
    
    print("Generating Markdown report...")
    try:
        report_content = generator.generate_report(findings, assets, metadata, ReportFormat.MARKDOWN)
        
        output_path = Path("test_report.md")
        output_path.write_text(report_content, encoding="utf-8")
        
        print(f"Report generated successfully at {output_path.absolute()}")
        print("-" * 50)
        print(report_content[:500] + "...") # Print start of report
        print("-" * 50)
        
    except Exception as e:
        print(f"FAILED to generate report: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_report_generation()
