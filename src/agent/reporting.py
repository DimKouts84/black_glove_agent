"""
Reporting Module for Black Glove Pentest Agent

This module implements comprehensive findings normalization, report generation,
and evidence storage with integrity verification for security assessment results.
"""

import json
import sqlite3
import hashlib
import logging
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from .models import SeverityLevel, AssetModel
from .db import get_db_connection

def _safe_json_default(obj):
    """
    Default JSON serializer for non-serializable types.
    Converts datetime to ISO strings and handles common types like bytes and sets.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except Exception:
            return str(obj)
    if isinstance(obj, set):
        return list(obj)
    # Fallback: if object exposes isoformat use it
    if hasattr(obj, "isoformat"):
        try:
            return obj.isoformat()
        except Exception:
            pass
    return str(obj)


class ReportFormat(Enum):
    """Enumeration of supported report formats."""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"


class EvidenceStorage:
    """
    Manages evidence storage and integrity verification.
    
    Handles raw tool outputs with SHA256 integrity checking
    and organized directory structure as specified in section 14.
    """
    
    def __init__(self, storage_path: str = None):
        """
        Initialize evidence storage.
        
        Args:
            storage_path: Path to store evidence files (defaults to ~/.homepentest/evidence)
        """
        if storage_path is None:
            self.storage_path = Path.home() / ".homepentest" / "evidence"
        else:
            self.storage_path = Path(storage_path)
        
        self.logger = logging.getLogger("black_glove.reporting.evidence")
        self._ensure_storage_directory()
    
    def _ensure_storage_directory(self) -> None:
        """Ensure evidence storage directory exists."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.logger.debug(f"Evidence storage directory ensured: {self.storage_path}")
    
    def store_evidence(self, content: Union[str, bytes], filename: str, 
                      asset_name: str = None) -> Dict[str, str]:
        """
        Store evidence with integrity verification.
        
        Args:
            content: Evidence content (string or bytes)
            filename: Evidence filename
            asset_name: Optional asset name for directory organization
            
        Returns:
            Dictionary with evidence metadata including hash
        """
        # Create asset-specific directory if provided
        if asset_name:
            asset_dir = self.storage_path / asset_name
            asset_dir.mkdir(exist_ok=True)
            evidence_path = asset_dir / filename
        else:
            evidence_path = self.storage_path / filename
        
        # Write content to file
        if isinstance(content, str):
            evidence_path.write_text(content, encoding='utf-8')
            content_bytes = content.encode('utf-8')
        else:
            evidence_path.write_bytes(content)
            content_bytes = content
        
        # Calculate SHA256 hash for integrity verification
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        
        # Store metadata
        metadata = {
            "path": str(evidence_path),
            "hash": sha256_hash,
            "size": len(content_bytes),
            "timestamp": datetime.now().isoformat(),
            "filename": filename
        }
        
        self.logger.debug(f"Evidence stored: {filename} (SHA256: {sha256_hash[:16]}...)")
        return metadata
    
    def verify_integrity(self, evidence_path: str, expected_hash: str) -> bool:
        """
        Verify evidence file integrity using SHA256 hash.
        
        Args:
            evidence_path: Path to evidence file
            expected_hash: Expected SHA256 hash
            
        Returns:
            bool: True if integrity verified, False otherwise
        """
        try:
            path = Path(evidence_path)
            if not path.exists():
                self.logger.warning(f"Evidence file not found: {evidence_path}")
                return False
            
            content = path.read_bytes()
            actual_hash = hashlib.sha256(content).hexdigest()
            
            if actual_hash == expected_hash:
                self.logger.debug(f"Integrity verified for: {evidence_path}")
                return True
            else:
                self.logger.warning(f"Integrity check failed for: {evidence_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Integrity verification failed: {evidence_path} - {e}")
            return False
    
    def get_evidence_metadata(self, evidence_path: str) -> Optional[Dict[str, Any]]:
        """
        Get evidence file metadata.
        
        Args:
            evidence_path: Path to evidence file
            
        Returns:
            Dictionary with evidence metadata, or None if file not found
        """
        path = Path(evidence_path)
        if not path.exists():
            return None
        
        stat = path.stat()
        return {
            "path": str(path),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
        }


@dataclass
class Finding:
    """
    Normalized security finding with standardized fields.
    
    Attributes:
        id: Unique finding identifier
        title: Concise finding title
        description: Detailed finding description
        severity: Severity level (low, medium, high, critical)
        confidence: Confidence level (0.0-1.0)
        asset_id: Associated asset ID
        asset_name: Associated asset name
        evidence_path: Path to evidence file
        evidence_hash: SHA256 hash of evidence for integrity
        recommended_fix: Remediation guidance
        references: Related references and resources
        cvss_score: Optional CVSS score
        created_at: Finding creation timestamp
    """
    id: Optional[int] = None
    title: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = 0.8
    asset_id: Optional[int] = None
    asset_name: str = ""
    evidence_path: Optional[str] = None
    evidence_hash: Optional[str] = None
    recommended_fix: str = ""
    references: List[str] = None
    cvss_score: Optional[float] = None
    created_at: str = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.references is None:
            self.references = []
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        data = asdict(self)
        data['severity'] = self.severity.value if self.severity else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary."""
        if 'severity' in data and isinstance(data['severity'], str):
            data['severity'] = SeverityLevel(data['severity'])
        return cls(**data)


class FindingsNormalizer:
    """
    Normalizes tool adapter outputs to standardized finding format.
    
    Converts various tool outputs into consistent finding representations
    that can be stored in the database and included in reports.
    """
    
    def __init__(self):
        """Initialize findings normalizer."""
        self.logger = logging.getLogger("black_glove.reporting.normalizer")
        self.evidence_storage = EvidenceStorage()
    
    def normalize_tool_output(self, tool_name: str, tool_output: Any, 
                            asset: AssetModel) -> List[Finding]:
        """
        Normalize tool output to standardized findings.
        
        Args:
            tool_name: Name of the tool that generated the output
            tool_output: Raw tool output
            asset: Asset that was scanned
            
        Returns:
            List of normalized findings
        """
        findings = []
        
        try:
            # Convert tool output to string if needed (use safe serializer for datetimes etc.)
            if isinstance(tool_output, (dict, list)):
                output_str = json.dumps(tool_output, indent=2, default=_safe_json_default)
            else:
                output_str = str(tool_output)
            
            # Store raw output as evidence
            evidence_filename = f"{tool_name}_{asset.name}_{int(datetime.now().timestamp())}.txt"
            evidence_metadata = self.evidence_storage.store_evidence(
                output_str, evidence_filename, asset.name
            )
            
            # Create finding based on tool type
            if tool_name.lower() in ['nmap', 'rustscan', 'masscan']:
                findings.extend(self._normalize_port_scan_output(tool_output, asset, evidence_metadata))
            elif tool_name.lower() in ['gobuster', 'dirb', 'dirsearch']:
                findings.extend(self._normalize_directory_scan_output(tool_output, asset, evidence_metadata))
            elif tool_name.lower() in ['nikto', 'nuclei']:
                findings.extend(self._normalize_vulnerability_scan_output(tool_output, asset, evidence_metadata))
            else:
                # Generic finding for unknown tools
                description = f"Scan results from {tool_name} on {asset.value}"
                
                # Use standard interpretation if available
                if isinstance(tool_output, dict) and "interpretation" in tool_output:
                    description = tool_output["interpretation"]
                    
                finding = Finding(
                    title=f"{tool_name} scan completed on {asset.name}",
                    description=description,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Review scan results for potential issues"
                )
                findings.append(finding)
            
            self.logger.debug(f"Normalized {len(findings)} findings from {tool_name}")
            
        except Exception as e:
            self.logger.error(f"Error normalizing {tool_name} output: {e}")
            # Create error finding
            error_finding = Finding(
                title=f"Error processing {tool_name} results",
                description=f"Failed to normalize {tool_name} output: {str(e)}",
                severity=SeverityLevel.LOW,
                confidence=0.9,
                asset_id=asset.id,
                asset_name=asset.name,
                recommended_fix="Check tool execution and output format"
            )
            findings.append(error_finding)
        
        return findings
    
    def _normalize_port_scan_output(self, output: Any, asset: AssetModel, 
                                  evidence_metadata: Dict[str, str]) -> List[Finding]:
        """Normalize port scan tool output."""
        findings = []
        
        # Example: Check for common high-risk ports
        high_risk_ports = [21, 22, 23, 25, 53, 110, 143, 445, 1433, 3306, 3389, 5432, 5900]
        open_ports = self._extract_open_ports(output)
        
        for port in open_ports:
            if port in high_risk_ports:
                severity = SeverityLevel.HIGH if port in [21, 23, 3389] else SeverityLevel.MEDIUM
                finding = Finding(
                    title=f"High-risk service detected on port {port}",
                    description=f"Service running on port {port} ({self._get_port_service(port)}) "
                              f"may pose security risks if not properly configured.",
                    severity=SeverityLevel.HIGH,
                    confidence=0.95,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix=f"Review service configuration on port {port}, "
                                  f"restrict access if not needed, or implement proper security controls.",
                    references=[
                        f"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search={port}"
                    ]
                )
                findings.append(finding)
        
        return findings
    
    def _normalize_directory_scan_output(self, output: Any, asset: AssetModel, 
                                       evidence_metadata: Dict[str, str]) -> List[Finding]:
        """Normalize directory scanning tool output."""
        findings = []
        
        # Example: Check for sensitive directories/files
        sensitive_paths = [
            '/admin', '/login', '/config', '/backup', '/.git', '/.env',
            '/wp-admin', '/phpmyadmin', '/manager', '/console'
        ]
        found_paths = self._extract_found_paths(output)
        
        for path in found_paths:
            if any(sensitive in path.lower() for sensitive in sensitive_paths):
                finding = Finding(
                    title=f"Sensitive path discovered: {path}",
                    description=f"Directory/file scan revealed potentially sensitive path: {path}",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Restrict access to sensitive paths, implement proper authentication, "
                                  "or remove unnecessary sensitive content.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ]
                )
                findings.append(finding)
        
        return findings
    
    def _normalize_vulnerability_scan_output(self, output: Any, asset: AssetModel, 
                                           evidence_metadata: Dict[str, str]) -> List[Finding]:
        """Normalize vulnerability scanning tool output."""
        findings = []
        
        # This would be more sophisticated in a real implementation
        # For now, create a generic finding
        finding = Finding(
            title=f"Vulnerability scan completed on {asset.name}",
            description="Vulnerability scanning tool executed successfully",
            severity=SeverityLevel.INFO,
            confidence=0.95,
            asset_id=asset.id,
            asset_name=asset.name,
            evidence_path=evidence_metadata["path"],
            evidence_hash=evidence_metadata["hash"],
            recommended_fix="Review detailed vulnerability scan results for specific issues and remediation steps."
        )
        findings.append(finding)
        
        return findings
    
    def _extract_open_ports(self, output: Any) -> List[int]:
        """Extract open ports from scan output."""
        # Simplified extraction - would be more sophisticated in real implementation
        ports = []
        if isinstance(output, dict):
            # Example: {"ports": [{"port": 80, "state": "open"}, ...]}
            if "ports" in output:
                for port_info in output["ports"]:
                    if isinstance(port_info, dict) and port_info.get("state") == "open":
                        ports.append(port_info.get("port", 0))
        elif isinstance(output, str):
            # Simple regex extraction
            # Simple regex extraction for "80/tcp open" or "port 80 open"
            import re
            # Match standard nmap output: 80/tcp open
            port_matches = re.findall(r'(\d+)/(?:tcp|udp)\s+open', output, re.IGNORECASE)
            # Match alternative output: Port 80 open
            if not port_matches:
                port_matches = re.findall(r'port\s+(\d+).*?open', output, re.IGNORECASE)
            
            ports = [int(p) for p in port_matches]
        return ports
    
    def _extract_found_paths(self, output: Any) -> List[str]:
        """Extract found paths from directory scan output."""
        paths = []
        if isinstance(output, dict):
            # Example: {"paths": ["/admin", "/login", ...]}
            if "paths" in output:
                paths = output["paths"]
        elif isinstance(output, str):
            # Simple line-by-line extraction
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip().startswith('/'):
                    paths.append(line.strip().split()[0])
        return paths
    
    def _get_port_service(self, port: int) -> str:
        """Get service name for common ports."""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC"
        }
        return services.get(port, f"Port {port}")


class ReportGenerator:
    """
    Generates security assessment reports in multiple formats.
    
    Creates comprehensive reports with findings, evidence, and remediation guidance
    in JSON, Markdown, HTML, and other supported formats.
    """
    
    def __init__(self):
        """Initialize report generator."""
        self.logger = logging.getLogger("black_glove.reporting.generator")
        self.evidence_storage = EvidenceStorage()
    
    def generate_report(self, findings: List[Finding], assets: List[AssetModel], 
                       metadata: Dict[str, Any], format_type: ReportFormat) -> str:
        """
        Generate security assessment report in specified format.
        
        Args:
            findings: List of security findings
            assets: List of scanned assets
            metadata: Report metadata (scan duration, timestamp, etc.)
            format_type: Desired report format
            
        Returns:
            Generated report content as string
        """
        self.logger.info(f"Generating {format_type.value} report with {len(findings)} findings")
        
        if format_type == ReportFormat.JSON:
            return self._generate_json_report(findings, assets, metadata)
        elif format_type == ReportFormat.MARKDOWN:
            return self._generate_markdown_report_v2(findings, assets, metadata)
        elif format_type == ReportFormat.HTML:
            return self._generate_html_report(findings, assets, metadata)
        elif format_type == ReportFormat.CSV:
            return self._generate_csv_report(findings, assets, metadata)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
    
    def _generate_json_report(self, findings: List[Finding], assets: List[AssetModel], 
                            metadata: Dict[str, Any]) -> str:
        """Generate JSON format report."""
        report_data = {
            "report_info": {
                "title": "Black Glove Security Assessment Report",
                "generated_at": datetime.now().isoformat(),
                "version": "1.0.0",
                **metadata
            },
            "summary": {
                "total_assets": len(assets),
                "total_findings": len(findings),
                "findings_by_severity": self._count_findings_by_severity(findings),
                "critical_findings": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
                "high_findings": len([f for f in findings if f.severity == SeverityLevel.HIGH])
            },
            "assets": [asset.model_dump() for asset in assets],
            "findings": [finding.to_dict() for finding in findings]
        }
        
        return json.dumps(report_data, indent=2, default=_safe_json_default)
    
    def _generate_markdown_report(self, findings: List[Finding], assets: List[AssetModel], 
                                metadata: Dict[str, Any]) -> str:
        """Generate Markdown format report."""
        lines = []
        
        # Report header
        lines.append("# Black Glove Security Assessment Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Version:** 1.0.0")
        lines.append("")
        
        # Metadata section
        lines.append("## Assessment Information")
        lines.append("")
        for key, value in metadata.items():
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
        lines.append("")
        
        # Summary section
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Total Assets Scanned:** {len(assets)}")
        lines.append(f"- **Total Findings:** {len(findings)}")
        lines.append(f"- **Critical Findings:** {len([f for f in findings if f.severity == SeverityLevel.CRITICAL])}")
        lines.append(f"- **High Findings:** {len([f for f in findings if f.severity == SeverityLevel.HIGH])}")
        lines.append("")
        
        # Findings by severity
        severity_counts = self._count_findings_by_severity(findings)
        lines.append("### Findings by Severity")
        lines.append("")
        for severity, count in severity_counts.items():
            lines.append(f"- **{severity.title()}:** {count}")
        lines.append("")
        
        # Assets section
        lines.append("## Scanned Assets")
        lines.append("")
        lines.append("| Name | Type | Value |")
        lines.append("|------|------|-------|")
        for asset in assets:
            lines.append(f"| {asset.name} | {asset.type.value} | {asset.value} |")
        lines.append("")
        
        # Findings section
        lines.append("## Detailed Findings")
        lines.append("")
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Display findings by severity (critical first)
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if severity in findings_by_severity:
                lines.append(f"### {severity.title()} Severity Findings")
                lines.append("")
                for i, finding in enumerate(findings_by_severity[severity], 1):
                    lines.append(f"#### {i}. {finding.title}")
                    lines.append("")
                    lines.append(f"**Description:** {finding.description}")
                    lines.append("")
                    lines.append(f"**Asset:** {finding.asset_name}")
                    lines.append(f"**Confidence:** {finding.confidence:.1%}")
                    if finding.cvss_score:
                        lines.append(f"**CVSS Score:** {finding.cvss_score}")
                    lines.append("")
                    lines.append(f"**Recommended Fix:** {finding.recommended_fix}")
                    lines.append("")
                    if finding.references:
                        lines.append("**References:**")
                        for ref in finding.references:
                            lines.append(f"- {ref}")
                        lines.append("")
                    if finding.evidence_path:
                        lines.append(f"**Evidence:** `{finding.evidence_path}`")
                        lines.append("")
                    lines.append("---")
                    lines.append("")
        
        return "\n".join(lines)
    
    def _generate_html_report(self, findings: List[Finding], assets: List[AssetModel], 
                            metadata: Dict[str, Any]) -> str:
        """Generate HTML format report."""
        # Simple HTML template - would be more sophisticated in real implementation
        html_lines = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>Black Glove Security Assessment Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 40px; }",
            "        h1, h2, h3 { color: #333; }",
            "        .critical { color: #dc3545; }",
            "        .high { color: #fd7e14; }",
            "        .medium { color: #ffc107; }",
            "        .low { color: #28a745; }",
            "        .info { color: #17a2b8; }",
            "        table { border-collapse: collapse; width: 100%; margin: 20px 0; }",
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "        th { background-color: #f2f2f2; }",
            "        .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; }",
            "    </style>",
            "</head>",
            "<body>",
            "<h1>Black Glove Security Assessment Report</h1>",
            f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"<p><strong>Version:</strong> 1.0.0</p>",
            ""
        ]
        
        # Metadata section
        html_lines.append("<h2>Assessment Information</h2>")
        html_lines.append("<ul>")
        for key, value in metadata.items():
            html_lines.append(f"    <li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>")
        html_lines.append("</ul>")
        html_lines.append("")
        
        # Summary section
        html_lines.append("<h2>Executive Summary</h2>")
        html_lines.append("<ul>")
        html_lines.append(f"    <li><strong>Total Assets Scanned:</strong> {len(assets)}</li>")
        html_lines.append(f"    <li><strong>Total Findings:</strong> {len(findings)}</li>")
        html_lines.append(f"    <li><strong>Critical Findings:</strong> {len([f for f in findings if f.severity == SeverityLevel.CRITICAL])}</li>")
        html_lines.append(f"    <li><strong>High Findings:</strong> {len([f for f in findings if f.severity == SeverityLevel.HIGH])}</li>")
        html_lines.append("</ul>")
        html_lines.append("")
        
        # Findings by severity
        severity_counts = self._count_findings_by_severity(findings)
        html_lines.append("<h3>Findings by Severity</h3>")
        html_lines.append("<ul>")
        for severity, count in severity_counts.items():
            html_lines.append(f"    <li><strong>{severity.title()}: {count}</li>")
        html_lines.append("</ul>")
        html_lines.append("")
        
        # Assets section
        html_lines.append("<h2>Scanned Assets</h2>")
        html_lines.append("<table>")
        html_lines.append("    <tr><th>Name</th><th>Type</th><th>Value</th></tr>")
        for asset in assets:
            html_lines.append(f"    <tr><td>{asset.name}</td><td>{asset.type.value}</td><td>{asset.value}</td></tr>")
        html_lines.append("</table>")
        html_lines.append("")
        
        # Findings section
        html_lines.append("<h2>Detailed Findings</h2>")
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Display findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if severity in findings_by_severity:
                html_lines.append(f"<h3 class='{severity}'>{severity.title()} Severity Findings</h3>")
                for i, finding in enumerate(findings_by_severity[severity], 1):
                    html_lines.append(f"<div class='finding {severity}'>")
                    html_lines.append(f"    <h4>{i}. {finding.title}</h4>")
                    html_lines.append(f"    <p><strong>Description:</strong> {finding.description}</p>")
                    html_lines.append(f"    <p><strong>Asset:</strong> {finding.asset_name}</p>")
                    html_lines.append(f"    <p><strong>Confidence:</strong> {finding.confidence:.1%}</p>")
                    if finding.cvss_score:
                        html_lines.append(f"    <p><strong>CVSS Score:</strong> {finding.cvss_score}</p>")
                    html_lines.append(f"    <p><strong>Recommended Fix:</strong> {finding.recommended_fix}</p>")
                    if finding.references:
                        html_lines.append("    <p><strong>References:</strong></p>")
                        html_lines.append("    <ul>")
                        for ref in finding.references:
                            html_lines.append(f"        <li>{ref}</li>")
                        html_lines.append("    </ul>")
                    if finding.evidence_path:
                        html_lines.append(f"    <p><strong>Evidence:</strong> <code>{finding.evidence_path}</code></p>")
                    html_lines.append("</div>")
                    html_lines.append("")
        
        html_lines.extend([
            "</body>",
            "</html>"
        ])
        
        return "\n".join(html_lines)
    
    def _generate_csv_report(self, findings: List[Finding], assets: List[AssetModel], 
                           metadata: Dict[str, Any]) -> str:
        """Generate CSV format report."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(["Black Glove Security Assessment Report"])
        writer.writerow(["Generated", datetime.now().isoformat()])
        writer.writerow([])
        
        # Metadata
        writer.writerow(["Assessment Information"])
        for key, value in metadata.items():
            writer.writerow([key.replace('_', ' ').title(), str(value)])
        writer.writerow([])
        
        # Summary
        writer.writerow(["Executive Summary"])
        writer.writerow(["Total Assets Scanned", len(assets)])
        writer.writerow(["Total Findings", len(findings)])
        writer.writerow(["Critical Findings", len([f for f in findings if f.severity == SeverityLevel.CRITICAL])])
        writer.writerow(["High Findings", len([f for f in findings if f.severity == SeverityLevel.HIGH])])
        writer.writerow([])
        
        # Findings
        writer.writerow(["Findings"])
        writer.writerow([
            "ID", "Title", "Severity", "Asset", "Description", 
            "Confidence", "CVSS Score", "Recommended Fix", "Evidence Path"
        ])
        
        for finding in findings:
            writer.writerow([
                finding.id or "",
                finding.title,
                finding.severity.value,
                finding.asset_name,
                finding.description[:100] + "..." if len(finding.description) > 100 else finding.description,
                f"{finding.confidence:.1%}",
                finding.cvss_score or "",
                finding.recommended_fix[:50] + "..." if len(finding.recommended_fix) > 50 else finding.recommended_fix,
                finding.evidence_path or ""
            ])
        
        return output.getvalue()
    
    def _count_findings_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _generate_markdown_report_v2(self, findings: List[Finding], assets: List[AssetModel], 
                                   metadata: Dict[str, Any]) -> str:
        """
        Generate Markdown report using Jinja2 template and Pydantic models.
        This is the new "thin/structured" format.
        """
        from .report_models import (
            FullReport, ExecutiveSummary, AssetReport, 
            Finding as ReportFinding, Severity as ReportSeverity
        )
        from jinja2 import Environment, FileSystemLoader
        
        # 1. Map Internal Findings -> Report Findings
        report_findings = []
        for f in findings:
            severity_map = {
                "critical": ReportSeverity.CRITICAL,
                "high": ReportSeverity.HIGH,
                "medium": ReportSeverity.MEDIUM,
                "low": ReportSeverity.LOW,
                "info": ReportSeverity.INFO
            }
            
            report_findings.append(ReportFinding(
                title=f.title,
                severity=severity_map.get(f.severity.value, ReportSeverity.INFO),
                description=f.description,
                remediation=f.recommended_fix,
                evidence=[f.evidence_path] if f.evidence_path else [],
                affected_assets=[f.asset_name]
            ))
            
        # 2. Map Assets -> Asset Reports
        asset_reports = []
        for asset in assets:
            # Find findings for this asset
            asset_specific_findings = [
                rf for rf in report_findings 
                if asset.name in rf.affected_assets
            ]
            
            asset_reports.append(AssetReport(
                target=asset.name,
                ip_addresses=[asset.value] if asset.type.value == "host" else [],
                findings=asset_specific_findings
                # tech_stack and open_ports would be populated from refined asset data if available
            ))

        # 3. Create Executive Summary
        severity_counts = self._count_findings_by_severity(findings)
        risk_score = 10.0
        if severity_counts.get("critical", 0) > 0:
            risk_score = 2.0
        elif severity_counts.get("high", 0) > 0:
            risk_score = 4.0
        elif severity_counts.get("medium", 0) > 0:
            risk_score = 6.0
        elif severity_counts.get("low", 0) > 0:
            risk_score = 8.0
            
        # Get top 5 critical/high findings for summary
        key_findings = sorted(
            [f for f in report_findings if f.severity in [ReportSeverity.CRITICAL, ReportSeverity.HIGH]],
            key=lambda x: x.severity.value
        )[:5]

        exec_summary = ExecutiveSummary(
            overview=f"Security assessment conducted on {len(assets)} assets. Found {len(findings)} issues.",
            risk_score=risk_score,
            key_findings=key_findings,
            recommendations=[
                "Remediate critical vulnerabilities immediately.",
                "Review high severity findings within 48 hours."
            ]
        )

        # 4. Build Full Report Model
        full_report = FullReport(
            target=assets[0].name if assets else "Unknown Target",
            executive_summary=exec_summary,
            assets=asset_reports,
            all_findings=report_findings
        )
        
        # 5. Render Template
        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        template = env.get_template("professional_report.md.j2")
        
        return template.render(report=full_report)


class ReportingManager:
    """
    Main reporting manager that coordinates findings normalization and report generation.
    
    Integrates with database to retrieve findings and assets, normalizes tool outputs,
    and generates comprehensive security assessment reports.
    """
    
    def __init__(self, db_connection=None):
        """
        Initialize reporting manager.
        
        Args:
            db_connection: Optional database connection
        """
        self.db_connection = db_connection or get_db_connection()
        self.logger = logging.getLogger("black_glove.reporting.manager")
        self.findings_normalizer = FindingsNormalizer()
        self.report_generator = ReportGenerator()
        self.evidence_storage = EvidenceStorage()
    
    def get_findings_from_database(self) -> List[Finding]:
        """
        Retrieve findings from database.
        
        Returns:
            List of findings from database
        """
        findings = []
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                SELECT id, title, severity, confidence, asset_id, evidence_path, 
                       recommended_fix, created_at
                FROM findings
                ORDER BY severity, created_at DESC
            """)
            
            rows = cursor.fetchall()
            for row in rows:
                finding = Finding(
                    id=row[0],
                    title=row[1],
                    severity=SeverityLevel(row[2]) if row[2] else SeverityLevel.MEDIUM,
                    confidence=row[3] or 0.8,
                    asset_id=row[4],
                    evidence_path=row[5],
                    recommended_fix=row[6] or "",
                    created_at=row[7]
                )
                findings.append(finding)
            
            self.logger.debug(f"Retrieved {len(findings)} findings from database")
            
        except Exception as e:
            self.logger.error(f"Error retrieving findings from database: {e}")
        
        return findings
    
    def get_assets_from_database(self) -> List[AssetModel]:
        """
        Retrieve assets from database.
        
        Returns:
            List of assets from database
        """
        assets = []
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT id, name, type, value FROM assets ORDER BY name")
            
            rows = cursor.fetchall()
            for row in rows:
                asset = AssetModel(
                    id=row[0],
                    name=row[1],
                    type=row[2],
                    value=row[3]
                )
                assets.append(asset)
            
            self.logger.debug(f"Retrieved {len(assets)} assets from database")
            
        except Exception as e:
            self.logger.error(f"Error retrieving assets from database: {e}")
        
        return assets
    
    def save_findings_to_database(self, findings: List[Finding]) -> None:
        """
        Save findings to database.
        
        Args:
            findings: List of findings to save
        """
        try:
            cursor = self.db_connection.cursor()
            
            for finding in findings:
                cursor.execute("""
                    INSERT INTO findings 
                    (asset_id, title, severity, confidence, evidence_path, recommended_fix)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    finding.asset_id,
                    finding.title,
                    finding.severity.value,
                    finding.confidence,
                    finding.evidence_path,
                    finding.recommended_fix
                ))
            
            self.db_connection.commit()
            self.logger.info(f"Saved {len(findings)} findings to database")
            
        except Exception as e:
            self.logger.error(f"Error saving findings to database: {e}")
            self.db_connection.rollback()
    
    def generate_assessment_report(self, format_type: ReportFormat = ReportFormat.JSON,
                                 include_evidence: bool = True) -> str:
        """
        Generate comprehensive security assessment report.
        
        Args:
            format_type: Desired report format
            include_evidence: Whether to include evidence files
            
        Returns:
            Generated report content
        """
        self.logger.info(f"Generating assessment report in {format_type.value} format")
        
        # Get data from database
        findings = self.get_findings_from_database()
        assets = self.get_assets_from_database()
        
        # Generate metadata
        metadata = {
            "scan_duration": "N/A",  # Would be calculated from orchestrator
            "total_scans": len(findings),
            "report_format": format_type.value,
            "include_evidence": include_evidence
        }
        
        # Generate report
        report_content = self.report_generator.generate_report(
            findings, assets, metadata, format_type
        )
        
        self.logger.info("Assessment report generation completed")
        return report_content
    
    def cleanup(self) -> None:
        """Clean up resources."""
        if hasattr(self.db_connection, 'close'):
            self.db_connection.close()
        self.logger.debug("Reporting manager cleanup completed")


# Factory function for creating reporting manager instances
def create_reporting_manager(db_connection=None) -> ReportingManager:
    """
    Factory function to create a reporting manager instance.
    
    Args:
        db_connection: Optional database connection
        
    Returns:
        ReportingManager: Configured reporting manager instance
    """
    return ReportingManager(db_connection)


# Add the missing import to CLI
def _create_reporting_manager_for_cli():
    """Helper function for CLI import."""
    try:
        return create_reporting_manager()
    except Exception:
        return None


# Context manager for reporting manager
class ReportingContext:
    """
    Context manager for reporting manager to ensure proper cleanup.
    """
    
    def __init__(self, db_connection=None):
        self.db_connection = db_connection
        self.reporting_manager = None
    
    def __enter__(self):
        self.reporting_manager = create_reporting_manager(self.db_connection)
        return self.reporting_manager
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.reporting_manager:
            self.reporting_manager.cleanup()
