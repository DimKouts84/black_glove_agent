"""
Reporting Module for Black Glove Pentest Agent

This module implements comprehensive findings normalization, report generation,
and evidence storage with integrity verification for security assessment results.
"""

import json
import sqlite3
import hashlib
import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from .models import SeverityLevel, AssetModel, severity_for_db
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
    source_tool: str = ""
    verification_state: str = "indicator"
    fingerprint: Optional[str] = None
    observation_count: int = 1
    run_id: Optional[str] = None
    step_id: Optional[str] = None
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
            if tool_name.lower() in ['nmap', 'rustscan', 'masscan', 'viewdns']:
                findings.extend(self._normalize_port_scan_output(
                    tool_output, asset, evidence_metadata, tool_name=tool_name.lower()
                ))
            elif tool_name.lower() in ['gobuster', 'dirb', 'dirsearch']:
                findings.extend(self._normalize_directory_scan_output(tool_output, asset, evidence_metadata))
            elif tool_name.lower() in ['nikto', 'nuclei']:
                findings.extend(self._normalize_vulnerability_scan_output(tool_output, asset, evidence_metadata))
            elif tool_name.lower() in ['web_vuln_scanner', 'sqli_scanner', 'web_server_scanner']:
                findings.extend(self._normalize_web_scan_output(
                    tool_name, tool_output, asset, evidence_metadata
                ))
            elif tool_name.lower() in [
                'passive_recon', 'osint_harvester', 'credential_tester', 'camera_security'
            ]:
                findings.extend(self._normalize_specialized_intel_output(
                    tool_name, tool_output, asset, evidence_metadata
                ))
            elif tool_name.lower() in [
                'dns_lookup', 'dns_recon', 'whois', 'ssl_check', 'public_ip'
            ]:
                findings.extend(self._normalize_network_infra_output(
                    tool_name, tool_output, asset, evidence_metadata
                ))
            elif tool_name.lower() in ['wappalyzer', 'sublist3r']:
                findings.extend(self._normalize_web_intel_wrapper_output(
                    tool_name, tool_output, asset, evidence_metadata
                ))
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

            for finding in findings:
                if not finding.source_tool:
                    finding.source_tool = tool_name

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
                recommended_fix="Check tool execution and output format",
                source_tool=tool_name,
            )
            findings.append(error_finding)

        return findings
    
    def _normalize_port_scan_output(self, output: Any, asset: AssetModel, 
                                  evidence_metadata: Dict[str, str],
                                  tool_name: str = "nmap") -> List[Finding]:
        """Normalize port scan tool output."""
        findings = []
        
        # Example: Check for common high-risk ports
        high_risk_ports = [21, 22, 23, 25, 53, 110, 143, 445, 1433, 3306, 3389, 5432, 5900]
        open_ports = self._extract_open_ports(output)
        port_services = self._extract_port_services(output)
        
        for port in open_ports:
            if port in high_risk_ports:
                severity = SeverityLevel.HIGH if port in [21, 23, 3389] else SeverityLevel.MEDIUM
                finding = Finding(
                    title=f"High-risk service detected on port {port}",
                    description=f"Service running on port {port} ({port_services.get(port) or self._get_port_service(port)}) "
                              f"may pose security risks if not properly configured.",
                    severity=severity,
                    confidence=0.95,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix=f"Review service configuration on port {port}, "
                                  f"restrict access if not needed, or implement proper security controls.",
                    references=[
                        f"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search={port}"
                    ],
                    source_tool=tool_name,
                )
                findings.append(finding)

        if open_ports:
            port_details = []
            for port in sorted(set(open_ports)):
                service = port_services.get(port) or self._get_port_service(port)
                port_details.append(f"{port}/{service}")
            findings.append(Finding(
                title=f"Open ports discovered ({len(set(open_ports))})",
                description=", ".join(port_details),
                severity=SeverityLevel.INFO,
                confidence=0.95,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                recommended_fix="Review exposed services and close unnecessary ports.",
                verification_state="informational",
                source_tool=tool_name,
            ))
        
        return findings
    
    def _normalize_directory_scan_output(self, output: Any, asset: AssetModel, 
                                       evidence_metadata: Dict[str, str]) -> List[Finding]:
        """Normalize directory scanning tool output."""
        findings = []
        
        sensitive_paths = [
            '/admin', '/login', '/config', '/backup', '/.git', '/.env',
            '/wp-admin', '/phpmyadmin', '/manager', '/console'
        ]
        critical_paths = ['/.env', '/.git', '/config', '/backup']

        entries = self._extract_dir_entries(output)
        if entries:
            for entry in entries:
                path = entry.get("path") or entry.get("host", "")
                if not path:
                    continue
                if not any(sensitive in path.lower() for sensitive in sensitive_paths):
                    continue
                status = entry.get("status")
                if entry.get("severity"):
                    severity = self._map_severity(entry["severity"])
                elif status == 200:
                    severity = (
                        SeverityLevel.CRITICAL
                        if any(c in path.lower() for c in critical_paths)
                        else SeverityLevel.HIGH
                    )
                elif status in (401, 403):
                    severity = SeverityLevel.MEDIUM
                elif status in (301, 302, 307):
                    severity = SeverityLevel.LOW
                else:
                    severity = SeverityLevel.MEDIUM
                confidence = 0.95 if status == 200 else 0.7
                findings.append(Finding(
                    title=f"Sensitive path discovered: {path}",
                    description=(
                        f"Directory scan revealed potentially sensitive path: {path}"
                        + (f" (HTTP {status})" if status else "")
                    ),
                    severity=severity,
                    confidence=confidence,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Restrict access to sensitive paths, implement proper authentication, "
                                  "or remove unnecessary sensitive content.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ]
                ))
            return findings

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
            severity=SeverityLevel.LOW,
            confidence=0.95,
            asset_id=asset.id,
            asset_name=asset.name,
            evidence_path=evidence_metadata["path"],
            evidence_hash=evidence_metadata["hash"],
            recommended_fix="Review detailed vulnerability scan results for specific issues and remediation steps."
        )
        findings.append(finding)
        
        return findings

    def _map_severity(self, severity_str: str) -> SeverityLevel:
        mapping = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.LOW,
            "error": SeverityLevel.HIGH,
        }
        return mapping.get(str(severity_str).lower(), SeverityLevel.MEDIUM)

    @staticmethod
    def _normalize_subdomain_label(name: str) -> str:
        label = str(name).strip().lower()
        if label.startswith("*."):
            label = label[2:]
        return label

    @classmethod
    def _normalize_subdomain_names(cls, names: Iterable[str]) -> List[str]:
        seen: set = set()
        ordered: List[str] = []
        for name in names:
            if not name:
                continue
            normalized = cls._normalize_subdomain_label(name)
            if normalized and normalized not in seen:
                seen.add(normalized)
                ordered.append(normalized)
        return sorted(ordered)

    @classmethod
    def _subdomain_fingerprint(cls, asset_id: int, names: Iterable[str]) -> str:
        normalized = cls._normalize_subdomain_names(names)
        raw = f"{asset_id}|subdomains|{'|'.join(normalized)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _emit_subdomain_finding(
        self,
        asset: AssetModel,
        names: Iterable[str],
        source_tool: str,
        evidence_metadata: Dict[str, str],
    ) -> Optional[Finding]:
        normalized = self._normalize_subdomain_names(names)
        if not normalized:
            return None
        sample = normalized[:5]
        finding = Finding(
            title=f"Subdomains discovered ({len(normalized)})",
            description=f"Sources: {source_tool}; sample: {', '.join(sample)}",
            severity=SeverityLevel.LOW,
            confidence=0.9,
            asset_id=asset.id,
            asset_name=asset.name,
            evidence_path=evidence_metadata["path"],
            evidence_hash=evidence_metadata["hash"],
            source_tool=source_tool,
            recommended_fix="Review subdomain attack surface.",
        )
        finding.fingerprint = self._subdomain_fingerprint(asset.id, normalized)
        return finding

    def reconcile_cross_tool_conflicts(
        self,
        findings: List[Finding],
        *,
        run_id: Optional[str] = None,
        current_findings: Optional[List[Finding]] = None,
    ) -> List[Finding]:
        """
        Reconcile contradictory observations from different tools on the same asset.

        When run_id is set, only findings from that run (plus current_findings) are
        considered. Returns findings mutated during this call (for persistence).
        """
        current_batch_ids = {id(f) for f in (current_findings or [])}
        mutated: List[Finding] = []

        def _in_scope(finding: Finding) -> bool:
            if run_id is None:
                return True
            if id(finding) in current_batch_ids:
                return True
            return finding.run_id == run_id

        by_asset: Dict[int, List[Finding]] = {}
        for finding in findings:
            if finding.asset_id is None or not _in_scope(finding):
                continue
            by_asset.setdefault(finding.asset_id, []).append(finding)

        for asset_findings in by_asset.values():
            wappalyzer_hsts = [
                f for f in asset_findings
                if f.source_tool == "wappalyzer"
                and f.title == "Technology detected: HSTS"
            ]
            missing_hsts = [
                f for f in asset_findings
                if f.source_tool == "web_server_scanner"
                and f.title == "Missing Strict-Transport-Security"
            ]
            if not wappalyzer_hsts or not missing_hsts:
                continue

            for finding in missing_hsts:
                if finding.verification_state == "conflicted":
                    continue
                before = (
                    finding.severity,
                    finding.verification_state,
                    finding.description,
                    finding.recommended_fix,
                )
                finding.severity = SeverityLevel.INFO
                finding.verification_state = "conflicted"
                finding.description = (
                    "HSTS inferred by fingerprinting but absent in direct response headers; "
                    "verify redirect chain and preload configuration."
                )
                finding.recommended_fix = (
                    "Confirm whether HSTS is enforced via HTTPS redirect, CDN, or preload; "
                    "add Strict-Transport-Security on origin if missing."
                )
                after = (
                    finding.severity,
                    finding.verification_state,
                    finding.description,
                    finding.recommended_fix,
                )
                if before != after:
                    mutated.append(finding)

        return mutated

    def _normalize_web_scan_output(
        self,
        tool_name: str,
        output: Any,
        asset: AssetModel,
        evidence_metadata: Dict[str, str],
    ) -> List[Finding]:
        """Normalize web_vuln_scanner, sqli_scanner, and web_server_scanner output."""
        findings: List[Finding] = []

        if not isinstance(output, dict):
            return findings

        if tool_name.lower() == "web_server_scanner":
            items = output.get("findings", [])
            skip_severities = {"OK", "INFO"}
            for item in items:
                sev_str = str(item.get("severity", "MEDIUM")).upper()
                if sev_str in skip_severities:
                    continue

                title = item.get("title", "Web server finding")
                detail = item.get("detail", "")
                note = item.get("note")
                if note:
                    detail = f"{detail} ({note})"
                confidence = float(item.get("confidence", 0.75))
                sev = self._map_severity(sev_str)
                verification_state = "indicator"

                response_url = str(item.get("response_url", ""))
                is_http_scan = (
                    item.get("context") == "http_scan"
                    or response_url.lower().startswith("http://")
                )
                if title == "Missing Strict-Transport-Security" and is_http_scan:
                    sev = SeverityLevel.INFO
                    verification_state = "informational"

                findings.append(Finding(
                    title=title,
                    description=detail,
                    severity=sev,
                    confidence=confidence,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    source_tool=tool_name,
                    verification_state=verification_state,
                    recommended_fix="Review and remediate the identified web server misconfiguration.",
                ))
        else:
            for vuln in output.get("vulnerabilities", []):
                vuln_type = vuln.get("type", "unknown")
                param = vuln.get("parameter", "")
                url = vuln.get("url", output.get("target_url", asset.value))
                evidence = vuln.get("evidence", "")
                sev_str = vuln.get("severity", "medium")
                confidence = float(vuln.get("confidence", 0.7))

                title = f"{tool_name}: {vuln_type}"
                if param:
                    title += f" in parameter '{param}'"

                description = evidence or f"Detected at {url}"
                if vuln.get("payload"):
                    description += f" (payload: {vuln['payload']})"

                fix_map = {
                    "xss_reflected": "Encode output and validate input; deploy CSP.",
                    "path_traversal": "Sanitize file paths; use allowlists for includes.",
                    "ssti": "Never pass user input to template engines.",
                    "error_based": "Use parameterized queries; review error handling.",
                    "boolean_blind": "Use parameterized queries; verify with manual testing.",
                    "time_blind": "Use parameterized queries; verify with manual testing.",
                }

                findings.append(Finding(
                    title=title,
                    description=description,
                    severity=self._map_severity(sev_str),
                    confidence=confidence,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix=fix_map.get(
                        vuln_type, "Review scan evidence and validate manually."
                    ),
                ))

        if not findings:
            coverage = output.get("coverage") or {}
            if output.get("not_applicable") or coverage.get("untested"):
                return findings
            findings.append(Finding(
                title=f"{tool_name} scan completed on {asset.name}",
                description=(
                    output.get("interpretation")
                    or f"No actionable issues from {tool_name}."
                ),
                severity=SeverityLevel.LOW,
                confidence=0.95,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                source_tool=tool_name,
                recommended_fix="No immediate action required based on automated scan.",
            ))

        return findings

    def _normalize_specialized_intel_output(
        self,
        tool_name: str,
        output: Any,
        asset: AssetModel,
        evidence_metadata: Dict[str, str],
    ) -> List[Finding]:
        """Normalize passive_recon, osint_harvester, credential_tester, camera_security."""
        findings: List[Finding] = []

        if not isinstance(output, dict):
            return findings

        tool = tool_name.lower()

        if tool == "passive_recon":
            for secret in output.get("potential_secrets", []):
                sev_str = secret.get("severity", "low")
                confidence = float(secret.get("confidence", 0.5))
                findings.append(Finding(
                    title=f"Passive recon indicator: {secret.get('type', 'unknown')}",
                    description=(
                        f"Match '{secret.get('match')}' in archived URL {secret.get('url')} "
                        f"(indicator only — content not verified)"
                    ),
                    severity=self._map_severity(sev_str),
                    confidence=confidence,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Manually verify archived URL; rotate credentials if confirmed.",
                ))

            crt_sh = output.get("crt_sh") or {}
            cert_names: List[str] = []
            for cert in crt_sh.get("certificates") or []:
                for name in cert.get("name_value") or []:
                    if name:
                        cert_names.append(str(name).strip())
            subdomain_finding = self._emit_subdomain_finding(
                asset, cert_names, tool_name, evidence_metadata
            )
            if subdomain_finding:
                findings.append(subdomain_finding)

        elif tool == "credential_tester":
            for cred in output.get("valid_credentials", []):
                findings.append(Finding(
                    title=f"Valid credentials found ({output.get('protocol', 'unknown')})",
                    description=(
                        f"Username '{cred.get('username')}' authenticated on "
                        f"{output.get('target')}:{output.get('port')}"
                    ),
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.9,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Change credentials immediately and restrict access.",
                ))

        elif tool == "camera_security":
            for finding_text in output.get("findings", []):
                if not isinstance(finding_text, str):
                    continue
                if finding_text.startswith("✓"):
                    continue
                if "CRITICAL" in finding_text:
                    sev = SeverityLevel.CRITICAL
                elif "VULNERABILITY" in finding_text or "RISK" in finding_text:
                    sev = SeverityLevel.HIGH
                else:
                    sev = SeverityLevel.MEDIUM
                findings.append(Finding(
                    title="Camera security finding",
                    description=finding_text,
                    severity=sev,
                    confidence=0.75,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Restrict camera access, disable anonymous streams, change defaults.",
                ))

        elif tool == "osint_harvester":
            emails = output.get("emails", [])
            subdomains = output.get("subdomains", [])
            if emails:
                findings.append(Finding(
                    title=f"OSINT emails discovered ({len(emails)})",
                    description=f"Sample: {', '.join(emails[:5])}",
                    severity=SeverityLevel.LOW,
                    confidence=0.85,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Review exposed contact information for privacy impact.",
                ))
            if subdomains:
                subdomain_finding = self._emit_subdomain_finding(
                    asset, subdomains, tool_name, evidence_metadata
                )
                if subdomain_finding:
                    findings.append(subdomain_finding)

        if not findings:
            description = output.get("interpretation") or f"No actionable issues from {tool_name}."
            coverage = output.get("coverage") or {}
            errors = output.get("errors") or {}
            if tool == "passive_recon":
                if coverage.get("crt_sh_ok") or coverage.get("wayback_ok"):
                    return findings
                if errors and not coverage.get("crt_sh_ok") and not coverage.get("wayback_ok"):
                    return findings
            findings.append(Finding(
                title=f"{tool_name} scan completed on {asset.name}",
                description=description,
                severity=SeverityLevel.LOW,
                confidence=0.95,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                recommended_fix="No immediate action required based on automated scan.",
            ))

        return findings

    def _normalize_network_infra_output(
        self,
        tool_name: str,
        output: Any,
        asset: AssetModel,
        evidence_metadata: Dict[str, str],
    ) -> List[Finding]:
        """Normalize dns_lookup, dns_recon, whois, ssl_check, public_ip output."""
        findings: List[Finding] = []

        if not isinstance(output, dict):
            return findings

        tool = tool_name.lower()

        if tool == "dns_lookup":
            for rtype, rtype_data in output.get("records", {}).items():
                records = rtype_data.get("records", [])
                error = rtype_data.get("error")
                if records:
                    findings.append(Finding(
                        title=f"DNS {rtype} records for {output.get('domain', asset.name)}",
                        description=f"{rtype}: {', '.join(records[:5])}"
                        + (f" (+{len(records) - 5} more)" if len(records) > 5 else ""),
                        severity=SeverityLevel.LOW,
                        confidence=0.9,
                        asset_id=asset.id,
                        asset_name=asset.name,
                        evidence_path=evidence_metadata["path"],
                        evidence_hash=evidence_metadata["hash"],
                        recommended_fix="Review DNS records for misconfigurations or data exposure.",
                    ))
                elif error:
                    benign_no_record = {
                        "No answer for record type",
                        "Domain does not exist",
                    }
                    if str(error) in benign_no_record:
                        continue
                    findings.append(Finding(
                        title=f"DNS {rtype} query issue",
                        description=str(error),
                        severity=SeverityLevel.INFO,
                        confidence=0.85,
                        asset_id=asset.id,
                        asset_name=asset.name,
                        evidence_path=evidence_metadata["path"],
                        evidence_hash=evidence_metadata["hash"],
                        recommended_fix="Verify DNS configuration.",
                        verification_state="informational",
                    ))

        elif tool == "dns_recon":
            for ns, res in output.get("zone_transfer", {}).items():
                if isinstance(res, dict) and res.get("status") == "success":
                    findings.append(Finding(
                        title=f"DNS zone transfer successful on {ns}",
                        description=f"AXFR returned {len(res.get('records', []))} records.",
                        severity=SeverityLevel.CRITICAL,
                        confidence=0.95,
                        asset_id=asset.id,
                        asset_name=asset.name,
                        evidence_path=evidence_metadata["path"],
                        evidence_hash=evidence_metadata["hash"],
                        recommended_fix="Disable zone transfers to unauthorized hosts immediately.",
                    ))
            for sub in output.get("brute_force", []):
                name = sub if isinstance(sub, str) else sub.get("name", "")
                if name:
                    findings.append(Finding(
                        title=f"Brute-forced subdomain: {name}",
                        description=f"Resolved subdomain discovered via DNS brute-force.",
                        severity=SeverityLevel.LOW,
                        confidence=0.8,
                        asset_id=asset.id,
                        asset_name=asset.name,
                        evidence_path=evidence_metadata["path"],
                        evidence_hash=evidence_metadata["hash"],
                        recommended_fix="Review subdomain attack surface.",
                    ))

        elif tool == "whois":
            domain = output.get("domain", asset.name)
            registrar = output.get("registrar")
            if isinstance(registrar, list):
                registrar = registrar[0]
            if not registrar and not output.get("creation_date") and not output.get("expiration_date"):
                warnings = output.get("warnings") or []
                desc = "No registration data returned"
                if warnings:
                    desc += f"; {'; '.join(warnings[:3])}"
                findings.append(Finding(
                    title=f"WHOIS/RDAP lookup incomplete for {domain}",
                    description=desc,
                    severity=SeverityLevel.LOW,
                    confidence=0.6,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    source_tool="whois",
                    recommended_fix="Verify RDAP connectivity and parser coverage for this TLD.",
                ))
                return findings

            expiry = output.get("expiration_date")
            expires_in = output.get("expires_in_days")
            if expires_in is None and expiry:
                try:
                    from datetime import datetime
                    if isinstance(expiry, list):
                        expiry = expiry[0]
                    if hasattr(expiry, "timestamp"):
                        expires_in = (expiry - datetime.utcnow()).days
                except Exception:
                    pass
            sev = SeverityLevel.LOW
            if expires_in is not None:
                if expires_in < 0:
                    sev = SeverityLevel.MEDIUM
                elif expires_in < 30:
                    sev = SeverityLevel.MEDIUM
            registrar = output.get("registrar")
            if isinstance(registrar, list):
                registrar = registrar[0]
            findings.append(Finding(
                title=f"WHOIS registration for {domain}",
                description=f"Registrar: {registrar}; expiration: {expiry}",
                severity=sev,
                confidence=0.85,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                source_tool="whois",
                recommended_fix="Monitor domain expiration and registrar accuracy.",
            ))

        elif tool == "ssl_check":
            is_expired = output.get("is_expired", False)
            expires_in = output.get("expires_in_days")
            subject = output.get("subject", {})
            cn = subject.get("commonName", "unknown") if isinstance(subject, dict) else "unknown"
            if is_expired:
                sev = SeverityLevel.HIGH
            elif expires_in is not None and expires_in < 30:
                sev = SeverityLevel.MEDIUM
            else:
                sev = SeverityLevel.LOW
            findings.append(Finding(
                title=f"SSL certificate metadata for {cn}",
                description=(
                    f"Expires: {output.get('not_after', 'unknown')}; "
                    "metadata only (trust not validated by scanner)"
                ),
                severity=sev,
                confidence=0.9,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                recommended_fix="Renew expired certificates; review TLS configuration.",
            ))

        elif tool == "public_ip":
            parts = []
            if output.get("ipv4"):
                parts.append(f"IPv4: {output['ipv4']}")
            if output.get("ipv6"):
                parts.append(f"IPv6: {output['ipv6']}")
            services = output.get("services_used")
            if services:
                parts.append(f"Services: {', '.join(services)}")
            if parts:
                findings.append(Finding(
                    title="Public IP addresses detected",
                    description="; ".join(parts),
                    severity=SeverityLevel.LOW,
                    confidence=0.95,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="No action required for IP detection.",
                ))

        if not findings:
            description = output.get("interpretation") or f"No actionable issues from {tool_name}."
            findings.append(Finding(
                title=f"{tool_name} scan completed on {asset.name}",
                description=description,
                severity=SeverityLevel.LOW,
                confidence=0.95,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                recommended_fix="No immediate action required based on automated scan.",
            ))

        return findings

    def _normalize_web_intel_wrapper_output(
        self,
        tool_name: str,
        output: Any,
        asset: AssetModel,
        evidence_metadata: Dict[str, str],
    ) -> List[Finding]:
        """Normalize wappalyzer and sublist3r output."""
        findings: List[Finding] = []
        confidence_threshold = 50

        if not isinstance(output, dict):
            return findings

        tool = tool_name.lower()

        if tool == "wappalyzer":
            for tech in output.get("technologies", []):
                conf = int(tech.get("confidence", 0) or 0)
                if conf < confidence_threshold:
                    continue
                name = tech.get("name", "unknown")
                version = tech.get("version")
                categories = tech.get("categories", [])
                sev = SeverityLevel.LOW
                cat_str = " ".join(categories).lower() if categories else ""
                if any(x in cat_str for x in ("php", "wordpress", "jquery")):
                    sev = SeverityLevel.LOW
                findings.append(Finding(
                    title=f"Technology detected: {name}",
                    description=(
                        f"Version: {version or 'unknown'}; confidence: {conf}%"
                        + (f"; categories: {', '.join(categories)}" if categories else "")
                    ),
                    severity=sev,
                    confidence=min(conf / 100.0, 0.95),
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Review stack for outdated or vulnerable components.",
                ))

        elif tool == "sublist3r":
            domain = output.get("domain", asset.name)
            sensitive_prefixes = ("dev.", "staging.", "admin.", "test.", "internal.")
            for sub in output.get("subdomains", []):
                if not isinstance(sub, str):
                    continue
                if not sub.endswith(f".{domain}") and sub != domain:
                    continue
                sev = SeverityLevel.LOW
                if any(sub.startswith(p) for p in sensitive_prefixes):
                    sev = SeverityLevel.MEDIUM
                findings.append(Finding(
                    title=f"Subdomain discovered: {sub}",
                    description=f"Enumerated via Sublist3r for zone {domain}.",
                    severity=sev,
                    confidence=0.85,
                    asset_id=asset.id,
                    asset_name=asset.name,
                    evidence_path=evidence_metadata["path"],
                    evidence_hash=evidence_metadata["hash"],
                    recommended_fix="Validate subdomain ownership and review exposure.",
                ))

        if not findings:
            description = output.get("interpretation") or f"No actionable issues from {tool_name}."
            if tool == "sublist3r":
                subs = output.get("subdomains") or []
                if not subs or "no subdomains" in description.lower():
                    return findings
            findings.append(Finding(
                title=f"{tool_name} scan completed on {asset.name}",
                description=description,
                severity=SeverityLevel.LOW,
                confidence=0.95,
                asset_id=asset.id,
                asset_name=asset.name,
                evidence_path=evidence_metadata["path"],
                evidence_hash=evidence_metadata["hash"],
                recommended_fix="No immediate action required based on automated scan.",
            ))

        return findings
    
    def _extract_open_ports(self, output: Any) -> List[int]:
        """Extract open ports from scan output."""
        ports = []
        if isinstance(output, dict):
            if "ports" in output:
                for port_info in output["ports"]:
                    if isinstance(port_info, dict) and port_info.get("state") == "open":
                        ports.append(int(port_info.get("port", 0)))
            if "hosts" in output:
                for host in output["hosts"]:
                    if not isinstance(host, dict):
                        continue
                    for port_info in host.get("ports", []):
                        if isinstance(port_info, dict) and port_info.get("state") == "open":
                            ports.append(int(port_info.get("port", 0)))
            if "open_ports" in output:
                for port_info in output["open_ports"]:
                    if isinstance(port_info, dict):
                        port_num = port_info.get("port") or port_info.get("number")
                        if port_num is not None:
                            ports.append(int(port_num))
                    elif isinstance(port_info, (int, str)) and str(port_info).isdigit():
                        ports.append(int(port_info))
        elif isinstance(output, str):
            import re
            port_matches = re.findall(r'(\d+)/(?:tcp|udp)\s+open', output, re.IGNORECASE)
            if not port_matches:
                port_matches = re.findall(r'port\s+(\d+).*?open', output, re.IGNORECASE)
            ports = [int(p) for p in port_matches]
        return [p for p in ports if p > 0]

    def _extract_port_services(self, output: Any) -> Dict[int, str]:
        """Map open port numbers to service names when present in scan output."""
        services: Dict[int, str] = {}
        if not isinstance(output, dict):
            return services
        if "hosts" in output:
            for host in output["hosts"]:
                if not isinstance(host, dict):
                    continue
                for port_info in host.get("ports", []):
                    if not isinstance(port_info, dict) or port_info.get("state") != "open":
                        continue
                    port = int(port_info.get("port", 0) or 0)
                    if port > 0:
                        services[port] = str(port_info.get("service") or self._get_port_service(port))
        if "ports" in output:
            for port_info in output["ports"]:
                if not isinstance(port_info, dict) or port_info.get("state") != "open":
                    continue
                port = int(port_info.get("port", 0) or 0)
                if port > 0:
                    services[port] = str(port_info.get("service") or self._get_port_service(port))
        return services
    
    def _extract_dir_entries(self, output: Any) -> List[Dict[str, Any]]:
        """Extract directory scan entries with optional status metadata."""
        if isinstance(output, dict) and "entries" in output:
            return [e for e in output["entries"] if isinstance(e, dict)]
        return []

    def _extract_found_paths(self, output: Any) -> List[str]:
        """Extract found paths from directory scan output."""
        paths = []
        if isinstance(output, dict):
            if "paths" in output:
                paths = list(output["paths"])
            elif "entries" in output:
                for entry in output["entries"]:
                    if not isinstance(entry, dict):
                        continue
                    path = entry.get("path") or entry.get("host")
                    if path:
                        paths.append(str(path))
        elif isinstance(output, str):
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

    @staticmethod
    def _aggregate_asset_metadata_from_findings(
        findings: List[Finding],
        asset: AssetModel,
    ) -> Dict[str, List[Any]]:
        """Derive IPs, tech stack, and open ports from normalized findings."""
        import re

        ips: set = set()
        tech_stack: set = set()
        open_ports: set = set()

        for finding in findings:
            if finding.asset_id != asset.id and finding.asset_name != asset.name:
                continue
            title = finding.title or ""
            desc = finding.description or ""
            source = (finding.source_tool or "").lower()

            if title.startswith("DNS A records") or title.startswith("DNS AAAA records"):
                for part in desc.split(":", 1)[-1].split(","):
                    ip = part.strip().split()[0].strip()
                    if ip and not ip.startswith("("):
                        ips.add(ip)

            if source == "wappalyzer" and title.startswith("Technology detected: "):
                tech = title.replace("Technology detected: ", "", 1).strip()
                if tech:
                    tech_stack.add(tech)

            if source in ("nmap", "rustscan", "masscan"):
                if title.startswith("Open ports discovered"):
                    for match in re.findall(r"\b(\d+)\b", desc):
                        open_ports.add(int(match))
                for match in re.findall(r"port (\d+)", title, re.IGNORECASE):
                    open_ports.add(int(match))

        return {
            "ip_addresses": sorted(ips),
            "tech_stack": sorted(tech_stack),
            "open_ports": sorted(open_ports),
        }

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
            
            meta = self._aggregate_asset_metadata_from_findings(findings, asset)
            ip_addresses = list(meta["ip_addresses"])
            if not ip_addresses and asset.type.value == "host":
                ip_addresses = [asset.value]

            asset_reports.append(AssetReport(
                target=asset.name,
                ip_addresses=ip_addresses,
                tech_stack=meta["tech_stack"],
                open_ports=meta["open_ports"],
                findings=asset_specific_findings,
            ))

        # 3. Create Executive Summary
        active_findings = [
            f for f in findings
            if f.verification_state not in ("conflicted", "informational")
        ]
        conflicted_findings = [
            f for f in findings if f.verification_state == "conflicted"
        ]
        informational_findings = [
            f for f in findings if f.verification_state == "informational"
        ]
        informational_titles = {f.title for f in informational_findings}
        severity_counts = self._count_findings_by_severity(active_findings)
        risk_score = 10.0
        if severity_counts.get("critical", 0) > 0:
            risk_score = 2.0
        elif severity_counts.get("high", 0) > 0:
            risk_score = 4.0
        elif severity_counts.get("medium", 0) > 0:
            risk_score = 6.0
        elif severity_counts.get("low", 0) > 0:
            risk_score = 8.0
            
        # Get top 5 critical/high findings for summary (exclude reconciled conflicts)
        conflicted_titles = {f.title for f in conflicted_findings}
        key_findings = sorted(
            [
                rf for rf in report_findings
                if rf.severity in [ReportSeverity.CRITICAL, ReportSeverity.HIGH]
                and rf.title not in conflicted_titles
                and rf.title not in informational_titles
            ],
            key=lambda x: x.severity.value
        )[:5]

        overview = (
            f"Security assessment conducted on {len(assets)} assets. "
            f"Found {len(active_findings)} issues."
        )
        if conflicted_findings:
            overview += (
                f" {len(conflicted_findings)} reconciled cross-tool observation(s) "
                "documented separately."
            )
        if informational_findings:
            overview += (
                f" {len(informational_findings)} scan coverage note(s) "
                "documented separately."
            )

        exec_summary = ExecutiveSummary(
            overview=overview,
            risk_score=risk_score,
            key_findings=key_findings,
            recommendations=[
                "Remediate critical vulnerabilities immediately.",
                "Review high severity findings within 48 hours."
            ]
        )

        # 4. Build Full Report Model
        target = metadata.get("primary_target")
        if not target and assets:
            target = assets[0].value or assets[0].name
        if not target:
            target = "Unknown Target"

        detailed_findings = [
            rf for rf in report_findings
            if rf.title not in informational_titles
        ]

        full_report = FullReport(
            target=target,
            executive_summary=exec_summary,
            assets=asset_reports,
            all_findings=detailed_findings,
            reconciled_findings=[
                ReportFinding(
                    title=f.title,
                    severity=severity_map.get(f.severity.value, ReportSeverity.INFO),
                    description=f.description,
                    remediation=f.recommended_fix,
                    evidence=[f.evidence_path] if f.evidence_path else [],
                    affected_assets=[f.asset_name] if f.asset_name else [],
                )
                for f in conflicted_findings
            ],
            coverage_findings=[
                ReportFinding(
                    title=f.title,
                    severity=ReportSeverity.INFO,
                    description=f.description,
                    remediation=f.recommended_fix,
                    evidence=[f.evidence_path] if f.evidence_path else [],
                    affected_assets=[f.asset_name] if f.asset_name else [],
                )
                for f in informational_findings
            ],
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
        self._injected_connection = db_connection
        self.logger = logging.getLogger("black_glove.reporting.manager")
        self.findings_normalizer = FindingsNormalizer()
        self.report_generator = ReportGenerator()
        self.evidence_storage = EvidenceStorage()

    @property
    def db_connection(self):
        """Optional injected connection (used by tests and ReportingContext)."""
        return self._injected_connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._injected_connection is not None:
            yield self._injected_connection
        else:
            conn = get_db_connection()
            try:
                yield conn
            finally:
                conn.close()
    
    def get_findings_from_database(
        self,
        *,
        run_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Finding]:
        """
        Retrieve findings from database.

        When run_id is provided, only findings tagged with that run are returned.
        """
        findings = []
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                if run_id:
                    cursor.execute(
                        """
                        SELECT f.id, f.title, f.severity, f.confidence, f.asset_id,
                               COALESCE(o.evidence_path, f.evidence_path),
                               f.recommended_fix,
                               COALESCE(o.observed_at, f.created_at),
                               COALESCE(o.description, f.description),
                               COALESCE(o.evidence_hash, f.evidence_hash),
                               f.source_tool, f.verification_state, f.fingerprint,
                               f.observation_count, o.run_id, o.step_id,
                               COALESCE(a.name, '')
                        FROM finding_observations o
                        JOIN findings f ON f.id = o.finding_id
                        LEFT JOIN assets a ON a.id = f.asset_id
                        INNER JOIN (
                            SELECT finding_id, MAX(id) AS max_obs_id
                            FROM finding_observations
                            WHERE run_id = ?
                            GROUP BY finding_id
                        ) latest ON latest.max_obs_id = o.id
                        WHERE o.run_id = ?
                        ORDER BY f.severity, o.observed_at DESC
                        """,
                        (run_id, run_id),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT f.id, f.title, f.severity, f.confidence, f.asset_id,
                               f.evidence_path, f.recommended_fix, f.created_at,
                               f.description, f.evidence_hash, f.source_tool,
                               f.verification_state, f.fingerprint, f.observation_count,
                               f.run_id, f.step_id, COALESCE(a.name, '')
                        FROM findings f
                        LEFT JOIN assets a ON a.id = f.asset_id
                        ORDER BY f.severity, f.created_at DESC
                        """
                    )

                rows = cursor.fetchall()
                for row in rows:
                    if (row[11] or "indicator") == "informational":
                        severity = SeverityLevel.INFO
                    else:
                        severity = SeverityLevel(row[2]) if row[2] else SeverityLevel.MEDIUM
                    finding = Finding(
                        id=row[0],
                        title=row[1],
                        severity=severity,
                        confidence=row[3] or 0.8,
                        asset_id=row[4],
                        evidence_path=row[5],
                        recommended_fix=row[6] or "",
                        created_at=row[7],
                        description=row[8] or "",
                        evidence_hash=row[9],
                        source_tool=row[10] or "",
                        verification_state=row[11] or "indicator",
                        fingerprint=row[12],
                        observation_count=row[13] or 1,
                        run_id=row[14],
                        step_id=row[15],
                        asset_name=row[16] or "",
                    )
                    findings.append(finding)

                self.logger.debug(f"Retrieved {len(findings)} findings from database")

        except Exception as e:
            self.logger.error(f"Error retrieving findings from database: {e}")

        return findings

    def get_findings_for_asset(
        self,
        asset_id: int,
        *,
        exclude_superseded: bool = True,
        run_id: Optional[str] = None,
    ) -> List[Finding]:
        """Load canonical findings for an asset (used for cross-tool reconciliation)."""
        findings: List[Finding] = []
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                sql = """
                    SELECT id, title, severity, confidence, asset_id, evidence_path,
                           recommended_fix, created_at, description, evidence_hash,
                           source_tool, verification_state, fingerprint, observation_count,
                           run_id, step_id
                    FROM findings
                    WHERE asset_id = ?
                """
                params: List[Any] = [asset_id]
                if run_id:
                    sql += " AND run_id = ?"
                    params.append(run_id)
                if exclude_superseded:
                    sql += " AND verification_state != 'superseded'"
                sql += " ORDER BY created_at DESC"
                cursor.execute(sql, tuple(params))
                for row in cursor.fetchall():
                    findings.append(
                        Finding(
                            id=row[0],
                            title=row[1],
                            severity=SeverityLevel(row[2]) if row[2] else SeverityLevel.MEDIUM,
                            confidence=row[3] or 0.8,
                            asset_id=row[4],
                            evidence_path=row[5],
                            recommended_fix=row[6] or "",
                            created_at=row[7],
                            description=row[8] or "",
                            evidence_hash=row[9],
                            source_tool=row[10] or "",
                            verification_state=row[11] or "indicator",
                            fingerprint=row[12],
                            observation_count=row[13] or 1,
                            run_id=row[14],
                            step_id=row[15],
                        )
                    )
        except Exception as e:
            self.logger.error(f"Error loading findings for asset {asset_id}: {e}")
        return findings
    
    def get_assets_from_database(self) -> List[AssetModel]:
        """
        Retrieve assets from database.
        
        Returns:
            List of assets from database
        """
        assets = []
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
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

    def get_assets_for_findings(self, findings: List[Finding]) -> List[AssetModel]:
        """
        Retrieve assets referenced by the given findings (run-scoped reporting).
        """
        asset_ids = sorted({f.asset_id for f in findings if f.asset_id})
        if not asset_ids:
            return []

        assets: List[AssetModel] = []
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                placeholders = ",".join("?" * len(asset_ids))
                cursor.execute(
                    f"SELECT id, name, type, value FROM assets WHERE id IN ({placeholders}) ORDER BY name",
                    asset_ids,
                )
                for row in cursor.fetchall():
                    assets.append(
                        AssetModel(
                            id=row[0],
                            name=row[1],
                            type=row[2],
                            value=row[3],
                        )
                    )
        except Exception as e:
            self.logger.error(f"Error retrieving assets for findings: {e}")

        return assets

    @staticmethod
    def _primary_report_target(assets: List[AssetModel], findings: List[Finding]) -> str:
        """Pick the best report target label from scoped assets and findings."""
        if not assets:
            return "Unknown Target"

        counts: Dict[int, int] = {}
        for finding in findings:
            if finding.asset_id:
                counts[finding.asset_id] = counts.get(finding.asset_id, 0) + 1

        if counts:
            primary_id = max(counts, key=lambda aid: (counts[aid], -aid))
            primary = next((a for a in assets if a.id == primary_id), assets[0])
        else:
            primary = assets[0]

        return primary.value or primary.name
    
    def save_findings_to_database(self, findings: List[Finding]) -> None:
        """
        Save findings to database with deduplication by fingerprint.
        Appends a finding_observations row for every save (run-scoped history).
        """
        if not findings:
            return
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                observed_at = datetime.now().isoformat()

                for finding in findings:
                    fingerprint = finding.fingerprint or self._finding_fingerprint(finding)
                    finding.fingerprint = fingerprint

                    cursor.execute(
                        """
                        INSERT INTO findings
                        (asset_id, title, severity, confidence, evidence_path,
                         recommended_fix, description, evidence_hash, source_tool,
                         verification_state, fingerprint, observation_count, run_id, step_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(fingerprint) DO UPDATE SET
                            observation_count = observation_count + 1,
                            severity = excluded.severity,
                            confidence = MAX(findings.confidence, excluded.confidence),
                            evidence_path = excluded.evidence_path,
                            evidence_hash = excluded.evidence_hash,
                            description = excluded.description,
                            verification_state = excluded.verification_state,
                            run_id = COALESCE(excluded.run_id, findings.run_id),
                            step_id = COALESCE(excluded.step_id, findings.step_id)
                        """,
                        (
                            finding.asset_id,
                            finding.title,
                            severity_for_db(finding.severity),
                            finding.confidence,
                            finding.evidence_path,
                            finding.recommended_fix,
                            finding.description,
                            finding.evidence_hash,
                            finding.source_tool,
                            finding.verification_state,
                            fingerprint,
                            finding.observation_count,
                            finding.run_id,
                            finding.step_id,
                        ),
                    )

                    cursor.execute(
                        "SELECT id FROM findings WHERE fingerprint = ?",
                        (fingerprint,),
                    )
                    row = cursor.fetchone()
                    if not row:
                        continue
                    finding_id = row[0]
                    finding.id = finding_id

                    if finding.run_id:
                        cursor.execute(
                            """
                            SELECT id, description FROM finding_observations
                            WHERE finding_id = ? AND run_id = ?
                            LIMIT 1
                            """,
                            (finding_id, finding.run_id),
                        )
                        existing_obs = cursor.fetchone()
                        if existing_obs:
                            merged_description = self._merge_observation_descriptions(
                                existing_obs[1] or "",
                                finding.description or "",
                            )
                            cursor.execute(
                                """
                                UPDATE finding_observations
                                SET description = ?, evidence_path = ?, evidence_hash = ?,
                                    observed_at = ?, step_id = COALESCE(?, step_id)
                                WHERE id = ?
                                """,
                                (
                                    merged_description,
                                    finding.evidence_path,
                                    finding.evidence_hash,
                                    observed_at,
                                    finding.step_id,
                                    existing_obs[0],
                                ),
                            )
                            continue

                    cursor.execute(
                        """
                        INSERT INTO finding_observations
                        (finding_id, run_id, step_id, evidence_path, evidence_hash,
                         description, observed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding_id,
                            finding.run_id,
                            finding.step_id,
                            finding.evidence_path,
                            finding.evidence_hash,
                            finding.description,
                            observed_at,
                        ),
                    )

                conn.commit()
                self.logger.info(f"Saved {len(findings)} findings to database")

        except Exception as e:
            self.logger.error(f"Error saving findings to database: {e}")
            if self._injected_connection is not None:
                self._injected_connection.rollback()

    @staticmethod
    def _merge_observation_descriptions(existing: str, new: str) -> str:
        """Merge observation text when the same finding is re-saved in one run."""
        import re

        if not existing or existing == new:
            return new
        if not new:
            return existing

        def _split_sources(description: str):
            match = re.match(r"Sources:\s*([^;]+);?\s*(.*)", description, re.DOTALL)
            if not match:
                return [], description
            sources = [s.strip() for s in match.group(1).split(",") if s.strip()]
            tail = match.group(2).strip()
            return sources, tail

        existing_sources, existing_tail = _split_sources(existing)
        new_sources, new_tail = _split_sources(new)
        if existing_sources or new_sources:
            merged = sorted(set(existing_sources + new_sources))
            tail = new_tail or existing_tail
            prefix = f"Sources: {', '.join(merged)}"
            return f"{prefix}; {tail}" if tail else prefix
        return new

    @staticmethod
    def _finding_fingerprint(finding: Finding) -> str:
        title_lower = finding.title.strip().lower()
        if (
            finding.source_tool == "web_server_scanner"
            and (title_lower.startswith("missing ") or title_lower.startswith("present "))
        ):
            raw = f"{finding.asset_id}|{finding.source_tool}|{title_lower}"
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if finding.title.startswith("Subdomains discovered ("):
            if finding.fingerprint:
                return finding.fingerprint
        location = (finding.description or "").strip().lower()[:200]
        raw = (
            f"{finding.asset_id}|{finding.source_tool}|"
            f"{title_lower}|{location}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    
    def generate_assessment_report(self, format_type: ReportFormat = ReportFormat.JSON,
                                 include_evidence: bool = True,
                                 run_id: Optional[str] = None) -> str:
        """
        Generate comprehensive security assessment report.
        """
        self.logger.info(f"Generating assessment report in {format_type.value} format")

        findings = self.get_findings_from_database(run_id=run_id)
        if run_id:
            assets = self.get_assets_for_findings(findings)
        else:
            assets = self.get_assets_from_database()

        primary_target = self._primary_report_target(assets, findings)

        metadata = {
            "scan_duration": "N/A",
            "total_scans": len(findings),
            "report_format": format_type.value,
            "include_evidence": include_evidence,
            "run_id": run_id,
            "primary_target": primary_target,
            "scoped_to_run": bool(run_id),
        }
        
        # Generate report
        report_content = self.report_generator.generate_report(
            findings, assets, metadata, format_type
        )
        
        self.logger.info("Assessment report generation completed")
        return report_content
    
    def cleanup(self) -> None:
        """Clean up resources."""
        if self._injected_connection is not None and hasattr(self._injected_connection, 'close'):
            self._injected_connection.close()
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
