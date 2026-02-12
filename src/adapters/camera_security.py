"""
Camera Security Adapter for Black Glove Pentest Agent

This module provides security testing for IP cameras and surveillance devices.
It checks for common security misconfigurations including:
- Open/exposed camera ports
- Anonymous RTSP stream access
- Unprotected HTTP admin panels
- Default credentials

IMPORTANT: Only use this adapter on authorized assets in your lab/network.
Unauthorized testing of security cameras may violate laws and privacy regulations.
"""

import socket
import time
import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus


class CameraSecurityAdapter(BaseAdapter):
    """
    Security testing adapter for IP cameras and surveillance devices.
    
    This adapter performs multiple security checks:
    1. Port scanning for common camera ports
    2. RTSP anonymous access testing
    3. HTTP authentication checks
    4. Default credential testing
    """
    
    # Common camera ports (comprehensive list by brand)
    CAMERA_PORTS = {
        # Standard Web/Streaming
        80: "HTTP",
        443: "HTTPS",
        554: "RTSP",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        
        # Hikvision
        8000: "Hikvision SDK/iVMS",
        8200: "Hikvision Data/Mgmt",
        10554: "Hikvision RTSP-Alt",
        
        # Dahua
        37777: "Dahua SmartPSS (TCP)",
        37778: "Dahua Control (UDP)",
        3800: "Dahua Legacy",
        
        # Axis
        49152: "Axis UPnP/Discovery",
        
        # Uniview
        7070: "Uniview Media",
        6060: "Uniview SDK",
        
        # Xiongmai (white-label)
        34567: "Xiongmai Control",
        
        # GeoVision
        4550: "GeoVision Command",
        5550: "GeoVision Data",
        5511: "GeoVision Mobile",
        
        # Avigilon
        38880: "Avigilon Server",
        
        # Mobotix
        50000: "Mobotix Management",
        
        # ONVIF/Generic
        3702: "ONVIF Discovery (UDP)",
        1935: "RTMP Streaming"
    }
    
    # Default credentials to test (common camera defaults)
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "12345"),
        ("admin", "password"),
        ("root", "root"),
        ("root", "12345"),
        ("root", "pass"),
        ("admin", "1234"),
        ("666666", "666666"),  # Common Chinese DVR
        ("888888", "888888"),  # Common Chinese DVR
    ]
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the camera security adapter.
        
        Args:
            config: Adapter configuration dictionary
        """
        super().__init__(config)
        self._required_config_fields = []
        self._required_params = ["target"]
        self.version = "1.1.0"  # Updated with vendor fingerprinting and extended ports
        
        # Configuration defaults
        self.timeout = config.get("timeout", 5)
        self.test_credentials = config.get("test_credentials", True)
        self.max_credential_tests = config.get("max_credential_tests", 5)
    
    def validate_config(self) -> bool:
        """
        Validate the adapter configuration.
        
        Returns:
            bool: True if configuration is valid
        """
        super().validate_config()
        
        if "timeout" in self.config:
            if not isinstance(self.config["timeout"], (int, float)) or self.config["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        if "test_credentials" in self.config:
            if not isinstance(self.config["test_credentials"], bool):
                raise ValueError("test_credentials must be a boolean")
        
        if "max_credential_tests" in self.config:
            if not isinstance(self.config["max_credential_tests"], int) or self.config["max_credential_tests"] <= 0:
                raise ValueError("max_credential_tests must be a positive integer")
        
        return True
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Validate execution parameters.
        
        Args:
            params: Parameters for the scan
            
        Returns:
            bool: True if parameters are valid
        """
        super().validate_params(params)
        
        target = params.get("target")
        # Basic validation of target format (IP or hostname)
        if target and not re.match(r'^[a-zA-Z0-9\.\-]+$', target):
            raise ValueError("Invalid target format")
        
        return True
    
    def execute(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute camera security checks.
        
        Args:
            params: Execution parameters including 'target'
            
        Returns:
            AdapterResult: Results of the security assessment
        """
        self.validate_params(params)
        
        target = params["target"]
        self.logger.info(f"Starting camera security assessment on {target}")
        
        findings = []
        open_ports = []
        
        try:
            # Step 1: Port scanning
            self.logger.info("Scanning common camera ports...")
            open_ports = self._scan_ports(target)
            
            if not open_ports:
                return AdapterResult(
                    status=AdapterResultStatus.SUCCESS,
                    data={
                        "target": target,
                        "open_ports": [],
                        "findings": ["No common camera ports are open"]
                    },
                    metadata={
                        "ports_scanned": list(self.CAMERA_PORTS.keys()),
                        "timestamp": time.time()
                    }
                )
            
            findings.append(f"Open ports detected: {', '.join([f'{p} ({self.CAMERA_PORTS[p]})' for p in open_ports])}")
            
            # Add brand-specific warnings for critical ports
            if 37777 in open_ports:
                findings.append("⚠️ DAHUA RISK: Port 37777 (SmartPSS) is open - this port is commonly targeted with default credentials")
            if 8000 in open_ports:
                findings.append("⚠️ HIKVISION RISK: Port 8000 (iVMS SDK) is open - verify strong authentication is enabled")
            if 34567 in open_ports:
                findings.append("⚠️ XIONGMAI RISK: Port 34567 is open - these devices often have known vulnerabilities")
            
            # Step 2: RTSP anonymous access check
            rtsp_ports = [p for p in open_ports if p in [554, 10554]]
            for rtsp_port in rtsp_ports:
                self.logger.info(f"Testing RTSP anonymous access on port {rtsp_port}...")
                rtsp_result = self._test_rtsp_anonymous(target, rtsp_port)
                if rtsp_result:
                    findings.append(f"⚠️ RTSP VULNERABILITY: {rtsp_result}")
            
            # Step 3: HTTP authentication check
            http_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000, 8200, 9000, 50000]]
            for port in http_ports:
                self.logger.info(f"Checking HTTP authentication on port {port}...")
                auth_result = self._test_http_auth(target, port)
                if auth_result:
                    findings.append(auth_result)
            
            # Step 4: Default credentials testing (if enabled)
            if self.test_credentials and http_ports:
                self.logger.info("Testing default credentials...")
                cred_results = self._test_default_credentials(target, http_ports)
                findings.extend(cred_results)
            
            # Determine overall status
            has_vulnerabilities = any("VULNERABILITY" in f or "WEAK" in f for f in findings)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "target": target,
                    "open_ports": [{"port": p, "service": self.CAMERA_PORTS[p]} for p in open_ports],
                    "findings": findings,
                    "vulnerabilities_detected": has_vulnerabilities
                },
                metadata={
                    "ports_scanned": list(self.CAMERA_PORTS.keys()),
                    "timestamp": time.time(),
                    "checks_performed": ["port_scan", "rtsp_anonymous", "http_auth", "default_creds"] if self.test_credentials else ["port_scan", "rtsp_anonymous", "http_auth"]
                }
            )
            
        except Exception as e:
            self.logger.error(f"Camera security check failed: {str(e)}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data={"error": str(e), "target": target},
                metadata={"timestamp": time.time()}
            )
    
    def _scan_ports(self, target: str) -> List[int]:
        """
        Scan common camera ports.
        
        Args:
            target: IP address or hostname
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        for port in self.CAMERA_PORTS.keys():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    self.logger.debug(f"Port {port} is open")
                
            except socket.gaierror:
                self.logger.error(f"Hostname {target} could not be resolved")
                break
            except socket.error as e:
                self.logger.debug(f"Port {port} connection error: {str(e)}")
                continue
        
        return sorted(open_ports)
    
    def _test_rtsp_anonymous(self, target: str, port: int = 554) -> Optional[str]:
        """
        Test for anonymous RTSP access with vendor-specific paths.
        
        Args:
            target: IP address or hostname
            port: RTSP port (default: 554)
            
        Returns:
            Vulnerability message if anonymous access is possible, None otherwise
        """
        # Vendor-specific RTSP paths (most to least common)
        common_rtsp_paths = [
            # Generic/Common
            "/",
            "/live",
            "/stream",
            "/ch0",
            "/ch1",
            "/0",
            
            # Hikvision
            "/Streaming/Channels/101",  # Channel 1, Stream 1 (main)
            "/Streaming/Channels/102",  # Channel 1, Stream 2 (sub)
            "/Streaming/Channels/1",
            "/h264",
            "/mpeg4",
            
            # Dahua
            "/cam/realmonitor?channel=1&subtype=0",  # Main stream
            "/cam/realmonitor?channel=1&subtype=1",  # Sub stream
            
            # Axis
            "/axis-media/media.amp",
            "/axis-media/media.amp?videocodec=h264",
            
            # Hanwha (Samsung)
            "/profile1/media.smp",
            "/profile2/media.smp"
        ]
        
        for path in common_rtsp_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                
                # Send RTSP DESCRIBE request
                rtsp_url = f"rtsp://{target}:{port}{path}"
                request = f"DESCRIBE {rtsp_url} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                # Check for successful response without authentication
                if "RTSP/1.0 200 OK" in response:
                    return f"Anonymous RTSP stream accessible at rtsp://{target}:{port}{path}"
                elif "401 Unauthorized" not in response and "RTSP/1.0" in response:
                    # Some response received, but not clear 200 or 401
                    self.logger.debug(f"RTSP path {path} responded: {response[:100]}")
                
            except socket.timeout:
                self.logger.debug(f"RTSP timeout on path {path}")
            except Exception as e:
                self.logger.debug(f"RTSP test error on path {path}: {str(e)}")
                continue
        
        return None
    
    def _test_http_auth(self, target: str, port: int) -> Optional[str]:
        """
        Test if HTTP admin panel requires authentication and identify vendor.
        
        Args:
            target: IP address or hostname
            port: HTTP port
            
        Returns:
            Finding message with vendor info if possible, None otherwise
        """
        protocol = "https" if port in [443, 8443] else "http"
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Send HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(8192).decode('utf-8', errors='ignore')
            sock.close()
            
            # Extract vendor from Server header
            vendor = self._identify_camera_vendor(response)
            vendor_str = f" ({vendor})" if vendor else ""
            
            # Check response
            if "HTTP/1.1 200 OK" in response or "HTTP/1.0 200 OK" in response:
                # Check if it's a camera interface
                camera_keywords = ["camera", "dvr", "nvr", "video", "surveillance", "ipcam", "webcam"]
                response_lower = response.lower()
                
                if any(keyword in response_lower for keyword in camera_keywords) or vendor:
                    return f"⚠️ HTTP VULNERABILITY: Camera web interface{vendor_str} on port {port} accessible without authentication"
                else:
                    return f"HTTP interface on port {port} is accessible (authentication unclear)"
            
            elif "401 Unauthorized" in response or "403 Forbidden" in response:
                return f"✓ HTTP interface{vendor_str} on port {port} requires authentication"
            
        except Exception as e:
            self.logger.debug(f"HTTP auth test error on port {port}: {str(e)}")
        
        return None
    
    def _identify_camera_vendor(self, http_response: str) -> Optional[str]:
        """
        Identify camera vendor from HTTP response headers.
        
        Args:
            http_response: Raw HTTP response
            
        Returns:
            Vendor name if identified, None otherwise
        """
        # Vendor fingerprints based on Server header
        vendor_signatures = {
            "Hikvision-Webs": "Hikvision",
            "DVRDVS-Webs": "Hikvision",
            "DPS/2.0": "Dahua",
            "Dahua-Webs": "Dahua",
            "Uc-httpd": "Xiongmai",
            "AXIS": "Axis",
            "Mobotix": "Mobotix",
            "GeoVision": "GeoVision"
        }
        
        response_lower = http_response.lower()
        
        for signature, vendor in vendor_signatures.items():
            if signature.lower() in response_lower:
                self.logger.info(f"Identified vendor: {vendor}")
                return vendor
        
        return None
    
    def _test_default_credentials(self, target: str, ports: List[int]) -> List[str]:
        """
        Test common default credentials on HTTP interfaces.
        
        Args:
            target: IP address or hostname
            ports: List of HTTP ports to test
            
        Returns:
            List of findings
        """
        findings = []
        tested_count = 0
        
        for port in ports[:2]:  # Test max 2 ports to avoid excessive requests
            if tested_count >= self.max_credential_tests:
                break
            
            for username, password in self.DEFAULT_CREDENTIALS[:self.max_credential_tests]:
                if tested_count >= self.max_credential_tests:
                    break
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target, port))
                    
                    # Create Basic Auth header
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    request = f"GET / HTTP/1.1\r\nHost: {target}\r\nAuthorization: Basic {credentials}\r\nConnection: close\r\n\r\n"
                    sock.send(request.encode())
                    
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    tested_count += 1
                    
                    # Check for successful authentication
                    if "HTTP/1.1 200 OK" in response or "HTTP/1.0 200 OK" in response:
                        findings.append(f"🔴 CRITICAL VULNERABILITY: Default credentials work! {username}:{password} on port {port}")
                        self.logger.warning(f"Default credentials found: {username}:{password} on port {port}")
                        break  # Stop testing this port if we found valid creds
                    
                    # Small delay to avoid triggering rate limits/lockouts
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.logger.debug(f"Credential test error ({username}:{password} on port {port}): {str(e)}")
                    continue
        
        if not findings and tested_count > 0:
            findings.append(f"✓ Default credentials tested ({tested_count} attempts) - none successful")
        
        return findings
    
    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Camera security scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No Camera security data."
            
        target = data.get("target", "unknown")
        open_ports = data.get("open_ports", [])
        findings = data.get("findings", [])
        vuln_detected = data.get("vulnerabilities_detected", False)
        
        summary = f"Camera Security Scan for {target}:\n"
        
        if open_ports:
            summary += f"- Open RTSP/Camera Ports: {', '.join(map(str, open_ports))}\n"
        else:
            summary += "- No common camera ports open.\n"
            
        if findings:
            summary += f"- Findings ({len(findings)}):\n"
            for f in findings:
                # findings are dicts: {'type': '...', 'description': '...', 'severity': '...'}
                sev = f.get("severity", "INFO").upper()
                desc = f.get("description", "")
                summary += f"  - [{sev}] {desc}\n"
        else:
            summary += "- No specific vulnerability findings.\n"
            
        if vuln_detected:
            summary += "\n[CRITICAL] Vulnerable camera configuration detected!"
        else:
            summary += "\nNo critical camera vulnerabilities detected."
            
        return summary

    def cleanup(self) -> None:
        """
        Clean up resources after execution.
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get adapter information.
        
        Returns:
            Dict containing adapter metadata
        """
        base_info = super().get_info()
        base_info.update({
            "name": "camera_security",
            "version": self.version,
            "description": "Comprehensive security testing for IP cameras and surveillance devices with vendor identification",
            "category": "security_assessment",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP address or hostname of the camera (e.g., '192.168.1.50')"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Connection timeout in seconds (default: 5)"
                    },
                    "test_credentials": {
                        "type": "boolean",
                        "description": "Optional: Whether to test default credentials (default: True)"
                    }
                },
                "required": ["target"]
            },
            "capabilities": [
                "Port scanning for 26+ camera-specific ports",
                "Vendor fingerprinting (Hikvision, Dahua, Axis, Xiongmai, etc.)",
                "RTSP anonymous access testing with vendor-specific paths",
                "HTTP authentication verification",
                "Default credential testing",
                "Brand-specific vulnerability warnings"
            ],
            "supported_vendors": [
                "Hikvision", "Dahua", "Axis", "Uniview", "Xiongmai",
                "GeoVision", "Avigilon", "Mobotix", "Hanwha/Samsung", "Generic ONVIF"
            ],
            "ports_checked": list(self.CAMERA_PORTS.keys()),
            "safety_notes": "Only use on authorized assets. Unauthorized testing may violate laws."
        })
        return base_info
