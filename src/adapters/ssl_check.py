"""
SSL Check Adapter for Black Glove Pentest Agent

This module provides an SSL certificate validation adapter for checking
SSL/TLS certificate information during passive reconnaissance phases.
"""

import time
import ssl
import socket
import datetime
from typing import Any, Dict

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus


class SslCheckAdapter(BaseAdapter):
    """
    SSL check adapter for SSL/TLS certificate validation.
    
    This adapter performs SSL certificate checks to gather certificate
    information including issuer, subject, validity dates, and security details.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SSL check adapter.
        
        Args:
            config: Adapter configuration dictionary
        """
        super().__init__(config)
        self._required_config_fields = []
        self._required_params = ["host"]
        self.version = "1.0.0"
        self.default_port = 443
    
    def validate_config(self) -> bool:
        """
        Validate the adapter configuration.
        
        Returns:
            bool: True if configuration is valid
        """
        # Call parent validation
        super().validate_config()
        
        # SSL-specific validation
        if "timeout" in self.config:
            if not isinstance(self.config["timeout"], (int, float)) or self.config["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        if "port" in self.config:
            if not isinstance(self.config["port"], int) or not (1 <= self.config["port"] <= 65535):
                raise ValueError("Port must be an integer between 1 and 65535")
        
        return True
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Validate execution parameters.
        
        Args:
            params: Parameters to validate
            
        Returns:
            bool: True if parameters are valid
        """
        # Call parent validation
        super().validate_params(params)
        
        # SSL-specific parameter validation
        if "host" in params:
            if not isinstance(params["host"], str) or not params["host"].strip():
                raise ValueError("Host must be a non-empty string")
        
        if "port" in params:
            if not isinstance(params["port"], int) or not (1 <= params["port"] <= 65535):
                raise ValueError("Port must be an integer between 1 and 65535")
        
        if "timeout" in params:
            if not isinstance(params["timeout"], (int, float)) or params["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        return True
    
    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute the SSL certificate check.
        
        Args:
            params: Execution parameters containing 'host' and optional 'port', 'timeout'
            
        Returns:
            AdapterResult: Standardized result structure
        """
        host = params["host"]
        port = params.get("port", self.config.get("port", self.default_port))
        timeout = params.get("timeout", self.config.get("timeout", 30))
        
        self.logger.info(f"Performing SSL certificate check for host: {host}:{port}")
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to get certs even if they're invalid
            
            # Connect and get certificate
            start_time = time.time()
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                self.logger.debug(f"Connected to {host}:{port}")
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    self.logger.debug(f"SSL handshake completed for {host}:{port}")
                    # Try to get certificate in both forms
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    self.logger.debug(f"Certificate retrieved: {cert}")
                    self.logger.debug(f"Binary certificate length: {len(cert_binary) if cert_binary else 0}")
                    execution_time = time.time() - start_time
            
            # Check if we got any certificate data
            if not cert and (not cert_binary or len(cert_binary) == 0):
                self.logger.debug(f"No certificate found for {host}:{port}")
                return AdapterResult(
                    status=AdapterResultStatus.FAILURE,
                    data=None,
                    metadata={
                        "adapter": self.name,
                        "host": host,
                        "port": port,
                        "timestamp": time.time()
                    },
                    error_message="No SSL certificate found"
                )
            
            # If we have binary cert but no parsed cert, try to parse it
            if not cert and cert_binary:
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_obj = x509.load_der_x509_certificate(cert_binary, default_backend())
                    # Convert to format similar to getpeercert()
                    cert = {
                        "subject": tuple((("commonName", attr.value),) for attr in cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)),
                        "issuer": tuple((("commonName", attr.value),) for attr in cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)),
                        "version": cert_obj.version.value,
                        "serialNumber": format(cert_obj.serial_number, 'x').upper(),
                        "notBefore": cert_obj.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
                        "notAfter": cert_obj.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
                    }
                    self.logger.debug(f"Parsed certificate from binary: {cert}")
                except Exception as e:
                    self.logger.debug(f"Failed to parse binary certificate: {e}")
                    # Fall back to basic info if parsing fails
                    cert = {"raw_binary": f"Certificate bytes: {len(cert_binary)} bytes"}
            
            # Parse certificate information
            cert_info = {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "version": cert.get("version"),
                "serial_number": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "subject_alt_names": cert.get("subjectAltName", []),
                "signature_algorithm": cert.get("signatureAlgorithm")
            }
            
            # Check certificate validity
            not_after = cert_info["not_after"]
            not_before = cert_info["not_before"]
            
            if not_after:
                expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                cert_info["expires_in_days"] = (expiry_date - datetime.datetime.utcnow()).days
                cert_info["is_expired"] = expiry_date < datetime.datetime.utcnow()
            
            if not_before:
                start_date = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                cert_info["is_not_yet_valid"] = start_date > datetime.datetime.utcnow()
            
            # Store raw evidence
            evidence_filename = f"ssl_{host.replace('.', '_')}_{port}_{int(time.time())}.txt"
            evidence_data = f"SSL Certificate Information for {host}:{port}\n\n"
            for key, value in cert_info.items():
                evidence_data += f"{key}: {value}\n"
            
            evidence_path = self._store_evidence(evidence_data, evidence_filename)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=cert_info,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "port": port,
                    "timestamp": time.time(),
                    "execution_time": execution_time
                },
                execution_time=execution_time,
                evidence_path=evidence_path
            )
            
        except socket.timeout:
            return AdapterResult(
                status=AdapterResultStatus.TIMEOUT,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "port": port,
                    "timeout": timeout,
                    "timestamp": time.time()
                },
                error_message=f"Connection timed out after {timeout} seconds"
            )
        except ssl.SSLError as e:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "port": port,
                    "timestamp": time.time()
                },
                error_message=f"SSL error: {str(e)}"
            )
        except socket.gaierror as e:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "port": port,
                    "timestamp": time.time()
                },
                error_message=f"DNS resolution failed: {str(e)}"
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "port": port,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get adapter information.
        
        Returns:
            Dict containing adapter information
        """
        base_info = super().get_info()
        base_info.update({
            "name": "SslCheckAdapter",
            "version": self.version,
            "description": "SSL check adapter for SSL/TLS certificate validation. Use for hostnames or IP addresses.",
            "capabilities": base_info["capabilities"] + ["ssl_validation", "certificate_info"],
            "requirements": ["ssl", "socket"],
            "default_port": self.default_port,
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "The target hostname or IP address to check SSL certificate (e.g., 'example.com' or '1.2.3.4')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Optional: Port number (default: 443)"
                    }
                },
                "required": ["host"]
            },
            "example_usage": {
                "host": "example.com",
                "port": 443,
                "timeout": 30
            }
        })
        return base_info


# Factory function
def create_ssl_check_adapter(config: Dict[str, Any] = None) -> SslCheckAdapter:
    """
    Factory function to create an SSL check adapter instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        SslCheckAdapter: Configured adapter instance
    """
    if config is None:
        config = {}
    return SslCheckAdapter(config)
