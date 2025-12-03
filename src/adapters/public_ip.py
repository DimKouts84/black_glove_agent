"""
Public IP detection adapter for Black Glove.

Uses external services to detect the user's public IPv4 and IPv6 addresses.
Primary service: ipify.org (industry standard)
Fallback: icanhazip.com
"""

import requests
from typing import Any, Dict, Optional
from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
import time
import logging


class PublicIpAdapter(BaseAdapter):
    """
    Adapter for detecting public IP addresses using external services.
    
    Uses ipify.org as primary service with fallback to icanhazip.com.
    Supports both IPv4 and IPv6 detection.
    """
    
    # Primary service (most widely used and reliable)
    IPV4_PRIMARY = "https://api.ipify.org?format=json"
    IPV6_PRIMARY = "https://api64.ipify.org?format=json"
    
    # Fallback services
    FALLBACK_SERVICES = [
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://api.my-ip.io/ip"
    ]
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._required_params = []  # No parameters required
        self.timeout = 10  # seconds
        
    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Detect public IP address using external services.
        
        Args:
            params: No parameters required (can be empty dict)
            
        Returns:
            AdapterResult with IP address information
        """
        self.logger.info("Detecting public IP address...")
        
        ipv4 = None
        ipv6 = None
        errors = []
        
        # Try to get IPv4
        try:
            ipv4 = self._get_ip_from_service(self.IPV4_PRIMARY)
            self.logger.info(f"Detected IPv4: {ipv4}")
        except Exception as e:
            self.logger.warning(f"Primary IPv4 service failed: {e}")
            errors.append(f"IPv4 primary: {str(e)}")
            
            # Try fallback services
            ipv4 = self._try_fallback_services()
            if ipv4:
                self.logger.info(f"Detected IPv4 via fallback: {ipv4}")
        
        # Try to get IPv6
        try:
            ipv6 = self._get_ip_from_service(self.IPV6_PRIMARY)
            self.logger.info(f"Detected IPv6: {ipv6}")
        except Exception as e:
            self.logger.debug(f"IPv6 detection failed (may not be available): {e}")
            errors.append(f"IPv6: {str(e)}")
        
        # Check if we got at least one IP
        if not ipv4 and not ipv6:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "timestamp": time.time(),
                    "errors": errors
                },
                error_message="Failed to detect public IP from all services"
            )
        
        # Prepare result data
        result_data = {}
        if ipv4:
            result_data["ipv4"] = ipv4
        if ipv6:
            result_data["ipv6"] = ipv6
        
        # Store evidence
        evidence_text = "Public IP Detection Results\n"
        evidence_text += f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        if ipv4:
            evidence_text += f"IPv4 Address: {ipv4}\n"
        if ipv6:
            evidence_text += f"IPv6 Address: {ipv6}\n"
        if errors:
            evidence_text += f"\nErrors encountered:\n"
            for error in errors:
                evidence_text += f"  - {error}\n"
        
        evidence_filename = f"public_ip_{int(time.time())}.txt"
        evidence_path = self._store_evidence(evidence_text, evidence_filename)
        
        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data=result_data,
            metadata={
                "adapter": self.name,
                "timestamp": time.time(),
                "services_used": ["ipify.org"],
                "errors": errors if errors else None
            },
            evidence_path=evidence_path
        )
    
    def _get_ip_from_service(self, url: str) -> Optional[str]:
        """
        Query a single IP detection service.
        
        Args:
            url: Service URL to query
            
        Returns:
            IP address string or None if failed
        """
        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        
        # Handle JSON responses
        if url.endswith("format=json"):
            data = response.json()
            return data.get("ip")
        
        # Handle plain text responses
        return response.text.strip()
    
    def _try_fallback_services(self) -> Optional[str]:
        """
        Try fallback services if primary fails.
        
        Returns:
            IP address or None if all failed
        """
        for service_url in self.FALLBACK_SERVICES:
            try:
                ip = self._get_ip_from_service(service_url)
                if ip:
                    self.logger.info(f"Got IP from fallback service: {service_url}")
                    return ip
            except Exception as e:
                self.logger.debug(f"Fallback service {service_url} failed: {e}")
                continue
        
        return None
    
    def get_info(self) -> Dict[str, Any]:
        """Get adapter information."""
        base_info = super().get_info()
        base_info.update({
            "name": "PublicIpAdapter",
            "version": "1.0.0",
            "description": "Detect public IP address using ipify.org and fallback services",
            "category": "reconnaissance",
            "capabilities": base_info["capabilities"] + ["ip_detection", "passive_recon"],
            "requirements": ["requests"],
            "parameters": {},  # No parameters required
            "safe_mode": True,  # Always safe, no target interaction
        })
        return base_info


def create_public_ip_adapter(config: Dict[str, Any] = None) -> PublicIpAdapter:
    """
    Factory function to create PublicIpAdapter instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        PublicIpAdapter instance
    """
    if config is None:
        config = {}
    return PublicIpAdapter(config)
