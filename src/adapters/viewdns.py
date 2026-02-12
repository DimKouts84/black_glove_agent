import requests
from typing import Any, Dict
from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
import time
import os

class ViewDnsAdapter(BaseAdapter):
    """
    Adapter for performing active port scans using ViewDNS.info API.
    """
    
    BASE_URL = "https://api.viewdns.info/portscan/"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._required_params = ["host"]
        self.api_key = config.get("viewdns_api_key") or os.getenv("VIEWDNS_API_KEY")

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute ViewDNS port scan.
        
        Args:
            params: Must contain 'host' key
            
        Returns:
            AdapterResult with open ports
        """
        host = params["host"]
        
        if not self.api_key:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "timestamp": time.time()
                },
                error_message="ViewDNS API key not configured"
            )

        try:
            self.logger.info(f"Starting ViewDNS port scan for {host}")
            
            # ViewDNS API parameters
            payload = {
                "host": host,
                "apikey": self.api_key,
                "output": "json"
            }
            
            response = requests.get(self.BASE_URL, params=payload, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse response
            ports = []
            if "response" in data and "port" in data["response"]:
                for port_info in data["response"]["port"]:
                    if port_info.get("status") == "open":
                        ports.append({
                            "port": port_info.get("number"),
                            "service": port_info.get("service"),
                            "protocol": "tcp"
                        })
            
            # Store evidence
            evidence_filename = f"viewdns_{host.replace('.', '_')}_{int(time.time())}.txt"
            evidence_data = f"ViewDNS Port Scan Results for {host}\\n\\n"
            evidence_data += f"Open Ports ({len(ports)}): \\n"
            for port in ports:
                evidence_data += f"  Port {port['port']}: {port['service']} ({port['protocol']})\\n"
            evidence_path = self._store_evidence(evidence_data, evidence_filename)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "host": host,
                    "open_ports": ports, 
                    "count": len(ports)
                },
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "timestamp": time.time()
                },
                evidence_path=evidence_path
            )
            
        except requests.RequestException as e:
            self.logger.error(f"ViewDNS API request failed: {e}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )
        except Exception as e:
            self.logger.error(f"ViewDNS scan failed: {e}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "host": host,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"ViewDNS scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No ViewDNS data."
            
        open_ports = data.get("open_ports", [])
        target = data.get("host", "unknown") # Changed from 'target' to 'host' to match _execute_impl's data structure
        
        if not open_ports:
            return f"ViewDNS found NO open ports on {target}."
            
        summary = f"ViewDNS found {len(open_ports)} open ports on {target}:\n"
        
        # port entries are usually dicts from ViewDNS API?
        # My previous view of viewdns.py showed it returns a list of ports (dicts or ints?)
        # Let's assume common ViewDNS return format or my adapter's normalization.
        # If I can't be sure, I'll print raw.
        # But generally it's a list of dicts like {'port': '80', 'service': 'http'}
        
        for p in open_ports:
            if isinstance(p, dict):
                port = p.get("port", "?")
                service = p.get("service", "unknown")
                summary += f"  - Port {port}/tcp: {service}\n"
            else:
                summary += f"  - Port {p}\n"
                
        return summary

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update({
            "name": "ViewDnsAdapter",
            "version": "1.0.0",
            "description": "Active port scanning using ViewDNS.info API. Use for IP addresses or hostnames.",
            "capabilities": base_info["capabilities"] + ["active_scan", "port_scan"],
            "requirements": ["requests", "viewdns_api_key"],
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "The target IP address or hostname to scan (e.g., '192.168.1.1' or 'example.com')"
                    }
                },
                "required": ["host"]
            }
        })
        return base_info


def create_viewdns_adapter(config: Dict[str, Any] = None) -> ViewDnsAdapter:
    if config is None:
        config = {}
    return ViewDnsAdapter(config)
