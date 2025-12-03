import shodan
from typing import Any, Dict
from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
import time
import os

class ShodanAdapter(BaseAdapter):
    """
    Adapter for performing passive reconnaissance using Shodan API.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._required_params = ["ip"]
        self.api_key = config.get("shodan_api_key") or os.getenv("SHODAN_API_KEY")
            
        if self.api_key:
            self.api = shodan.Shodan(self.api_key)
        else:
            self.api = None
            self.logger.warning("Shodan API key not found. Shodan adapter will not function correctly.")

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute Shodan host lookup.
        
        Args:
            params: Must contain 'ip' key
            
        Returns:
            AdapterResult with host information
        """
        ip = params["ip"]
        
        if not self.api:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "ip": ip,
                    "timestamp": time.time()
                },
                error_message="Shodan API key not configured"
            )

        try:
            self.logger.info(f"Starting Shodan lookup for {ip}")
            
            # Lookup the host
            host_info = self.api.host(ip)
            
            # Extract relevant info
            data = {
                "ip": host_info.get("ip_str"),
                "org": host_info.get("org"),
                "os": host_info.get("os"),
                "ports": host_info.get("ports", []),
                "vulns": list(host_info.get("vulns", [])),
                "hostnames": host_info.get("hostnames", [])
            }
            
            # Store evidence
            evidence_filename = f"shodan_{ip.replace('.', '_')}_{int(time.time())}.txt"
            evidence_data = f"Shodan Results for {ip}\\n\\n"
            evidence_data += f"IP: {data['ip']}\\n"
            evidence_data += f"Organization: {data['org']}\\n"
            evidence_data += f"OS: {data['os']}\\n"
            evidence_data += f"Open Ports: {', '.join(map(str, data['ports']))}\\n"
            evidence_data += f"Hostnames: {', '.join(data['hostnames'])}\\n"
            evidence_data += f"Vulnerabilities: {', '.join(data['vulns'])}\\n"
            evidence_path = self._store_evidence(evidence_data, evidence_filename)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data=data,
                metadata={
                    "adapter": self.name,
                    "ip": ip,
                    "timestamp": time.time()
                },
                evidence_path=evidence_path
            )
            
        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "ip": ip,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )
        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "ip": ip,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update({
            "name": "ShodanAdapter",
            "version": "1.0.0",
            "description": "Passive reconnaissance using Shodan API",
            "capabilities": base_info["capabilities"] + ["passive_recon", "host_lookup"],
            "requirements": ["shodan", "shodan_api_key"]
        })
        return base_info


def create_shodan_adapter(config: Dict[str, Any] = None) -> ShodanAdapter:
    if config is None:
        config = {}
    return ShodanAdapter(config)
