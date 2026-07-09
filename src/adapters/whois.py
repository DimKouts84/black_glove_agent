"""
WHOIS Adapter for Black Glove Pentest Agent

This module provides a WHOIS lookup adapter for domain information gathering
during passive reconnaissance phases.
"""

import time
import whois
from typing import Any, Dict

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from .domain_params import resolve_domain


class WhoisAdapter(BaseAdapter):
    """
    WHOIS adapter for domain information lookup.
    
    This adapter performs WHOIS queries to gather domain registration
    information including registrar, creation date, expiration date,
    and contact information.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the WHOIS adapter.
        
        Args:
            config: Adapter configuration dictionary
        """
        super().__init__(config)
        self._required_config_fields = []
        self._required_params = ["domain"]
        self.version = "1.0.0"
    
    def validate_config(self) -> bool:
        """
        Validate the adapter configuration.
        
        Returns:
            bool: True if configuration is valid
        """
        # Call parent validation
        super().validate_config()
        
        # WHOIS-specific validation (timeout in config is reserved for future use)
        return True
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Validate execution parameters.
        
        Args:
            params: Parameters to validate
            
        Returns:
            bool: True if parameters are valid
        """
        if not isinstance(params, dict):
            raise ValueError("Parameters must be a dictionary")

        if "domain" not in params:
            try:
                params["domain"] = resolve_domain(params)
            except ValueError:
                pass

        # Call parent validation
        super().validate_params(params)
        if "domain" in params:
            if not isinstance(params["domain"], str) or not params["domain"].strip():
                raise ValueError("Domain must be a non-empty string")
        
        return True

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute the WHOIS lookup.
        
        Args:
            params: Execution parameters containing 'domain'
            
        Returns:
            AdapterResult: Standardized result structure
        """
        domain = params["domain"]
        
        self.logger.info(f"Performing WHOIS lookup for domain: {domain}")
        
        try:
            # Execute WHOIS query
            start_time = time.time()
            whois_info = whois.whois(domain)
            execution_time = time.time() - start_time
            
            # Store raw evidence
            evidence_filename = f"whois_{domain.replace('.', '_')}_{int(time.time())}.txt"
            evidence_path = self._store_evidence(str(whois_info), evidence_filename)
            
            # Normalize list fields for consistent output
            def _first(val):
                if isinstance(val, list) and val:
                    return val[0]
                return val

            creation = _first(getattr(whois_info, 'creation_date', None))
            expiration = _first(getattr(whois_info, 'expiration_date', None))
            expires_in_days = None
            if expiration and hasattr(expiration, "timestamp"):
                import datetime
                expires_in_days = (expiration - datetime.datetime.utcnow()).days

            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "domain": domain,
                    "registrar": _first(getattr(whois_info, 'registrar', None)),
                    "creation_date": creation,
                    "expiration_date": expiration,
                    "expires_in_days": expires_in_days,
                    "name_servers": getattr(whois_info, 'name_servers', None),
                    "emails": getattr(whois_info, 'emails', None),
                    "org": getattr(whois_info, 'org', None),
                    "raw": str(whois_info)
                },
                metadata={
                    "adapter": self.name,
                    "domain": domain,
                    "timestamp": time.time(),
                    "execution_time": execution_time
                },
                execution_time=execution_time,
                evidence_path=evidence_path
            )
            
        except whois.WhoisError as e:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                metadata={
                    "adapter": self.name,
                    "domain": domain,
                    "timestamp": time.time()
                },
                error_message=f"WHOIS lookup failed: {str(e)}"
            )
        except Exception as e:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "domain": domain,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )
    
    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Whois lookup failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No Whois data."
            
        domain = data.get("domain")
        registrar = data.get("registrar")
        creation_date = data.get("creation_date")
        expiration_date = data.get("expiration_date")
        emails = data.get("emails")
        
        # Handle lists for dates/emails (whois sometimes returns lists)
        if isinstance(domain, list): domain = domain[0]
        if isinstance(registrar, list): registrar = registrar[0]
        
        def fmt_date(d):
            if isinstance(d, list): return str(d[0])
            return str(d)
            
        summary = f"Whois Registration Info for {domain}:\n"
        summary += f"- Registrar: {registrar}\n"
        summary += f"- Created: {fmt_date(creation_date)}\n"
        summary += f"- Expires: {fmt_date(expiration_date)}\n"
        
        if emails:
            if isinstance(emails, list):
                summary += f"- Emails: {', '.join(emails[:3])}\n"
            else:
                summary += f"- Email: {emails}\n"
                
        return summary

    def get_info(self) -> Dict[str, Any]:
        """
        Get adapter information.
        
        Returns:
            Dict containing adapter information
        """
        base_info = super().get_info()
        base_info.update({
            "name": "WhoisAdapter",
            "version": self.version,
            "description": "WHOIS adapter for domain registration information lookup. Use for domain names, not IP addresses.",
            "capabilities": base_info["capabilities"] + ["domain_lookup", "registration_info"],
            "requirements": ["python-whois"],
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The domain name to lookup (e.g., 'example.com'). NOT an IP address."
                    }
                },
                "required": ["domain"]
            },
            "example_usage": {
                "domain": "example.com"
            }
        })
        return base_info


# Factory function
def create_whois_adapter(config: Dict[str, Any] = None) -> WhoisAdapter:
    """
    Factory function to create a WHOIS adapter instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        WhoisAdapter: Configured adapter instance
    """
    if config is None:
        config = {}
    return WhoisAdapter(config)
