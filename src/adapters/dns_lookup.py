"""
DNS Lookup Adapter for Black Glove Pentest Agent

This module provides a DNS record lookup adapter for gathering DNS information
during passive reconnaissance phases.
"""

import time
import dns.resolver
import dns.exception
from typing import Any, Dict, List

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus


class DnsLookupAdapter(BaseAdapter):
    """
    DNS lookup adapter for DNS record enumeration.
    
    This adapter performs DNS queries to gather various DNS record types
    including A, AAAA, MX, NS, TXT, CNAME, and SOA records.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the DNS lookup adapter.
        
        Args:
            config: Adapter configuration dictionary
        """
        super().__init__(config)
        self._required_config_fields = []
        self._required_params = ["domain"]
        self.version = "1.0.0"
        self.default_record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    
    def validate_config(self) -> bool:
        """
        Validate the adapter configuration.
        
        Returns:
            bool: True if configuration is valid
        """
        # Call parent validation
        super().validate_config()
        
        # DNS-specific validation
        if "timeout" in self.config:
            if not isinstance(self.config["timeout"], (int, float)) or self.config["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        if "record_types" in self.config:
            if not isinstance(self.config["record_types"], list):
                raise ValueError("Record types must be a list")
            if not all(isinstance(rt, str) for rt in self.config["record_types"]):
                raise ValueError("All record types must be strings")
        
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
        
        # DNS-specific parameter validation
        if "domain" in params:
            if not isinstance(params["domain"], str) or not params["domain"].strip():
                raise ValueError("Domain must be a non-empty string")
        
        if "record_types" in params:
            if not isinstance(params["record_types"], list):
                raise ValueError("Record types must be a list")
            if not all(isinstance(rt, str) for rt in params["record_types"]):
                raise ValueError("All record types must be strings")
        
        if "timeout" in params:
            if not isinstance(params["timeout"], (int, float)) or params["timeout"] <= 0:
                raise ValueError("Timeout must be a positive number")
        
        return True
    
    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute the DNS lookup.
        
        Args:
            params: Execution parameters containing 'domain' and optional 'record_types', 'timeout'
            
        Returns:
            AdapterResult: Standardized result structure
        """
        domain = params["domain"]
        record_types = params.get("record_types", self.config.get("record_types", self.default_record_types))
        timeout = params.get("timeout", self.config.get("timeout", 30))
        
        self.logger.info(f"Performing DNS lookup for domain: {domain}")
        
        try:
            # Set resolver timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            dns_results = {}
            errors = {}
            
            # Query each record type
            for record_type in record_types:
                try:
                    start_time = time.time()
                    answers = resolver.resolve(domain, record_type)
                    query_time = time.time() - start_time
                    
                    records = []
                    for rdata in answers:
                        records.append(str(rdata))
                    
                    dns_results[record_type] = {
                        "records": records,
                        "count": len(records),
                        "query_time": query_time
                    }
                    
                except dns.resolver.NXDOMAIN:
                    dns_results[record_type] = {
                        "records": [],
                        "count": 0,
                        "error": "Domain does not exist"
                    }
                except dns.resolver.NoAnswer:
                    dns_results[record_type] = {
                        "records": [],
                        "count": 0,
                        "error": "No answer for record type"
                    }
                except dns.exception.Timeout:
                    errors[record_type] = f"Timeout after {timeout} seconds"
                except Exception as e:
                    errors[record_type] = str(e)
            
            # Store raw evidence
            evidence_filename = f"dns_{domain.replace('.', '_')}_{int(time.time())}.txt"
            evidence_data = f"DNS Lookup Results for {domain}\n\n"
            for record_type, result in dns_results.items():
                evidence_data += f"{record_type} Records:\n"
                if result.get("records"):
                    for record in result["records"]:
                        evidence_data += f"  {record}\n"
                else:
                    evidence_data += f"  {result.get('error', 'No records found')}\n"
                evidence_data += "\n"
            
            evidence_path = self._store_evidence(evidence_data, evidence_filename)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "domain": domain,
                    "records": dns_results,
                    "errors": errors
                },
                metadata={
                    "adapter": self.name,
                    "domain": domain,
                    "record_types": record_types,
                    "timestamp": time.time()
                },
                execution_time=time.time() - time.time(),  # Will be updated by base class
                evidence_path=evidence_path
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
            return f"DNS lookup failed: {result.error_message}"
        
        data = result.data
        if not data or not data.get("records"):
            return "No DNS data."
            
        summary = f"DNS Records for {data.get('domain', 'N/A')}:\n"
        total_records_found = 0
        
        for rtype, rtype_data in data["records"].items():
            records = rtype_data.get("records", [])
            count = rtype_data.get("count", 0)
            error = rtype_data.get("error")

            if records:
                total_records_found += count
                summary += f"- {rtype} ({count} records):\n"
                # Show first few
                for r in records[:5]:
                    summary += f"  {r}\n"
                if count > 5:
                    summary += f"  ... ({count-5} more)\n"
            elif error:
                summary += f"- {rtype}: {error}\n"
            else:
                summary += f"- {rtype}: No records found\n"
        
        if total_records_found == 0:
            return f"DNS lookup completed for {data.get('domain', 'N/A')} but found no records."
            
        return summary

    def cleanup(self) -> None:
        """
        Perform any necessary cleanup after adapter execution.
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """
        Get adapter information.
        
        Returns:
            Dict containing adapter information
        """
        base_info = super().get_info()
        base_info.update({
            "name": "DnsLookupAdapter",
            "version": self.version,
            "description": "DNS lookup adapter for DNS record enumeration. Use for domain names, not IP addresses.",
            "capabilities": base_info["capabilities"] + ["dns_enumeration", "record_lookup"],
            "requirements": ["dnspython"],
            "supported_record_types": self.default_record_types,
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The domain name to lookup (e.g., 'example.com'). NOT an IP address."
                    },
                    "record_types": {
                        "type": "array",
                        "description": "Optional: List of DNS record types to query (e.g., ['A', 'MX', 'NS'])"
                    }
                },
                "required": ["domain"]
            },
            "example_usage": {
                "domain": "example.com",
                "record_types": ["A", "MX", "NS"],
                "timeout": 30
            }
        })
        return base_info


# Factory function
def create_dns_lookup_adapter(config: Dict[str, Any] = None) -> DnsLookupAdapter:
    """
    Factory function to create a DNS lookup adapter instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        DnsLookupAdapter: Configured adapter instance
    """
    if config is None:
        config = {}
    return DnsLookupAdapter(config)
