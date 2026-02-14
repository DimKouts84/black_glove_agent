import sys
import os
from contextlib import contextmanager

@contextmanager
def suppress_output():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = devnull
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

try:
    with suppress_output():
        import sublist3r
        
        # Monkey-patch sublist3r to fix "expected string or bytes-like object, got 'int'" error
        # which happens when an engine times out and returns 0 instead of a string.
        if hasattr(sublist3r, 'enumratorBase'):
            original_get_response = sublist3r.enumratorBase.get_response
            def patched_get_response(self, response):
                res = original_get_response(self, response)
                if res == 0:
                    return ""
                return res
            sublist3r.enumratorBase.get_response = patched_get_response
except ImportError:
    # Fallback if sublist3r is not installed or fails to import
    sublist3r = None

from typing import Any, Dict
from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
import time

class Sublist3rAdapter(BaseAdapter):
    """
    Adapter for performing subdomain enumeration using Sublist3r.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._required_params = ["domain"]

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute Sublist3r subdomain enumeration.
        
        Args:
            params: Must contain 'domain' key
            
        Returns:
            AdapterResult with discovered subdomains
        """
        domain = params["domain"]
        
        try:
            self.logger.info(f"Starting Sublist3r scan for {domain}")
            
            # Sublist3r signature: main(domain, threads, savefile, silent, verbose, enable_bruteforce, engines, names)
            result = sublist3r.main(
                domain,
                40,             # threads
                None,           # savefile
                True,           # silent
                False,          # verbose
                False,          # enable_bruteforce
                None,           # engines
                None            # names
            )
            
            # Sublist3r returns either:
            # - A flat list of subdomains (older versions)
            # - A list of dicts [{engine: result}, ...] (newer versions)
            subdomains = []
            if result is None:
                result = []
            
            # Handle both formats
            if isinstance(result, list):
                for item in result:
                    if isinstance(item, str):
                        # Flat list of subdomain strings
                        subdomains.append(item)
                    elif isinstance(item, dict):
                        # Dict per engine: {engine_name: list_or_error}
                        for engine, engine_result in item.items():
                            if isinstance(engine_result, list):
                                subdomains.extend(engine_result)
                            # Skip exceptions/errors from individual engines
            
            # Deduplicate and sort
            unique_subdomains = sorted(list(set(subdomains)))
            
            # Store evidence
            evidence_filename = f"sublist3r_{domain.replace('.', '_')}_{int(time.time())}.txt"
            evidence_data = f"Sublist3r Results for {domain}\\n\\n"
            for subdomain in unique_subdomains:
                evidence_data += f"{subdomain}\\n"
            evidence_path = self._store_evidence(evidence_data, evidence_filename)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "domain": domain,
                    "subdomains": unique_subdomains, 
                    "count": len(unique_subdomains)
                },
                metadata={
                    "adapter": self.name,
                    "domain": domain,
                    "timestamp": time.time()
                },
                evidence_path=evidence_path
            )
            
        except Exception as e:
            self.logger.error(f"Sublist3r scan failed: {e}")
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
            return f"Sublist3r scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No Sublist3r data."
            
        subdomains = data.get("subdomains", [])
        domain = data.get("domain", "unknown")
        
        if not subdomains:
            return f"Sublist3r found NO subdomains for {domain}."
            
        summary = f"Sublist3r found {len(subdomains)} subdomains for {domain}:\n"
        
        # Limit output
        for sub in subdomains[:20]:
            summary += f"  - {sub}\n"
            
        if len(subdomains) > 20:
            summary += f"  ... and {len(subdomains)-20} more.\n"
            
        return summary

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update({
            "name": "Sublist3rAdapter",
            "version": "1.0.0",
            "description": "Subdomain enumeration using Sublist3r",
            "capabilities": base_info["capabilities"] + ["subdomain_enumeration"],
            "requirements": ["sublist3r-lib"]
        })
        return base_info


def create_sublist3r_adapter(config: Dict[str, Any] = None) -> Sublist3rAdapter:
    if config is None:
        config = {}
    return Sublist3rAdapter(config)
