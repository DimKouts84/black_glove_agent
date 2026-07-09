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
    sublist3r = None

from typing import Any, Dict, List
from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from .domain_params import resolve_domain
import time

SENSITIVE_PREFIXES = ("dev.", "staging.", "admin.", "test.", "internal.")


class Sublist3rAdapter(BaseAdapter):
    """
    Adapter for performing subdomain enumeration using Sublist3r.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._required_params = ["domain"]
        self.default_threads = int(config.get("threads", 40))

    def validate_config(self) -> bool:
        super().validate_config()
        if sublist3r is None:
            raise ValueError("sublist3r package is not installed")
        return True

    def validate_params(self, params: Dict[str, Any]) -> bool:
        if sublist3r is None:
            raise ValueError("sublist3r package is not installed")
        if "domain" not in params:
            try:
                params["domain"] = resolve_domain(params)
            except ValueError:
                pass
        super().validate_params(params)
        max_results = params.get("max_results")
        if max_results is not None and (
            not isinstance(max_results, int) or max_results <= 0
        ):
            raise ValueError("max_results must be a positive integer")
        return True

    def _filter_subdomains(self, subdomains: List[str], domain: str) -> List[str]:
        """Keep only subdomains in the parent zone."""
        filtered = []
        domain = domain.lower().strip(".")
        for sub in subdomains:
            if not isinstance(sub, str):
                continue
            sub = sub.strip().lower()
            if sub == domain or sub.endswith(f".{domain}"):
                filtered.append(sub)
        return sorted(list(set(filtered)))

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        domain = params["domain"]
        max_results = params.get("max_results")
        threads = int(params.get("threads", self.default_threads))

        if sublist3r is None:
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"adapter": self.name, "domain": domain, "timestamp": time.time()},
                error_message="sublist3r package is not installed",
            )
        
        try:
            self.logger.info(f"Starting Sublist3r scan for {domain}")
            
            result = sublist3r.main(
                domain,
                threads,
                None,
                True,
                False,
                False,
                None,
                None,
            )
            
            subdomains: List[str] = []
            if result is None:
                result = []
            
            if isinstance(result, list):
                for item in result:
                    if isinstance(item, str):
                        subdomains.append(item)
                    elif isinstance(item, dict):
                        for engine, engine_result in item.items():
                            if isinstance(engine_result, list):
                                subdomains.extend(engine_result)
            
            unique_subdomains = self._filter_subdomains(subdomains, domain)
            if max_results:
                unique_subdomains = unique_subdomains[:max_results]
            
            evidence_filename = f"sublist3r_{domain.replace('.', '_')}_{int(time.time())}.txt"
            evidence_data = f"Sublist3r Results for {domain}\n\n"
            for subdomain in unique_subdomains:
                evidence_data += f"{subdomain}\n"
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
        
        for sub in subdomains[:20]:
            flag = " [sensitive pattern]" if any(sub.startswith(p) for p in SENSITIVE_PREFIXES) else ""
            summary += f"  - {sub}{flag}\n"
            
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
            "requirements": ["sublist3r-lib"],
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"},
                    "max_results": {"type": "integer", "description": "Limit results after dedup"},
                    "threads": {"type": "integer", "description": "Worker threads (default from config)"},
                },
                "required": ["domain"],
            },
        })
        return base_info


def create_sublist3r_adapter(config: Dict[str, Any] = None) -> Sublist3rAdapter:
    if config is None:
        config = {}
    return Sublist3rAdapter(config)
