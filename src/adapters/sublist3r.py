import sublist3r
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
            
            # Sublist3r arguments: domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines
            subdomains = sublist3r.main(
                domain, 
                40,  # threads
                savefile=None, 
                ports=None, 
                silent=True, 
                verbose=False, 
                enable_bruteforce=False, 
                engines=None
            )
            
            # Sublist3r returns a list of subdomains (strings) or None
            if subdomains is None:
                subdomains = []
            
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
