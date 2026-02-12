import logging
import time
import concurrent.futures
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import dns.resolver
import dns.zone
import dns.query
import dns.exception

from .base import BaseAdapter, AdapterResult, AdapterResultStatus

logger = logging.getLogger(__name__)

class DNSReconAdapter(BaseAdapter):
    """
    Enhanced DNS Reconnaissance Adapter.
    Performs DNS Zone Transfers (AXFR) and Subdomain Brute-forcing.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "DNSReconAdapter"
        self.description = "Performs advanced DNS reconnaissance (Zone Transfer, Brute-force)"
        self.default_wordlist = Path("bin/wordlists/common.txt")

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status == AdapterResultStatus.FAILURE:
            return f"DNS Recon failed: {result.error_message}"
        elif result.status == AdapterResultStatus.PARTIAL:
            summary = f"DNS Recon completed with partial results and errors: {result.error_message}\n"
        else:
            summary = "DNS Reconnaissance Results:\n"
        
        data = result.data
        if not data:
            return summary + "No DNS Recon data."
            
        zone_transfer = data.get("zone_transfer", {})
        brute_force = data.get("brute_force", [])
        
        # Zone Transfer
        zt_found = False
        for ns, res in zone_transfer.items():
            if res.get("status") == "success":
                summary += f"- [CRITICAL] Zone transfer SUCCESSFUL on {ns}!\n"
                zt_found = True
                records = res.get("records", [])
                summary += f"  Retrieved {len(records)} records.\n"
            else:
                summary += f"- Zone transfer failed on {ns}.\n"
        if not zt_found and not zone_transfer:
            summary += "- No zone transfer attempts were successful or performed.\n"
        
        # Brute Force
        if brute_force:
            summary += f"- Brute force found {len(brute_force)} subdomains.\n"
            for item in brute_force[:10]:
                 # item is like {'name': 'foo.com', 'address': '1.2.3.4'}
                 name = item.get("name", "")
                 addr = item.get("address", "")
                 summary += f"  {name} -> {addr}\n"
            if len(brute_force) > 10:
                summary += f"  ... ({len(brute_force)-10} more)\n"
        else:
            summary += "- Brute force found no subdomains.\n"
            
        return summary

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": "1.0.0",
            "description": self.description,
            "capabilities": ["zone_transfer", "brute_force"],
            "requirements": ["dnspython"],
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The domain to scan (e.g., 'example.com')"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["zone_transfer", "brute_force", "all"],
                        "description": "Scanning mode (default: all)"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Optional: Path to custom subdomain wordlist"
                    }
                },
                "required": ["target"]
            }
        }

    def validate_params(self, params: Dict[str, Any]) -> None:
        if "target" not in params or not params["target"]:
            raise ValueError("Target domain is required")
        
        mode = params.get("mode", "all")
        if mode not in ["zone_transfer", "brute_force", "all"]:
            raise ValueError(f"Invalid mode: {mode}. Must be 'zone_transfer', 'brute_force', or 'all'")

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        domain = params["target"]
        mode = params.get("mode", "all")
        wordlist_path = params.get("wordlist")
        
        if wordlist_path:
            wordlist_path = Path(wordlist_path)
        else:
            # Resolve relative to project root if possible, or use absolute path if provided in config
            # Here we assume running from project root
            wordlist_path = self.default_wordlist
            if not wordlist_path.exists():
                 # Try to find it relative to this file? No, standard is project root.
                 # Let's log a warning if we can't find it and define a fallback or fail
                 pass

        result_data = {
            "domain": domain,
            "zone_transfer": {},
            "brute_force": [],
            "errors": []
        }

        # 1. Zone Transfer
        if mode in ["zone_transfer", "all"]:
            logger.info(f"Attempting Zone Transfer on {domain}")
            zt_results = self._attempt_zone_transfer(domain)
            result_data["zone_transfer"] = zt_results
            if "error" in zt_results:
                result_data["errors"].append(f"Zone Transfer failed: {zt_results['error']}")

        # 2. Brute Force
        if mode in ["brute_force", "all"]:
            logger.info(f"Starting Subdomain Brute-force on {domain}")
            if wordlist_path and wordlist_path.exists():
                bf_results = self._brute_force_subdomains(domain, wordlist_path)
                result_data["brute_force"] = bf_results
            else:
                msg = f"Wordlist not found at {wordlist_path}. Skipping brute-force."
                logger.warning(msg)
                result_data["errors"].append(msg)

        status = AdapterResultStatus.SUCCESS
        if not result_data["zone_transfer"] and not result_data["brute_force"] and result_data["errors"]:
             status = AdapterResultStatus.FAILURE
        elif result_data["errors"]:
             status = AdapterResultStatus.PARTIAL

        return AdapterResult(
            status=status,
            data=result_data,
            metadata={}
        )

    def _attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempts AXFR against all nameservers."""
        results = {}
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(r.target) for r in ns_answers]
        except Exception as e:
            logger.error(f"Failed to resolve NS records for {domain}: {e}")
            return {"error": str(e)}

        for ns in nameservers:
            ns_clean = ns.rstrip('.')
            try:
                # Resolve IP of nameserver
                ns_ip = dns.resolver.resolve(ns_clean, 'A')[0].address
                # Attempt Zone Transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=5.0))
                
                # If successful, parse records
                records = []
                for name, node in zone.nodes.items():
                    name_str = str(name) + "." + domain if str(name) != "@" else domain
                    for rdataset in node.rdatasets:
                        records.append(f"{name_str} {rdataset}")
                
                results[ns_clean] = {"status": "success", "records": records}
                logger.info(f"Zone transfer SUCCESS against {ns_clean}")
                
            except Exception as e:
                pass
                # Most servers deny AXFR, so this is expected. We don't populate failures to keep noise down
                # or we can verify if the user wants verbose failure logs
        
        return results

    def _brute_force_subdomains(self, domain: str, wordlist_path: Path) -> List[str]:
        """Brute-forces subdomains using a wordlist and ThreadPool."""
        found_subdomains = set()
        
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to read wordlist: {e}")
            return []

        # Limit concurrency
        max_workers = 10
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        def check_subdomain(sub: str) -> Optional[str]:
            full_domain = f"{sub}.{domain}"
            try:
                # Try A record
                resolver.resolve(full_domain, 'A')
                return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
            for future in concurrent.futures.as_completed(future_to_sub):
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        return sorted(list(found_subdomains))


def create_dns_recon_adapter(config: Dict[str, Any] = None) -> BaseAdapter:
    return DNSReconAdapter(config)
