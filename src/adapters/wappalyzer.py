import wappalyzer
from typing import Any, Dict
from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
import time
import warnings

# Suppress warnings from Wappalyzer if any
warnings.filterwarnings("ignore")

class WappalyzerAdapter(BaseAdapter):
    """
    Adapter for performing technology stack detection using Wappalyzer.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._required_params = ["url"]

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        """
        Execute Wappalyzer technology detection.
        
        Args:
            params: Must contain 'url' key
            
        Returns:
            AdapterResult with detected technologies
        """
        url = params["url"]
        
        try:
            # Ensure URL has protocol
            if not url.startswith("http"):
                url = f"http://{url}"
                
            self.logger.info(f"Starting Wappalyzer scan for {url}")
            
            # Use wappalyzer.analyze_with_versions
            technologies = wappalyzer.analyze_with_versions(url)
            
            # Format results for better readability
            formatted_results = []
            for tech_name, tech_data in technologies.items():
                versions = tech_data.get('versions', []) if isinstance(tech_data, dict) else []
                formatted_results.append({
                    "name": tech_name,
                    "versions": versions if versions else []
                })
            
            # Store evidence
            evidence_filename = f"wappalyzer_{url.replace('://', '_').replace('/', '_')}_{int(time.time())}.txt"
            evidence_data = f"Wappalyzer Results for {url}\\n\\n"
            for tech in formatted_results:
                evidence_data += f"Technology: {tech['name']}\\n"
                if tech['versions']:
                    evidence_data += f"  Versions: {', '.join(tech['versions'])}\\n"
                evidence_data += "\\n"
            evidence_path = self._store_evidence(evidence_data, evidence_filename)
            
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "url": url,
                    "technologies": formatted_results, 
                    "count": len(formatted_results)
                },
                metadata={
                    "adapter": self.name,
                    "url": url,
                    "timestamp": time.time()
                },
                evidence_path=evidence_path
            )
            
        except Exception as e:
            self.logger.error(f"Wappalyzer scan failed: {e}")
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={
                    "adapter": self.name,
                    "url": url,
                    "timestamp": time.time()
                },
                error_message=str(e)
            )

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update({
            "name": "WappalyzerAdapter",
            "version": "1.0.0",
            "description": "Technology stack detection using Wappalyzer",
            "capabilities": base_info["capabilities"] + ["tech_detection"],
            "requirements": ["wappalyzer"]
        })
        return base_info


def create_wappalyzer_adapter(config: Dict[str, Any] = None) -> WappalyzerAdapter:
    if config is None:
        config = {}
    return WappalyzerAdapter(config)
