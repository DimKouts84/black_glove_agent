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
            
            # wappalyzer.analyze returns: {url: {tech_name: {version, confidence, categories, groups}, ...}}
            result = wappalyzer.analyze(url, scan_type='full', threads=3)
            
            # Extract technologies from the URL key
            technologies = result.get(url, {})
            
            # Format results for better readability
            formatted_results = []
            for tech_name, tech_data in technologies.items():
                version = tech_data.get('version', '') if isinstance(tech_data, dict) else ''
                confidence = tech_data.get('confidence', 0) if isinstance(tech_data, dict) else 0
                categories = tech_data.get('categories', []) if isinstance(tech_data, dict) else []
                formatted_results.append({
                    "name": tech_name,
                    "version": version if version else None,
                    "confidence": confidence,
                    "categories": categories
                })
            
            # Store evidence
            evidence_filename = f"wappalyzer_{url.replace('://', '_').replace('/', '_')}_{int(time.time())}.txt"
            evidence_data = f"Wappalyzer Results for {url}\\n\\n"
            for tech in formatted_results:
                evidence_data += f"Technology: {tech['name']}\\n"
                if tech['version']:
                    evidence_data += f"  Version: {tech['version']}\\n"
                evidence_data += f"  Confidence: {tech['confidence']}%\\n"
                if tech['categories']:
                    evidence_data += f"  Categories: {', '.join(tech['categories'])}\\n"
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

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Wappalyzer scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No Wappalyzer data."
            
        techs = data.get("technologies", [])
        target = data.get("url", "unknown") # Use 'url' from data, not 'target'
        
        if not techs:
            return f"Wappalyzer detected NO technologies on {target}."
            
        summary = f"Wappalyzer detected {len(techs)} technologies on {target}:\n"
        
        # techs is a list of dictionaries, as formatted in _execute_impl
        for tech in techs:
            name = tech.get("name", "Unknown")
            version = tech.get("version")
            confidence = tech.get("confidence", 0)
            categories = tech.get("categories", [])
            
            tech_summary = f"  - {name}"
            if version:
                tech_summary += f" (v{version})"
            if categories:
                tech_summary += f" [{', '.join(categories)}]"
            if confidence and confidence > 0:
                tech_summary += f" (Confidence: {confidence}%)"
            summary += tech_summary + "\n"
        
        return summary

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
