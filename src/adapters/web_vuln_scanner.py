"""
Web Vulnerability Scanner Adapter for Black Glove Pentest Agent

Performs lightweight active scanning for common web vulnerabilities:
- Reflected Cross-Site Scripting (XSS)
- Path Traversal / LFI
- Server-Side Template Injection (SSTI)
- Missing Security Headers

Safe detection focus (non-destructive).
"""

import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus

logger = logging.getLogger(__name__)

class WebVulnScannerAdapter(BaseAdapter):
    """
    Lightweight Web Vulnerability Scanner.
    
    Implements:
    1. Reflected XSS detection
    2. Path Traversal detection
    3. SSTI detection
    4. Security Header analysis
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "WebVulnScannerAdapter"
        self.version = "1.0.0"
        self.description = "Lightweight web vulnerability scanner (XSS, LFI, SSTI, Headers)"
        
        self._timeout = self.config.get("timeout", 10.0)
        self._user_agent = self.config.get(
            "user_agent", 
            "Mozilla/5.0 (compatible; BlackGloveScanner/1.0; +https://github.com/black-glove)"
        )

    def validate_params(self, params: Dict[str, Any]) -> None:
        if "target_url" not in params or not params["target_url"]:
            raise ValueError("target_url is required")
        
        parsed = urllib.parse.urlparse(params["target_url"])
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid target_url format")

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["xss", "lfi", "ssti", "headers"],
            "requirements": ["requests"],
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Full URL to scan including scheme (e.g., 'https://example.com/page?param=value')"
                    },
                    "scans": {
                        "type": "array",
                        "description": "Optional scan types: xss, lfi, ssti, headers (default: all)"
                    },
                    "params_to_test": {
                        "type": "array",
                        "description": "Optional: specific URL parameters to test"
                    }
                },
                "required": ["target_url"]
            }
        }

    def _request(self, method: str, url: str) -> requests.Response:
        try:
            return requests.request(
                method,
                url,
                headers={"User-Agent": self._user_agent},
                timeout=self._timeout,
                verify=False
            )
        except requests.RequestException as e:
            logger.warning(f"Request failed: {url} - {e}")
            return None

    def _check_headers(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Check for missing or misconfigured security headers."""
        findings = []
        headers = response.headers
        
        security_headers = {
            "Content-Security-Policy": "Missing Content-Security-Policy (CSP) header.",
            "X-Frame-Options": "Missing X-Frame-Options header (Clickjacking risk).",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header.",
            "Strict-Transport-Security": "Missing HSTS header (HTTPS enforcement)."
        }
        
        for header, msg in security_headers.items():
            if header not in headers:
                findings.append({
                    "type": "missing_header",
                    "header": header,
                    "evidence": msg,
                    "severity": "low"
                })
        
        # Check for server leakage
        if "Server" in headers:
            findings.append({
                "type": "info_disclosure",
                "header": "Server",
                "evidence": f"Server header detected: {headers['Server']}",
                "severity": "info"
            })
            
        return findings

    def _check_xss(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        """Check for potentially reflected XSS."""
        # Simple canary payload
        canary = "BG_XSS_TEST_" + str(int(urllib.parse.urlparse(url).port or 80))
        payload = f"<script>console.log('{canary}')</script>"
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        original_val = query_params.get(param, [""])[0]
        
        # Inject
        query_params[param] = [payload]
        new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_params, doseq=True)))
        
        resp = self._request("GET", new_url)
        if resp:
            if payload in resp.text:
                logger.info(f"XSS reflected via {param}")
                return {
                    "type": "xss_reflected",
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Payload reflected in response body",
                    "severity": "high"
                }
            else:
                 if canary in resp.text:
                     logger.debug(f"XSS sanitized for param {param} (canary reflected, tags stripped)")
        else:
             logger.debug(f"Request failed for XSS check on param {param}")

        return None

    def _check_lfi(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        """Check for Path Traversal / LFI."""
        payloads = [
            ("../../../../etc/passwd", "root:x:0:0:"),
            ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("/etc/passwd", "root:x:0:0:")
        ]
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for payload, marker in payloads:
            query_params[param] = [payload]
            new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_params, doseq=True)))
            
            resp = self._request("GET", new_url)
            if resp and marker in resp.text:
                return {
                    "type": "path_traversal",
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Found marker '{marker}' in response",
                    "severity": "high"
                }
        return None

    def _check_ssti(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        """Check for Server-Side Template Injection."""
        # Simple math injection: 7*7 = 49
        payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49")
        ]
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        original_val = query_params.get(param, [""])[0]
        
        for payload, marker in payloads:
            # We look for the result (49) but ensure the payload itself isn't just reflected
            # If payload is "{{7*7}}" and response has "{{7*7}}", it's likely just XSS or text.
            # If response has "49" and NOT "{{7*7}}", it's SSTI.
            
            query_params[param] = [payload]
            new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_params, doseq=True)))
            
            resp = self._request("GET", new_url)
            if resp:
                if marker in resp.text and payload not in resp.text:
                     return {
                        "type": "ssti",
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Expression evaluated to '{marker}'",
                        "severity": "critical"
                    }
        return None

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target_url = params["target_url"]
        scans = params.get("scans", ["xss", "lfi", "ssti", "headers"])
        params_to_test = params.get("params_to_test")
        
        logger.info(f"Starting Web Vuln scan on {target_url}")
        
        # 1. Baseline Request & Header Analysis
        baseline_resp = self._request("GET", target_url)
        if not baseline_resp:
             return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data={},
                error_message="Could not connect to target",
                metadata={}
            )
            
        findings = []
        
        if "headers" in scans:
            header_findings = self._check_headers(baseline_resp)
            findings.extend(header_findings)
            
        # 2. Parameter Analysis
        parsed = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        scan_params = list(query_params.keys())
        if params_to_test:
            scan_params = [p for p in scan_params if p in params_to_test]
            
        for param in scan_params:
            if "xss" in scans:
                res = self._check_xss(target_url, param)
                if res: findings.append(res)
                
            if "lfi" in scans:
                res = self._check_lfi(target_url, param)
                if res: findings.append(res)
                
            if "ssti" in scans:
                res = self._check_ssti(target_url, param)
                if res: findings.append(res)

        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "target_url": target_url,
                "vulnerabilities": findings,
                "scanned_params": scan_params
            },
            metadata={}
        )

def create_web_vuln_scanner_adapter(config: Dict[str, Any] = None) -> WebVulnScannerAdapter:
    return WebVulnScannerAdapter(config)
