"""
Web Vulnerability Scanner Adapter for Black Glove Pentest Agent

Performs lightweight active scanning for common web vulnerabilities:
- Reflected Cross-Site Scripting (XSS)
- Path Traversal / LFI
- Server-Side Template Injection (SSTI)

Safe detection focus (non-destructive). Use web_server_scanner for header checks.
"""

import hashlib
import logging
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from .url_params import resolve_target_url

logger = logging.getLogger(__name__)

EXPLOITABLE_TYPES = {"xss_reflected", "path_traversal", "ssti"}


class WebVulnScannerAdapter(BaseAdapter):
    """Lightweight web vulnerability scanner (XSS, LFI, SSTI)."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "WebVulnScannerAdapter"
        self.version = "1.1.0"
        self.description = "Lightweight web vulnerability scanner (XSS, LFI, SSTI)"

        self._timeout = self.config.get("timeout", 10.0)
        self._user_agent = self.config.get(
            "user_agent",
            "Mozilla/5.0 (compatible; BlackGloveScanner/1.0; +https://github.com/black-glove)",
        )

    def validate_params(self, params: Dict[str, Any]) -> None:
        resolve_target_url(params)

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Web Vuln scan failed: {result.error_message}"

        data = result.data
        if not data:
            return "No Web Vuln scan data."

        vulns = data.get("vulnerabilities", [])
        scanned_count = len(data.get("scanned_params", []))
        exploitable = [v for v in vulns if v.get("type") in EXPLOITABLE_TYPES]

        if not exploitable:
            if scanned_count == 0:
                return (
                    f"Web Vuln Scanner: no URL query parameters to test on {data.get('target_url', 'target')} "
                    "(scan not applicable - static page or parameterless URL)."
                )
            return (
                f"Web Vuln Scanner checked {scanned_count} parameters and found "
                "NO exploitable vulnerabilities."
            )

        summary = (
            f"Web Vuln Scanner FOUND {len(exploitable)} potential issues "
            f"(checked {scanned_count} params):\n"
        )
        for v in exploitable:
            type_ = v.get("type", "unknown")
            sev = v.get("severity", "medium").upper()
            url = v.get("url", "")
            param = v.get("parameter", "")
            payload = v.get("payload", "")
            evidence = v.get("evidence", "")

            summary += f"  - [{sev}] {type_} in parameter '{param}' at {url}\n"
            if payload:
                summary += f"    Payload: {payload}\n"
            if evidence:
                summary += f"    Evidence: {evidence}\n"

        return summary

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["xss", "lfi", "ssti"],
            "requirements": ["requests"],
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Full URL to scan (e.g. https://example.com/page?param=value). Alias: target",
                    },
                    "target": {
                        "type": "string",
                        "description": "Alias for target_url",
                    },
                    "scans": {
                        "type": "array",
                        "description": "Optional scan types: xss, lfi, ssti (default: all)",
                    },
                    "params_to_test": {
                        "type": "array",
                        "description": "Optional: specific URL parameters to test",
                    },
                },
                "required": ["target_url"],
            },
        }

    def _request(self, method: str, url: str) -> Optional[requests.Response]:
        try:
            return requests.request(
                method,
                url,
                headers={"User-Agent": self._user_agent},
                timeout=self._timeout,
                verify=False,
            )
        except requests.RequestException as e:
            logger.warning(f"Request failed: {url} - {e}")
            return None

    @staticmethod
    def _body_hash(resp: requests.Response) -> str:
        return hashlib.sha256(resp.content).hexdigest()

    def _build_param_url(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        query_params[param] = [value]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_xss(
        self, url: str, param: str, baseline_text: str
    ) -> Optional[Dict[str, Any]]:
        canary = "BG_XSS_TEST_" + str(int(urllib.parse.urlparse(url).port or 80))
        payload = f"<script>console.log('{canary}')</script>"
        new_url = self._build_param_url(url, param, payload)

        resp = self._request("GET", new_url)
        if not resp:
            return None

        if payload in resp.text and payload not in baseline_text:
            injected_url = new_url
            return {
                "type": "xss_reflected",
                "parameter": param,
                "url": injected_url,
                "payload": payload,
                "evidence": "Payload reflected in response body (not present in baseline)",
                "severity": "high",
                "confidence": 0.85,
            }
        return None

    def _check_lfi(
        self, url: str, param: str, baseline_text: str
    ) -> Optional[Dict[str, Any]]:
        payloads = [
            ("../../../../etc/passwd", "root:x:0:0:"),
            ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("/etc/passwd", "root:x:0:0:"),
        ]

        for payload, marker in payloads:
            if marker in baseline_text:
                continue

            new_url = self._build_param_url(url, param, payload)
            resp = self._request("GET", new_url)
            if resp and marker in resp.text:
                return {
                    "type": "path_traversal",
                    "parameter": param,
                    "url": new_url,
                    "payload": payload,
                    "evidence": f"Marker '{marker}' found in response but absent from baseline",
                    "severity": "high",
                    "confidence": 0.8,
                }
        return None

    def _check_ssti(self, url: str, param: str, baseline_text: str) -> Optional[Dict[str, Any]]:
        """Require two independent template expressions to evaluate (reduces '49' false positives)."""
        payload_sets = [
            [("{{7*7}}", "49"), ("{{7*'7'}}", "7777777")],
            [("${7*7}", "49"), ("${7*'7'}", "7777777")],
        ]

        for payloads in payload_sets:
            matches = 0
            last_url = url
            for payload, marker in payloads:
                if payload in baseline_text or marker in baseline_text:
                    break

                new_url = self._build_param_url(url, param, payload)
                resp = self._request("GET", new_url)
                if not resp:
                    break

                if marker in resp.text and payload not in resp.text:
                    matches += 1
                    last_url = new_url

            if matches >= 2:
                return {
                    "type": "ssti",
                    "parameter": param,
                    "url": last_url,
                    "payload": payloads[0][0],
                    "evidence": "Multiple template expressions evaluated in response",
                    "severity": "critical",
                    "confidence": 0.9,
                }
        return None

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target_url = resolve_target_url(params)
        scans = params.get("scans", ["xss", "lfi", "ssti"])
        if "headers" in scans:
            scans = [s for s in scans if s != "headers"]
            logger.info("headers scan deprecated; use web_server_scanner instead")
        params_to_test = params.get("params_to_test")

        logger.info(f"Starting Web Vuln scan on {target_url}")

        baseline_resp = self._request("GET", target_url)
        if not baseline_resp:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data={},
                error_message="Could not connect to target",
                metadata={},
            )

        baseline_text = baseline_resp.text
        findings: List[Dict[str, Any]] = []

        parsed = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed.query)

        scan_params = list(query_params.keys())
        if params_to_test:
            scan_params = [p for p in scan_params if p in params_to_test]

        if not scan_params:
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={
                    "target_url": target_url,
                    "vulnerabilities": [],
                    "scanned_params": [],
                    "not_applicable": True,
                    "message": "No URL query parameters available to test",
                    "coverage": {
                        "scanned_params": 0,
                        "untested": True,
                        "reason": "no_query_parameters",
                    },
                },
                metadata={},
            )

        for param in scan_params:
            if "xss" in scans:
                res = self._check_xss(target_url, param, baseline_text)
                if res:
                    findings.append(res)

            if "lfi" in scans:
                res = self._check_lfi(target_url, param, baseline_text)
                if res:
                    findings.append(res)

            if "ssti" in scans:
                res = self._check_ssti(target_url, param, baseline_text)
                if res:
                    findings.append(res)

        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "target_url": target_url,
                "vulnerabilities": findings,
                "scanned_params": scan_params,
                "coverage": {
                    "scanned_params": len(scan_params),
                    "untested": False,
                },
            },
            metadata={},
        )


def create_web_vuln_scanner_adapter(config: Dict[str, Any] = None) -> WebVulnScannerAdapter:
    return WebVulnScannerAdapter(config)
