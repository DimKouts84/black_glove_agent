"""
SQL Injection Scanner Adapter for Black Glove Pentest Agent

SQLMap-lite detection of SQLi vulnerabilities using error-based, boolean-blind, 
and time-blind techniques. Safe detection only (no data extraction).
"""

import logging
import time
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus

logger = logging.getLogger(__name__)

# Common SQL Error patterns
# Based on SQLMap's xml error patterns (simplified)
SQL_ERRORS = {
    "MySQL": [
        r"SQL syntax",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
    ],
    "Microsoft SQL Server": [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
    ],
    "Microsoft Access": [
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
    ],
    "Oracle": [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_.*",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
    ],
}

class SQLiScannerAdapter(BaseAdapter):
    """
    SQL Injection detection adapter.
    
    Implements:
    1. Error-based detection
    2. Boolean-based blind detection
    3. Time-based blind detection
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "SQLiScannerAdapter"
        self.version = "1.0.0"
        self.description = "SQLMap-lite SQL injection scanner (error, boolean, time)"
        
        self._timeout = self.config.get("timeout", 10.0)
        self._user_agent = self.config.get(
			"user_agent", 
			"Mozilla/5.0 (compatible; BlackGloveScanner/1.0; +https://github.com/black-glove)"
		)

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"SQLi scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No SQLi scan data."
            
        vulns = data.get("vulnerabilities", [])
        scanned_count = len(data.get("scanned_params", []))
        
        if not vulns:
            return f"SQLi Scanner checked {scanned_count} parameters and found NO vulnerabilities."
            
        summary = f"SQLi Scanner FOUND {len(vulns)} vulnerabilities (checked {scanned_count} params):\n"
        for v in vulns:
            url = v.get("url", "")
            param = v.get("parameter", "")
            payload = v.get("payload", "")
            type_ = v.get("type", "unknown")
            summary += f"  - [CRITICAL] {type_} in parameter '{param}' at {url}\n    Payload: {payload}\n"
            
        return summary

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["error_based", "boolean_blind", "time_blind"],
            "requirements": ["requests"],
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Full URL with query parameters to test (e.g., 'https://example.com/page?id=1')"
                    },
                    "techniques": {
                        "type": "array",
                        "description": "Optional: error, boolean, time (default: all)"
                    }
                },
                "required": ["target_url"]
            }
        }

    def validate_params(self, params: Dict[str, Any]) -> None:
        if "target_url" not in params or not params["target_url"]:
            raise ValueError("target_url is required")
        
        # Simple URL validation
        parsed = urllib.parse.urlparse(params["target_url"])
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid target_url format (must include scheme and host)")

    def _request(self, method: str, url: str, params: Dict = None, data: Dict = None) -> requests.Response:
        """Helper to make requests with consistent config."""
        try:
            return requests.request(
                method,
                url,
                params=params,
                data=data,
                headers={"User-Agent": self._user_agent},
                timeout=self._timeout,
                verify=False # Often scanning weird self-signed targets
            )
        except requests.RequestException as e:
            logger.warning(f"Request failed: {url} - {e}")
            return None

    def _check_error_based(self, url: str, param: str, baseline_resp: requests.Response) -> Optional[Dict[str, Any]]:
        """Inject generic error triggers and check for DB errors."""
        # Payloads that often cause syntax errors
        payloads = ["'", '"', "')"]
        
        for char in payloads:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Inject into the specific parameter
            # parse_qs returns lists, so we take the first one usually
            original_val = query_params.get(param, [""])[0]
            query_params[param] = [original_val + char]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            
            logger.debug(f"Testing URL: {new_url}")
            
            resp = self._request("GET", new_url)
            if not resp:
                continue

            # Check response body for error strings
            for db_type, regexes in SQL_ERRORS.items():
                for pattern in regexes:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        logger.debug(f"Matched SQL error pattern: {pattern}")
                        return {
                            "type": "error_based",
                            "parameter": param,
                            "payload": char,
                            "database": db_type,
                            "evidence": f"Found error pattern: {pattern}"
                        }
        return None

    def _check_boolean_blind(self, url: str, param: str, baseline_resp: requests.Response) -> Optional[Dict[str, Any]]:
        """
        Check for boolean blind SQLi.
        Logic: 
        1. Inject AND 1=1 (True) -> Should match baseline
        2. Inject AND 1=2 (False) -> Should differ from baseline
        """
        if not baseline_resp:
            return None
            
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        original_val = query_params.get(param, [""])[0]

        # Simplified payloads (generic)
        true_payload = " AND 1=1"
        false_payload = " AND 1=2"
        
        # Test True condition
        query_params[param] = [original_val + true_payload]
        url_true = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_params, doseq=True)))
        resp_true = self._request("GET", url_true)
        
        # Test False condition
        query_params[param] = [original_val + false_payload]
        url_false = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_params, doseq=True)))
        resp_false = self._request("GET", url_false)
        
        if not resp_true or not resp_false:
            return None

        # Compare logic
        # 1. True response should look like baseline (status code & approx content length)
        # 2. False response should look different (status code or content length)
        
        # Similarity check (simple length comparison for now)
        base_len = len(baseline_resp.content)
        true_len = len(resp_true.content)
        false_len = len(resp_false.content)
        
        # Heuristic: True is within 5% of Baseline, False is significantly different?
        # Better: True == Baseline (mostly), False != True.
        
        # If True and False are identical, injection failed or not Boolean blind.
        if true_len == false_len:
            return None

        # If True is roughly same as Baseline AND False is consistently different
        len_diff_true = abs(base_len - true_len)
        len_diff_false = abs(base_len - false_len)
        
        # Tolerance: 20 bytes or 1% ?
        # Let's say if True is closer to Base than False is
        if len_diff_true < len_diff_false and len_diff_false > 50: # Arbitrary threshold of 50 bytes diff
             return {
                "type": "boolean_blind",
                "parameter": param,
                "payloads": {"true": true_payload, "false": false_payload},
                "evidence": f"True len: {true_len}, False len: {false_len}, Base len: {base_len}"
            }
        
        return None

    def _check_time_blind(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        """
        Check for time-based blind SQLi using SLEEP()
        """
        # MySQL/PostgreSQL generic sleep
        # Testing just generic SLEEP(5) for now.
        # Ideally we'd try WAITFOR DELAY, pg_sleep, etc.
        
        sleep_sec = 5
        payload = f" AND SLEEP({sleep_sec})" 
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        original_val = query_params.get(param, [""])[0]
        
        query_params[param] = [original_val + payload]
        new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_params, doseq=True)))
        
        start_time = time.time()
        resp = self._request("GET", new_url)
        elapsed = time.time() - start_time
        
        if resp and elapsed >= sleep_sec:
            # Confirm it wasn't just a slow request? 
            # Ideally retry, but for this lightweight scanner, we flag it.
            return {
                "type": "time_blind",
                "parameter": param,
                "payload": payload,
                "evidence": f"Request took {elapsed:.2f}s with sleep({sleep_sec})"
            }
        return None

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target_url = params["target_url"]
        techniques = params.get("techniques", ["error", "boolean", "time"])
        params_to_test = params.get("params_to_test") # Optional list of param names

        logger.info(f"Starting SQLi scan on {target_url}")
        
        # 1. Parse URL to get parameters
        parsed = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params:
            logger.info("No parameters found in URL to fuzz.")
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"vulnerabilities": [], "message": "No parameters to test"},
                metadata={}
            )

        # Baseline request
        baseline_resp = self._request("GET", target_url)
        if not baseline_resp:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data={},
                error_message="Could not connect to target",
                metadata={}
            )

        findings = []
        
        # Determine params to scan
        scan_params = list(query_params.keys())
        if params_to_test:
            scan_params = [p for p in scan_params if p in params_to_test]

        for param in scan_params:
            # Error-based
            if "error" in techniques:
                res = self._check_error_based(target_url, param, baseline_resp)
                if res:
                    findings.append(res)
                    continue # Found one type, maybe skip others for this param to save time? 
                             # Or continue to find all types? Let's continue.
            
            # Boolean-blind
            if "boolean" in techniques:
                res = self._check_boolean_blind(target_url, param, baseline_resp)
                if res:
                    findings.append(res)
            
            # Time-blind
            if "time" in techniques:
                res = self._check_time_blind(target_url, param)
                if res:
                    findings.append(res)

        logger.info(f"Found {len(findings)} SQL injection vulnerabilities")

        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "target_url": target_url,
                "vulnerabilities": findings,
                "scanned_params": scan_params
            },
            metadata={}
        )

def create_sqli_scanner_adapter(config: Dict[str, Any] = None) -> SQLiScannerAdapter:
    return SQLiScannerAdapter(config)
