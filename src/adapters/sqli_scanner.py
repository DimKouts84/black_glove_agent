"""
SQL Injection Scanner Adapter for Black Glove Pentest Agent

SQLMap-lite detection of SQLi vulnerabilities using error-based, boolean-blind,
and time-blind techniques. Safe detection only (no data extraction).
"""

import hashlib
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from .url_params import resolve_target_url

logger = logging.getLogger(__name__)

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

SQLI_SEVERITY = {
    "error_based": ("critical", 0.9),
    "time_blind": ("high", 0.75),
    "boolean_blind": ("medium", 0.6),
}


class SQLiScannerAdapter(BaseAdapter):
    """SQL Injection detection adapter."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "SQLiScannerAdapter"
        self.version = "1.1.0"
        self.description = "SQLMap-lite SQL injection scanner (error, boolean, time)"

        self._timeout = self.config.get("timeout", 10.0)
        self._user_agent = self.config.get(
            "user_agent",
            "Mozilla/5.0 (compatible; BlackGloveScanner/1.0; +https://github.com/black-glove)",
        )

    def validate_params(self, params: Dict[str, Any]) -> None:
        resolve_target_url(params)

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

        summary = f"SQLi Scanner FOUND {len(vulns)} potential issues (checked {scanned_count} params):\n"
        for v in vulns:
            url = v.get("url", "")
            param = v.get("parameter", "")
            payload = v.get("payload", "")
            type_ = v.get("type", "unknown")
            sev = v.get("severity", "medium").upper()
            summary += f"  - [{sev}] {type_} in parameter '{param}' at {url}\n    Payload: {payload}\n"

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
                        "description": "Full URL with query parameters (alias: target)",
                    },
                    "target": {"type": "string", "description": "Alias for target_url"},
                    "techniques": {
                        "type": "array",
                        "description": "Optional: error, boolean, time (default: all)",
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
    def _body_fingerprint(resp: requests.Response) -> str:
        normalized = re.sub(r"\s+", " ", resp.text.strip())
        return hashlib.sha256(f"{resp.status_code}:{normalized}".encode()).hexdigest()

    def _match_sql_error(self, text: str) -> Optional[tuple]:
        for db_type, regexes in SQL_ERRORS.items():
            for pattern in regexes:
                if re.search(pattern, text, re.IGNORECASE):
                    return db_type, pattern
        return None

    def _build_param_url(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        query_params[param] = [value]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _vuln_dict(
        self,
        url: str,
        param: str,
        vuln_type: str,
        payload: str,
        evidence: str,
        **extra: Any,
    ) -> Dict[str, Any]:
        severity, confidence = SQLI_SEVERITY.get(vuln_type, ("medium", 0.5))
        return {
            "type": vuln_type,
            "parameter": param,
            "url": url,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "confidence": confidence,
            **extra,
        }

    def _check_error_based(
        self, url: str, param: str, baseline_resp: requests.Response
    ) -> Optional[Dict[str, Any]]:
        baseline_match = self._match_sql_error(baseline_resp.text)
        payloads = ["'", '"', "')"]

        for char in payloads:
            original_val = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get(
                param, [""]
            )[0]
            new_url = self._build_param_url(url, param, original_val + char)

            resp = self._request("GET", new_url)
            if not resp:
                continue

            match = self._match_sql_error(resp.text)
            if match and not baseline_match:
                db_type, pattern = match
                return self._vuln_dict(
                    new_url,
                    param,
                    "error_based",
                    char,
                    f"SQL error on injection only: {pattern}",
                    database=db_type,
                )
        return None

    def _check_boolean_blind(
        self, url: str, param: str, baseline_resp: requests.Response
    ) -> Optional[Dict[str, Any]]:
        if not baseline_resp:
            return None

        original_val = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get(
            param, [""]
        )[0]
        base_fp = self._body_fingerprint(baseline_resp)

        true_payload = " AND 1=1"
        false_payload = " AND 1=2"

        url_true = self._build_param_url(url, param, original_val + true_payload)
        url_false = self._build_param_url(url, param, original_val + false_payload)

        resp_true = self._request("GET", url_true)
        resp_false = self._request("GET", url_false)

        if not resp_true or not resp_false:
            return None

        true_fp = self._body_fingerprint(resp_true)
        false_fp = self._body_fingerprint(resp_false)

        if true_fp == false_fp:
            return None

        if true_fp == base_fp and false_fp != base_fp:
            return self._vuln_dict(
                url_true,
                param,
                "boolean_blind",
                true_payload,
                "True condition matches baseline; false condition differs (body fingerprint)",
            )

        return None

    def _check_time_blind(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        sleep_sec = 5
        original_val = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get(
            param, [""]
        )[0]

        start = time.time()
        baseline_resp = self._request("GET", url)
        baseline_elapsed = time.time() - start
        if not baseline_resp:
            return None

        payload = f" AND SLEEP({sleep_sec})"
        new_url = self._build_param_url(url, param, original_val + payload)

        start = time.time()
        resp = self._request("GET", new_url)
        elapsed = time.time() - start

        if not resp or elapsed < sleep_sec:
            return None

        if elapsed - baseline_elapsed < sleep_sec - 1:
            return None

        start = time.time()
        confirm_resp = self._request("GET", new_url)
        confirm_elapsed = time.time() - start

        if confirm_resp and confirm_elapsed >= sleep_sec - 1:
            return self._vuln_dict(
                new_url,
                param,
                "time_blind",
                payload,
                f"Confirmed delay: baseline {baseline_elapsed:.2f}s, "
                f"injection {elapsed:.2f}s and {confirm_elapsed:.2f}s",
            )

        return None

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target_url = resolve_target_url(params)
        techniques = params.get("techniques", ["error", "boolean", "time"])
        params_to_test = params.get("params_to_test")

        logger.info(f"Starting SQLi scan on {target_url}")

        parsed = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed.query)

        if not query_params:
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"vulnerabilities": [], "message": "No parameters to test"},
                metadata={},
            )

        baseline_resp = self._request("GET", target_url)
        if not baseline_resp:
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data={},
                error_message="Could not connect to target",
                metadata={},
            )

        findings: List[Dict[str, Any]] = []
        scan_params = list(query_params.keys())
        if params_to_test:
            scan_params = [p for p in scan_params if p in params_to_test]

        for param in scan_params:
            if "error" in techniques:
                res = self._check_error_based(target_url, param, baseline_resp)
                if res:
                    findings.append(res)

            if "boolean" in techniques:
                res = self._check_boolean_blind(target_url, param, baseline_resp)
                if res:
                    findings.append(res)

            if "time" in techniques:
                res = self._check_time_blind(target_url, param)
                if res:
                    findings.append(res)

        logger.info(f"Found {len(findings)} SQL injection indicators")

        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "target_url": target_url,
                "vulnerabilities": findings,
                "scanned_params": scan_params,
            },
            metadata={},
        )


def create_sqli_scanner_adapter(config: Dict[str, Any] = None) -> SQLiScannerAdapter:
    return SQLiScannerAdapter(config)
