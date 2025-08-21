"""
Passive Recon Adapter for Black Glove Pentest Agent

This adapter performs passive reconnaissance by querying:
- crt.sh for historical certificates and discovered subject names
- Internet Archive Wayback Machine (CDX API) for archived URLs

It aggregates, normalizes, and stores evidence for later analysis.
"""

import time
import json
import re
import socket
from typing import Any, Dict, List, Optional
from urllib import request, parse, error

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus

class PassiveReconAdapter(BaseAdapter):
    """
    Passive Recon adapter combining crt.sh and Wayback Machine lookups.
    """

    # In-memory cross-call rate limiter timestamps keyed by base_url
    _last_call_times: Dict[str, float] = {}

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the passive recon adapter.

        Config options (all optional):
          - timeout: default HTTP timeout (seconds), default 30
          - retries: number of retry attempts on transient failures (default 1)
          - backoff_factor: multiplier for exponential backoff between retries (default 1.5)
          - respect_retry_after: honor Retry-After header when present (default True)
          - crt_sh:
              base_url: default "https://crt.sh/"
              include_subdomains: bool, default True
              timeout: seconds (overrides default per-call)
              max_results: int (cap results), default 200
              rate_limit_rpm: int requests per minute limit (optional)
          - wayback:
              base_url: default "https://web.archive.org/cdx/search/cdx"
              timeout: seconds (overrides default per-call)
              max_results: int (cap results), default 200
              filter_status: str (e.g. "200"), default "200"
              collapse: str (e.g. "digest"), default "digest"
              rate_limit_rpm: int requests per minute limit (optional)
        """
        super().__init__(config)
        self._required_config_fields = []
        self._required_params = ["domain"]
        self.version = "1.0.0"

        # Defaults
        self._defaults = {
            "timeout": 30,
            "retries": 1,
            "backoff_factor": 1.5,
            "respect_retry_after": True,
            "crt_sh": {
                "base_url": "https://crt.sh/",
                "include_subdomains": True,
                "timeout": None,
                "max_results": 200,
                "rate_limit_rpm": None,
            },
            "wayback": {
                "base_url": "https://web.archive.org/cdx/search/cdx",
                "timeout": None,
                "max_results": 200,
                "filter_status": "200",
                "collapse": "digest",
                "rate_limit_rpm": None,
            },
        }

    # ---- Validation ----

    def validate_config(self) -> bool:
        super().validate_config()

        def _is_pos_num(x: Any) -> bool:
            return isinstance(x, (int, float)) and x > 0

        cfg = self.config or {}
        if "timeout" in cfg and not _is_pos_num(cfg["timeout"]):
            raise ValueError("timeout must be a positive number")

        if "retries" in cfg and not (isinstance(cfg["retries"], int) and cfg["retries"] >= 0):
            raise ValueError("retries must be a non-negative integer")

        if "backoff_factor" in cfg and not _is_pos_num(cfg["backoff_factor"]):
            raise ValueError("backoff_factor must be a positive number")

        if "respect_retry_after" in cfg and not isinstance(cfg["respect_retry_after"], bool):
            raise ValueError("respect_retry_after must be boolean")

        crt = cfg.get("crt_sh", {})
        if "timeout" in crt and crt["timeout"] is not None and not _is_pos_num(crt["timeout"]):
            raise ValueError("crt_sh.timeout must be a positive number")
        if "max_results" in crt and not (isinstance(crt["max_results"], int) and crt["max_results"] > 0):
            raise ValueError("crt_sh.max_results must be a positive integer")
        if "include_subdomains" in crt and not isinstance(crt["include_subdomains"], bool):
            raise ValueError("crt_sh.include_subdomains must be boolean")
        if "rate_limit_rpm" in crt and crt["rate_limit_rpm"] is not None:
            if not (isinstance(crt["rate_limit_rpm"], int) and crt["rate_limit_rpm"] > 0):
                raise ValueError("crt_sh.rate_limit_rpm must be a positive integer")

        wb = cfg.get("wayback", {})
        if "timeout" in wb and wb["timeout"] is not None and not _is_pos_num(wb["timeout"]):
            raise ValueError("wayback.timeout must be a positive number")
        if "max_results" in wb and not (isinstance(wb["max_results"], int) and wb["max_results"] > 0):
            raise ValueError("wayback.max_results must be a positive integer")
        if "rate_limit_rpm" in wb and wb["rate_limit_rpm"] is not None:
            if not (isinstance(wb["rate_limit_rpm"], int) and wb["rate_limit_rpm"] > 0):
                raise ValueError("wayback.rate_limit_rpm must be a positive integer")

        return True

    def validate_params(self, params: Dict[str, Any]) -> bool:
        super().validate_params(params)

        domain = params.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain must be a non-empty string")
        if not self._is_valid_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")

        if "max_results" in params:
            if not isinstance(params["max_results"], int) or params["max_results"] <= 0:
                raise ValueError("max_results must be a positive integer")

        return True

    # ---- Core execution ----

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        domain: str = params["domain"].strip()

        # Resolve effective settings
        def _get(path: List[str], default: Any):
            cfg = self.config or {}
            ref = cfg
            for key in path:
                if not isinstance(ref, dict) or key not in ref:
                    return default
                ref = ref[key]
            return ref if ref is not None else default

        timeout_global = _get(["timeout"], self._defaults["timeout"])

        # crt.sh settings
        crt_base = _get(["crt_sh", "base_url"], self._defaults["crt_sh"]["base_url"]).rstrip("/")
        crt_timeout = _get(["crt_sh", "timeout"], self._defaults["crt_sh"]["timeout"]) or timeout_global
        crt_include_sub = _get(
            ["crt_sh", "include_subdomains"], self._defaults["crt_sh"]["include_subdomains"]
        )
        crt_limit = params.get("max_results", None) or _get(
            ["crt_sh", "max_results"], self._defaults["crt_sh"]["max_results"]
        )
        crt_rpm = _get(["crt_sh", "rate_limit_rpm"], self._defaults["crt_sh"]["rate_limit_rpm"])

        # wayback settings
        wb_base = _get(["wayback", "base_url"], self._defaults["wayback"]["base_url"])
        wb_timeout = _get(["wayback", "timeout"], self._defaults["wayback"]["timeout"]) or timeout_global
        wb_limit = params.get("max_results", None) or _get(
            ["wayback", "max_results"], self._defaults["wayback"]["max_results"]
        )
        wb_filter_status = _get(
            ["wayback", "filter_status"], self._defaults["wayback"]["filter_status"]
        )
        wb_collapse = _get(["wayback", "collapse"], self._defaults["wayback"]["collapse"])
        wb_rpm = _get(["wayback", "rate_limit_rpm"], self._defaults["wayback"]["rate_limit_rpm"])

        self.logger.info(
            f"Passive recon for domain={domain} (crt.sh include_subdomains={crt_include_sub}, "
            f"limits: crt={crt_limit}, wayback={wb_limit})"
        )

        # Execute queries
        crt_result: Dict[str, Any] = {}
        wb_result: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        timings: Dict[str, float] = {}

        # crt.sh
        try:
            # rate limit
            self._rate_limit_wait(crt_base, crt_rpm)

            t0 = time.time()
            crt_query = f"%.{domain}" if crt_include_sub else domain
            crt_url = f"{crt_base}/?q={parse.quote(crt_query)}&output=json"
            crt_raw = self._http_get(crt_url, crt_timeout)
            timings["crt_sh_time"] = time.time() - t0

            crt_entries = self._parse_crt_json(crt_raw)
            if crt_limit and len(crt_entries) > crt_limit:
                crt_entries = crt_entries[:crt_limit]

            normalized = []
            for e in crt_entries:
                # name_value may include multiple names separated by newlines
                names = []
                nv = e.get("name_value")
                if isinstance(nv, str):
                    names = list({n.strip() for n in nv.splitlines() if n.strip()})

                normalized.append(
                    {
                        "id": e.get("id") or e.get("entry_timestamp"),
                        "issuer_ca_id": e.get("issuer_ca_id"),
                        "issuer_name": e.get("issuer_name"),
                        "name_value": names,
                        "not_before": e.get("not_before"),
                        "not_after": e.get("not_after"),
                        "serial_number": e.get("serial_number"),
                    }
                )

            crt_result = {
                "certificates": normalized,
                "count": len(normalized),
            }
        except Exception as e:
            errors["crt_sh"] = str(e)
            crt_result = {"certificates": [], "count": 0}

        # Wayback
        try:
            # rate limit
            self._rate_limit_wait(wb_base, wb_rpm)

            t0 = time.time()
            # fields: timestamp, original URL, mime, statuscode, length, digest
            query = {
                "url": f"{domain}/*",
                "output": "json",
                "fl": "timestamp,original,mime,statuscode,length,digest",
                "filter": f"statuscode:{wb_filter_status}" if wb_filter_status else None,
                "collapse": wb_collapse if wb_collapse else None,
                "limit": str(wb_limit) if wb_limit else None,
            }
            # remove None params
            query = {k: v for k, v in query.items() if v is not None}
            wb_url = f"{wb_base}?{parse.urlencode(query)}"
            wb_raw = self._http_get(wb_url, wb_timeout)
            timings["wayback_time"] = time.time() - t0

            wb_entries = self._parse_wayback_json(wb_raw)
            if wb_limit and len(wb_entries) > wb_limit:
                wb_entries = wb_entries[:wb_limit]

            normalized_snaps = []
            for row in wb_entries:
                normalized_snaps.append(
                    {
                        "timestamp": row.get("timestamp"),
                        "url": row.get("original"),
                        "mime": row.get("mime"),
                        "status": row.get("statuscode"),
                        "length": row.get("length"),
                        "digest": row.get("digest"),
                    }
                )

            wb_result = {
                "snapshots": normalized_snaps,
                "count": len(normalized_snaps),
            }
        except Exception as e:
            errors["wayback"] = str(e)
            wb_result = {"snapshots": [], "count": 0}

        # Determine status
        both_empty = crt_result.get("count", 0) == 0 and wb_result.get("count", 0) == 0
        if errors and not both_empty and (crt_result.get("count", 0) > 0 or wb_result.get("count", 0) > 0):
            status = AdapterResultStatus.PARTIAL
        elif both_empty and errors:
            # If both failed, treat as FAILURE (no data), not ERROR (reserved for exceptions in BaseAdapter)
            status = AdapterResultStatus.FAILURE
        else:
            status = AdapterResultStatus.SUCCESS

        # Build data payload
        data = {
            "domain": domain,
            "crt_sh": crt_result,
            "wayback": wb_result,
            "timings": timings,
            "errors": errors,
        }

        # Store evidence
        evidence_filename = f"passive_recon_{domain.replace('.', '_')}_{int(time.time())}.json"
        evidence_path = self._store_evidence(data, evidence_filename)

        return AdapterResult(
            status=status,
            data=data,
            metadata={
                "adapter": self.name,
                "domain": domain,
                "include_subdomains": crt_include_sub,
                "crt_limit": crt_limit,
                "wayback_limit": wb_limit,
                "timestamp": time.time(),
            },
            evidence_path=evidence_path,
        )

    # ---- Helpers ----

    def _rate_limit_wait(self, base_url: str, rpm: Optional[int]) -> None:
        """
        Enforce a simple per-base-url requests-per-minute limit.
        """
        if not rpm:
            return
        min_interval = 60.0 / float(rpm)
        last = PassiveReconAdapter._last_call_times.get(base_url)
        now = time.time()
        if last is not None:
            elapsed = now - last
            if elapsed < min_interval:
                to_sleep = max(0.0, min_interval - elapsed)
                self.logger.debug(f"Rate limiting {base_url}: sleeping {to_sleep:.3f}s")
                time.sleep(to_sleep)
        PassiveReconAdapter._last_call_times[base_url] = time.time()

    def _http_get(self, url: str, timeout: float) -> str:
        """
        HTTP GET with basic retries, exponential backoff, and Retry-After support.
        """
        retries = self.config.get("retries", self._defaults["retries"])
        backoff = self.config.get("backoff_factor", self._defaults["backoff_factor"])
        respect_retry_after = self.config.get("respect_retry_after", self._defaults["respect_retry_after"])

        attempt = 0
        delay = 1.0

        while True:
            req = request.Request(
                url,
                headers={
                    "User-Agent": "BlackGlovePassiveRecon/1.0 (+https://example.invalid)",
                    "Accept": "application/json,text/plain;q=0.8,*/*;q=0.5",
                },
                method="GET",
            )
            self.logger.debug(f"HTTP GET {url} (attempt {attempt + 1})")
            try:
                with request.urlopen(req, timeout=timeout) as resp:
                    charset = resp.headers.get_content_charset() or "utf-8"
                    return resp.read().decode(charset, errors="replace")
            except error.HTTPError as e:
                code = getattr(e, "code", None)
                # Retry on 429 or 5xx
                if (code == 429) or (isinstance(code, int) and 500 <= code < 600):
                    if attempt < retries:
                        retry_after: Optional[float] = None
                        if respect_retry_after:
                            hdrs = getattr(e, "hdrs", None) or {}
                            ra = None
                            try:
                                ra = hdrs.get("Retry-After") if hasattr(hdrs, "get") else None
                            except Exception:
                                ra = None
                            if ra is not None:
                                try:
                                    retry_after = float(ra)
                                except Exception:
                                    retry_after = None
                        sleep_time = retry_after if (retry_after is not None) else delay
                        self.logger.warning(f"HTTPError {code} for {url}, retrying in {sleep_time:.2f}s")
                        time.sleep(max(0.0, sleep_time))
                        attempt += 1
                        delay *= backoff
                        continue
                    raise Exception(f"HTTPError {code} for {url}")
                # Non-retryable 4xx
                raise Exception(f"HTTPError {code} for {url}")
            except error.URLError as e:
                if attempt < retries:
                    self.logger.warning(f"URLError for {url}: {e.reason}, retrying in {delay:.2f}s")
                    time.sleep(max(0.0, delay))
                    attempt += 1
                    delay *= backoff
                    continue
                raise Exception(f"URLError for {url}: {e.reason}")
            except socket.timeout:
                if attempt < retries:
                    self.logger.warning(f"Timeout for {url}, retrying in {delay:.2f}s")
                    time.sleep(max(0.0, delay))
                    attempt += 1
                    delay *= backoff
                    continue
                raise Exception(f"Connection timed out after {timeout} seconds")

    def _parse_crt_json(self, raw: str) -> List[Dict[str, Any]]:
        # crt.sh sometimes returns multiple JSON objects concatenated; handle robustly
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Attempt to repair concatenated objects: }{ -> },{
        repaired = None
        try:
            repaired = f"[{raw.strip()}]"
            repaired = repaired.replace("}\n{", "},{").replace("}{", "},{")
            parsed2 = json.loads(repaired)
            if isinstance(parsed2, list):
                return parsed2
        except Exception:
            # Fallthrough to empty
            pass

        return []

    def _parse_wayback_json(self, raw: str) -> List[Dict[str, Any]]:
        """
        Wayback CDX API returns a JSON array:
          [
            ["timestamp","original","mime","statuscode","length","digest"],
            ["20230101","http://...","text/html","200","1234","XYZ"], ...
          ]
        Convert to list of dicts using header row.
        """
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, list) or not parsed:
                return []
            if not isinstance(parsed[0], list):
                return []

            header = parsed[0]
            results = []
            for row in parsed[1:]:
                if not isinstance(row, list):
                    continue
                item = {}
                for i, key in enumerate(header):
                    if i < len(row):
                        item[str(key)] = row[i]
                results.append(item)
            return results
        except Exception:
            return []

    def _is_valid_domain(self, domain: str) -> bool:
        # Basic FQDN validator (supports punycode, ascii)
        # RFC-compliant enough for our use-case
        if len(domain) > 253:
            return False
        pattern = re.compile(
            r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9\-]{2,63}$"
        )
        return bool(pattern.match(domain))

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update(
            {
                "name": "PassiveReconAdapter",
                "version": self.version,
                "description": "Passive reconnaissance via crt.sh and Wayback Machine",
                "capabilities": base_info["capabilities"]
                + ["certificate_history", "archived_url_discovery", "evidence_storage"],
                "requirements": ["stdlib-urllib", "json"],
                "example_usage": {
                    "domain": "example.com",
                    "max_results": 100,
                },
            }
        )
        return base_info

# Factory function
def create_passive_recon_adapter(config: Dict[str, Any] = None) -> PassiveReconAdapter:
    """
    Factory function to create a Passive Recon adapter instance.

    Args:
        config: Optional configuration dictionary

    Returns:
        PassiveReconAdapter: Configured adapter instance
    """
    if config is None:
        config = {}
    return PassiveReconAdapter(config)
