"""
Gobuster Adapter for Black Glove Pentest Agent

Executes gobuster as a local process via ProcessRunner and parses stdout into normalized results.
Stores raw text evidence under evidence/gobusteradapter/.
"""

from __future__ import annotations

import re
import time
import shutil
from typing import Any, Dict, List, Optional
from pathlib import Path

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from .url_params import resolve_target_url
from .domain_params import resolve_domain
from utils.process_runner import ProcessRunner

_SAFE_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z0-9][A-Za-z0-9\-]*$")
_SAFE_EXT_RE = re.compile(r"^[A-Za-z0-9\.]+$")
_SAFE_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_SAFE_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9\-]{2,63}$"
)
_SOFT404_ERROR_PATTERN = re.compile(
    r"status code that matches the provided options",
    re.IGNORECASE,
)
_SOFT404_LENGTH_PATTERN = re.compile(r"Length:\s*(\d+)", re.IGNORECASE)

class GobusterAdapter(BaseAdapter):
    """
    Safe, local gobuster execution supporting dir and dns modes.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config or {})
        self._required_config_fields = []  # all optional
        self._required_params = ["mode"]
        self.version = "1.1.0"
        self._runner: ProcessRunner = self.config.get("_runner") or ProcessRunner()
        
        # Determine gobuster executable path
        self._gobuster_path = "gobuster" # Default to system PATH
        
        # Check for bundled binary in bin/gobuster/gobuster.exe
        try:
            root_dir = Path(__file__).parent.parent.parent
            bundled_path = root_dir / "bin" / "gobuster" / "gobuster.exe"
            if bundled_path.exists():
                self._gobuster_path = str(bundled_path)
        except Exception:
            pass
            
        # Determine default wordlist path
        self._default_wordlist = None
        try:
            root_dir = Path(__file__).parent.parent.parent
            bundled_wordlist = root_dir / "bin" / "wordlists" / "common.txt"
            if bundled_wordlist.exists():
                self._default_wordlist = str(bundled_wordlist)
        except Exception:
            pass

        # Defaults
        self._defaults = {
            "timeout": 300.0,
            "default_mode": "dir",
            "wordlist": self._default_wordlist,  # host path to wordlist
            "rate_limit_rpm": None,  # reserved for orchestrator/policy engine
        }

    @staticmethod
    def _project_root() -> Path:
        return Path(__file__).parent.parent.parent

    def _resolve_wordlist_path(self, wordlist: Optional[str]) -> str:
        """Resolve bare filenames and missing paths to bundled defaults."""
        if wordlist and str(wordlist).strip():
            candidate = Path(wordlist).expanduser()
            if candidate.is_file():
                return str(candidate.resolve())

            root_relative = self._project_root() / candidate
            if root_relative.is_file():
                return str(root_relative.resolve())

            bundled = self._project_root() / "bin" / "wordlists" / candidate.name
            if bundled.is_file() and len(candidate.parts) == 1:
                return str(bundled.resolve())

            if candidate.is_absolute() or len(candidate.parts) > 1:
                return str(candidate)

        if self._default_wordlist and Path(self._default_wordlist).is_file():
            return str(Path(self._default_wordlist).resolve())

        raise ValueError(
            "wordlist must be a valid file path; omit wordlist to use the bundled default"
        )

    @staticmethod
    def _parse_soft404_exclude_length(stderr: str) -> Optional[int]:
        if not stderr:
            return None
        match = _SOFT404_LENGTH_PATTERN.search(stderr)
        return int(match.group(1)) if match else None

    @staticmethod
    def _is_soft404_gobuster_error(message: str) -> bool:
        if not message:
            return False
        return bool(_SOFT404_ERROR_PATTERN.search(message))

    @staticmethod
    def _probe_soft404_length(url: str) -> Optional[int]:
        try:
            import requests
            from urllib.parse import urljoin

            probe_url = urljoin(url.rstrip("/") + "/", "black_glove_probe_not_found_xyz123")
            resp = requests.get(probe_url, timeout=10, verify=False, allow_redirects=False)
            if resp.status_code in (404, 403, 200):
                return len(resp.content)
        except Exception:
            pass
        return None

    def _run_process(
        self,
        params: Dict[str, Any],
        wordlist: str,
        mode: str,
        timeout: float,
    ) -> tuple[Dict[str, Any], List[str]]:
        cmd = self._build_command(params=params, wordlist=wordlist, mode=mode)
        run_result = self._runner.run(
            {
                "command": cmd[0],
                "args": cmd[1:],
                "env": {},
                "cwd": None,
                "timeout": timeout,
            }
        )
        return run_result, cmd

    def _finalize_success(
        self,
        run_result: Dict[str, Any],
        params: Dict[str, Any],
        mode: str,
        metadata_extra: Optional[Dict[str, Any]] = None,
    ) -> AdapterResult:
        stdout = run_result.get("stdout", "") or ""
        parsed = self._parse_output(stdout, mode)
        self._filter_entries(parsed, params, mode)
        self._annotate_entries(parsed.get("entries", []), mode)

        safe_id = None
        if mode == "dir":
            safe_id = (params.get("url") or "").replace("/", "_").replace(":", "_").replace(".", "_")
        else:
            safe_id = (params.get("domain") or "").replace(".", "_")
        evidence_filename = f"gobuster_{mode}_{safe_id}_{int(time.time())}.txt"
        evidence_path = self._store_evidence(stdout, evidence_filename)

        metadata = {
            "adapter": self.name,
            "timestamp": time.time(),
            "mode": mode,
            "url": params.get("url"),
            "domain": params.get("domain"),
            "threads": params.get("threads"),
            "extensions": params.get("extensions"),
            "status_codes": params.get("status_codes"),
        }
        if metadata_extra:
            metadata.update(metadata_extra)

        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data=parsed,
            metadata=metadata,
            evidence_path=evidence_path,
        )

    # ---- Validation ----

    def validate_config(self) -> bool:
        super().validate_config()
        cfg = self.config or {}

        if "timeout" in cfg and (not isinstance(cfg["timeout"], (int, float)) or cfg["timeout"] <= 0):
            raise ValueError("timeout must be a positive number")

        if "default_mode" in cfg and cfg["default_mode"] not in ("dir", "dns"):
            raise ValueError("default_mode must be 'dir' or 'dns'")

        if "wordlist" in cfg and cfg["wordlist"] is not None:
            if not isinstance(cfg["wordlist"], str) or not cfg["wordlist"].strip():
                raise ValueError("wordlist must be a non-empty string path or None")

        # Check if gobuster is available
        if self._gobuster_path == "gobuster" and not shutil.which("gobuster"):
             # We don't raise here to allow instantiation, but execution will fail.
             pass

        return True

    def validate_params(self, params: Dict[str, Any]) -> bool:
        super().validate_params(params)

        mode = params.get("mode") or self.config.get("default_mode", self._defaults["default_mode"])
        if mode not in ("dir", "dns"):
            raise ValueError("mode must be 'dir' or 'dns'")

        if mode == "dir":
            if "url" not in params:
                params["url"] = resolve_target_url(params)
        elif mode == "dns":
            if "domain" not in params:
                params["domain"] = resolve_domain(params)

        wordlist = params.get("wordlist") or self.config.get("wordlist") or self._defaults["wordlist"]
        params["wordlist"] = self._resolve_wordlist_path(wordlist)

        if mode == "dir":
            url = params.get("url")
            if not isinstance(url, str) or not _SAFE_URL_RE.match(url.strip()):
                raise ValueError("url must be a valid http(s) URL")
            # Optional extensions
            exts = params.get("extensions")
            if exts is not None:
                if not isinstance(exts, list) or not all(isinstance(x, str) for x in exts):
                    raise ValueError("extensions must be a list of strings")
                for x in exts:
                    if not _SAFE_EXT_RE.match(x):
                        raise ValueError(f"unsafe extension: {x}")
            # Optional status codes
            scs = params.get("status_codes")
            if scs is not None:
                if not isinstance(scs, list) or not all(isinstance(c, int) and 100 <= c <= 599 for c in scs):
                    raise ValueError("status_codes must be a list of valid HTTP integers")
        else:  # dns
            domain = params.get("domain")
            if not isinstance(domain, str) or not _SAFE_DOMAIN_RE.match(domain.strip()):
                raise ValueError("domain must be a valid FQDN")

        threads = params.get("threads")
        if threads is not None and (not isinstance(threads, int) or threads <= 0 or threads > 256):
            raise ValueError("threads must be a positive integer (1..256)")

        extra_flags = params.get("extra_flags")
        if extra_flags is not None:
            if not isinstance(extra_flags, list) or not all(isinstance(x, str) for x in extra_flags):
                raise ValueError("extra_flags must be a list of strings")
            for f in extra_flags:
                if not _SAFE_FLAG_RE.match(f):
                    raise ValueError(f"Unsafe extra flag: {f}")

        return True

    # ---- Core execution ----

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        cfg = self.config or {}
        timeout = float(cfg.get("timeout", self._defaults["timeout"]))

        mode = params.get("mode") or cfg.get("default_mode", self._defaults["default_mode"])
        wordlist = params.get("wordlist") or cfg.get("wordlist") or self._defaults["wordlist"]
        wordlist = self._resolve_wordlist_path(wordlist)

        evidence_dir = "evidence/" + self.name.lower()
        try:
            from pathlib import Path as _P
            _P(evidence_dir).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        run_params = dict(params)
        exclude_lengths: List[int] = [
            int(length) for length in (run_params.get("exclude_lengths") or [])
        ]
        pre_probe_length: Optional[int] = None
        if mode == "dir":
            pre_probe_length = self._probe_soft404_length(params.get("url", "").strip())
            if pre_probe_length is not None and pre_probe_length not in exclude_lengths:
                exclude_lengths.append(pre_probe_length)
        run_params["exclude_lengths"] = exclude_lengths

        run_result, cmd = self._run_process(run_params, wordlist, mode, timeout)

        if run_result["status"] == "timeout":
            return AdapterResult(
                status=AdapterResultStatus.TIMEOUT,
                data=None,
                metadata={"adapter": self.name, "timestamp": time.time(), "command": cmd},
                error_message=run_result.get("stderr") or "Execution timed out",
            )

        stderr = run_result.get("stderr") or ""
        failed = run_result["status"] == "error" or (run_result.get("exit_code") not in (None, 0))

        if failed and mode == "dir" and self._is_soft404_gobuster_error(stderr):
            retry_lengths = list(exclude_lengths)
            parsed_length = self._parse_soft404_exclude_length(stderr)
            if parsed_length is not None and parsed_length not in retry_lengths:
                retry_lengths.append(parsed_length)
            if retry_lengths != exclude_lengths:
                retry_params = dict(params)
                retry_params["exclude_lengths"] = retry_lengths
                run_result, cmd = self._run_process(retry_params, wordlist, mode, timeout)
                exclude_lengths = retry_lengths
                stderr = run_result.get("stderr") or ""
                failed = run_result["status"] == "error" or (
                    run_result.get("exit_code") not in (None, 0)
                )

        if failed:
            if mode == "dir" and self._is_soft404_gobuster_error(stderr):
                excluded = exclude_lengths[0] if exclude_lengths else "unknown"
                message = (
                    "Directory enumeration skipped: SPA catch-all 200 responses; "
                    f"excluded length {excluded} but no distinct paths found"
                )
                return AdapterResult(
                    status=AdapterResultStatus.PARTIAL,
                    data={
                        "stdout": run_result.get("stdout", ""),
                        "stderr": stderr,
                        "exit_code": run_result.get("exit_code"),
                        "mode": mode,
                        "entries": [],
                    },
                    metadata={
                        "adapter": self.name,
                        "timestamp": time.time(),
                        "command": cmd,
                        "soft_404_excluded_length": exclude_lengths[0] if exclude_lengths else None,
                        "warnings": [message],
                    },
                    error_message=message,
                )
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data={
                    "stdout": run_result.get("stdout", ""),
                    "stderr": stderr,
                    "exit_code": run_result.get("exit_code"),
                },
                metadata={"adapter": self.name, "timestamp": time.time(), "command": cmd},
                error_message=stderr or "gobuster execution failed",
            )

        metadata_extra: Dict[str, Any] = {}
        if exclude_lengths:
            metadata_extra["soft_404_excluded_length"] = exclude_lengths[0]
            metadata_extra["warnings"] = [
                f"Excluded catch-all response length {exclude_lengths[0]} for SPA soft-404 handling"
            ]
        return self._finalize_success(run_result, run_params, mode, metadata_extra)

    # ---- Builders/Parsers ----

    def _build_command(self, *, params: Dict[str, Any], wordlist: str, mode: str) -> List[str]:
        extra_flags: List[str] = params.get("extra_flags") or []
        threads: Optional[int] = params.get("threads")

        cmd: List[str] = [self._gobuster_path, mode]

        # common: wordlist
        # For local execution, we just pass the path directly
        cmd += ["-w", wordlist]

        # threads
        if threads:
            cmd += ["-t", str(int(threads))]

        if mode == "dir":
            url = params["url"].strip()
            cmd += ["-u", url]
            # optional extensions
            exts = params.get("extensions") or []
            if exts:
                safe_exts = [x for x in exts if _SAFE_EXT_RE.match(x)]
                if safe_exts:
                    cmd += ["-x", ",".join(safe_exts)]
            # optional status codes to include
            scs = params.get("status_codes") or []
            if scs:
                cmd += ["-s", ",".join(str(int(c)) for c in scs)]
            exclude_lengths = params.get("exclude_lengths") or []
            for length in exclude_lengths:
                cmd += ["--exclude-length", str(int(length))]
        else:  # dns
            domain = params["domain"].strip()
            cmd += ["-d", domain]

        # sanitized extra flags
        for f in extra_flags:
            if _SAFE_FLAG_RE.match(f):
                cmd.append(f)

        return cmd

    def _parse_output(self, stdout: str, mode: str) -> Dict[str, Any]:
        """
        Parse gobuster stdout.

        dir mode lines examples:
          /admin (Status: 301) [Size: 0]
          /images (Status: 200)
        dns mode lines examples:
          Found: admin.example.com
          admin.example.com (A) 192.168.1.100
        """
        lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        result: Dict[str, Any] = {"mode": mode, "entries": []}

        if mode == "dir":
            dir_re = re.compile(
                r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d{3})\)\s*(?:\[Size:\s*(?P<size>\d+)\])?",
                re.IGNORECASE,
            )
            for ln in lines:
                m = dir_re.search(ln)
                if m:
                    entry = {
                        "path": m.group("path"),
                        "status": int(m.group("status")),
                        "size": int(m.group("size")) if m.group("size") else None,
                    }
                    result["entries"].append(entry)
        else:
            # DNS: accept "Found: host" and generic "host (A) ip" formats
            found_re = re.compile(r"^Found:\s*(?P<host>[A-Za-z0-9\.\-]+)", re.IGNORECASE)
            generic_re = re.compile(r"^(?P<host>[A-Za-z0-9\.\-]+)\s+\((?P<rtype>[A-Z]+)\)\s+(?P<data>.+)$")
            for ln in lines:
                m1 = found_re.search(ln)
                if m1:
                    result["entries"].append({"host": m1.group("host")})
                    continue
                m2 = generic_re.search(ln)
                if m2:
                    result["entries"].append(
                        {
                            "host": m2.group("host"),
                            "record_type": m2.group("rtype"),
                            "data": m2.group("data"),
                        }
                    )
        return result

    def _filter_entries(self, parsed: Dict[str, Any], params: Dict[str, Any], mode: str) -> None:
        if mode != "dir":
            return
        status_codes = params.get("status_codes")
        if not status_codes:
            return
        allowed = {int(c) for c in status_codes}
        parsed["entries"] = [
            e for e in parsed.get("entries", [])
            if e.get("status") in allowed
        ]

    def _annotate_entries(self, entries: List[Dict[str, Any]], mode: str) -> None:
        """Add severity hints based on path and HTTP status."""
        critical_paths = ["/.env", "/.git", "/config", "/backup"]
        for entry in entries:
            if mode != "dir":
                entry["severity"] = "info"
                continue
            path = (entry.get("path") or "").lower()
            status = entry.get("status")
            if status == 200 and any(c in path for c in critical_paths):
                entry["severity"] = "critical"
            elif status == 200:
                entry["severity"] = "high"
            elif status in (401, 403):
                entry["severity"] = "medium"
            elif status in (301, 302, 307):
                entry["severity"] = "low"
            else:
                entry["severity"] = "medium"

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status == AdapterResultStatus.PARTIAL:
            return result.error_message or "Gobuster directory enumeration skipped due to SPA soft-404 responses."
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Gobuster scan failed: {result.error_message}"
            
        data = result.data
        if not data or not isinstance(data, dict) or "entries" not in data:
            return "Gobuster found no results."
            
        findings = data.get("entries", [])
        mode = data.get("mode")
        
        if not findings:
            return "Gobuster completed but found no entries."
            
        if mode == "dir":
            summary = f"Gobuster directory scan found {len(findings)} paths:\n"
            for f in findings[:20]: # Limit to top 20 to avoid flooding
                path = f.get("path", "")
                status = f.get("status", "")
                summary += f"  - {path} (Status: {status})\n"
            if len(findings) > 20:
                summary += f"  ... and {len(findings) - 20} more."
            return summary
            
        elif mode == "dns":
            summary = f"Gobuster DNS scan found {len(findings)} subdomains:\n"
            for f in findings[:20]:
                host = f.get("host", "")
                # DNS entries can have 'data' (IP) or just 'host'
                ip_data = f.get("data", "")
                if ip_data:
                    summary += f"  - {host} -> {ip_data}\n"
                else:
                    summary += f"  - {host}\n"
            if len(findings) > 20:
                summary += f"  ... and {len(findings) - 20} more."
            return summary
            
        return f"Gobuster found {len(findings)} items in {mode} mode."

    # ---- Info ----

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update(
            {
                "name": "GobusterAdapter",
                "version": self.version,
                "description": "Local gobuster execution for directory and DNS enumeration",
                "capabilities": base_info["capabilities"]
                + ["dir_enum", "dns_enum", "stdout_parsing", "evidence_storage"],
                "requirements": ["gobuster"],
                "example_usage": {
                    "dir": {"mode": "dir", "url": "http://example.com", "wordlist": "/path/to/wordlist.txt", "threads": 10},
                    "dns": {"mode": "dns", "domain": "example.com", "wordlist": "/path/to/subdomains.txt", "threads": 50},
                },
            }
        )
        return base_info

# Factory
def create_gobuster_adapter(config: Dict[str, Any] = None) -> GobusterAdapter:
    if config is None:
        config = {}
    return GobusterAdapter(config)
