"""
Nmap Adapter for Black Glove Pentest Agent

Executes nmap as a local process via ProcessRunner and parses XML output into a normalized result.
Stores raw XML evidence under evidence/nmapadapter/.
"""

from __future__ import annotations

import re
import time
import shutil
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from xml.etree import ElementTree as ET

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from utils.process_runner import ProcessRunner

import socket

_SAFE_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z0-9][A-Za-z0-9\-]*$")
_SAFE_SCRIPT_RE = re.compile(r"^[A-Za-z0-9_\-\.]+$")
_PORTS_RE = re.compile(r"^[0-9,\-]+$")  # e.g., 80,443 or 1-1024
_TARGET_SAFE_RE = re.compile(r"^[A-Za-z0-9\.\-:]+$")  # basic IP/hostname/IPv6 literal

def resolve_host(target, retries=2):
    """Resolve hostname with retry mechanism."""
    for i in range(retries + 1):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            if i < retries:
                time.sleep(1)
    return None

class NmapAdapter(BaseAdapter):
    """
    Safe, local nmap execution with XML parsing and normalized results.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config or {})
        self._required_config_fields = []  # optional config entirely
        self._required_params = ["target"]
        self.version = "1.1.0"
        # Dependency injection for tests
        self._runner: ProcessRunner = self.config.get("_runner") or ProcessRunner()
        
        # Determine nmap executable path
        self._nmap_path = "nmap" # Default to system PATH
        
        # Check for bundled binary in bin/nmap/nmap.exe
        # We assume the project root is 3 levels up from this file (src/adapters/nmap.py)
        # Adjust based on actual structure: src/adapters/nmap.py -> src/adapters -> src -> root
        try:
            root_dir = Path(__file__).parent.parent.parent
            bundled_path = root_dir / "bin" / "nmap" / "nmap.exe"
            if bundled_path.exists():
                self._nmap_path = str(bundled_path)
        except Exception:
            pass

        # Defaults
        self._defaults = {
            "timeout": 300.0,
            "default_flags": ["-Pn", "-sV", "-T3"],
            "rate_limit_rpm": None,  # reserved (handled by orchestrator/policy engine normally)
        }

    # ---- Validation ----

    def validate_config(self) -> bool:
        super().validate_config()

        cfg = self.config or {}
        if "timeout" in cfg:
            if not isinstance(cfg["timeout"], (int, float)) or float(cfg["timeout"]) <= 0:
                raise ValueError("timeout must be a positive number")
        
        if "default_flags" in cfg:
            if not isinstance(cfg["default_flags"], list) or not all(isinstance(x, str) for x in cfg["default_flags"]):
                raise ValueError("default_flags must be a list of strings")
            # sanitize flags
            for f in cfg["default_flags"]:
                if not _SAFE_FLAG_RE.match(f):
                    raise ValueError(f"Unsafe default flag: {f}")
        if "rate_limit_rpm" in cfg and cfg["rate_limit_rpm"] is not None:
            if not isinstance(cfg["rate_limit_rpm"], int) or cfg["rate_limit_rpm"] <= 0:
                raise ValueError("rate_limit_rpm must be a positive integer or None")

        # Check if nmap is available
        if not shutil.which("nmap"):
             # We don't raise here to allow instantiation, but execution will fail. 
             # Or we could warn. For now, we'll let execution fail if not found.
             pass

        return True

    def validate_params(self, params: Dict[str, Any]) -> bool:
        super().validate_params(params)
        target = params.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")
        
        # More permissive validation for domain names
        target_stripped = target.strip()
        if not _TARGET_SAFE_RE.match(target_stripped):
            # Allow valid domain names that might not match the strict regex
            if '.' in target_stripped and not target_stripped.startswith('.') and not target_stripped.endswith('.'):
                # This looks like a valid domain, let it pass
                pass
            else:
                raise ValueError("target contains invalid characters")

        ports = params.get("ports")
        if ports is not None:
            if not isinstance(ports, str) or not _PORTS_RE.match(ports):
                raise ValueError("ports must be a string containing digits, commas, and hyphens only")

        scripts = params.get("scripts")
        if scripts is not None:
            if not isinstance(scripts, list) or not all(isinstance(s, str) for s in scripts):
                raise ValueError("scripts must be a list of strings")
            for s in scripts:
                if not _SAFE_SCRIPT_RE.match(s):
                    raise ValueError(f"unsafe script name: {s}")

        extra_flags = params.get("extra_flags")
        if extra_flags is not None:
            if not isinstance(extra_flags, list) or not all(isinstance(x, str) for x in extra_flags):
                raise ValueError("extra_flags must be a list of strings")
            for f in extra_flags:
                if not _SAFE_FLAG_RE.match(f):
                    raise ValueError(f"Unsafe extra flag: {f}")

        if "output_xml" in params and params["output_xml"] is not True:
            # This adapter always uses -oX - for safety
            raise ValueError("output_xml must be True (adapter always uses XML to stdout)")

        return True

    # ---- Core execution ----

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        # Check if nmap is installed before attempting execution
        # Use self._nmap_path which might be the bundled one
        nmap_cmd = self._nmap_path
        
        # If it's just "nmap", check PATH. If it's a path, check existence.
        if nmap_cmd == "nmap":
             if not shutil.which("nmap"):
                return AdapterResult(
                    status=AdapterResultStatus.FAILURE,
                    data=None,
                    error_message="Nmap executable not found. Please install nmap or place portable nmap in bin/nmap/."
                )
        elif not Path(nmap_cmd).exists():
             return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data=None,
                error_message=f"Bundled Nmap not found at {nmap_cmd}"
            )

        # Effective config
        cfg = self.config or {}
        timeout = float(cfg.get("timeout", self._defaults["timeout"]))
        default_flags: List[str] = cfg.get("default_flags", self._defaults["default_flags"]) or []

        # Validate and resolve target
        target = params["target"].strip()
        resolved_target = resolve_host(target)
        if not resolved_target and not re.match(r'^\d+\.\d+\.\d+\.\d+', target):  # Not an IP address
            # Try to resolve the target - if it fails, let nmap handle it (might be a valid nmap target format)
            pass  # Let nmap deal with it directly

        # Build command
        cmd = self._build_command(
            params={
                "target": target,
                "ports": params.get("ports"),
                "scripts": params.get("scripts"),
                "extra_flags": params.get("extra_flags"),
                "output_xml": True,
            },
            cfg={
                "default_flags": default_flags,
            },
        )

        # Prepare evidence directory
        evidence_dir = "evidence/" + self.name.lower()
        try:
            from pathlib import Path as _P
            _P(evidence_dir).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # Execute process
        # cmd[0] is 'nmap', but ProcessRunner expects command and args separately
        # We need to use the resolved nmap_cmd
        run_result = self._runner.run(
            {
                "command": nmap_cmd,
                "args": cmd[1:], # skip 'nmap' placeholder from _build_command
                "env": {},
                "cwd": None,
                "timeout": timeout,
            }
        )

        # Map status
        if run_result["status"] == "timeout":
            return AdapterResult(
                status=AdapterResultStatus.TIMEOUT,
                data=None,
                metadata={
                    "adapter": self.name,
                    "timestamp": time.time(),
                    "command": cmd,
                },
                error_message=run_result.get("stderr") or "Execution timed out",
            )

        if run_result["status"] == "error" or (run_result.get("exit_code") not in (None, 0)):
            return AdapterResult(
                status=AdapterResultStatus.FAILURE,
                data={
                    "stdout": run_result.get("stdout", ""),
                    "stderr": run_result.get("stderr", ""),
                    "exit_code": run_result.get("exit_code"),
                },
                metadata={
                    "adapter": self.name,
                    "timestamp": time.time(),
                    "command": cmd,
                },
                error_message=run_result.get("stderr") or "nmap execution failed",
            )

        xml_text = run_result.get("stdout", "") or ""
        parsed = self._parse_xml(xml_text)

        # Evidence
        safe_target = params["target"].replace("/", "_").replace(":", "_").replace(".", "_")
        evidence_filename = f"nmap_{safe_target}_{int(time.time())}.xml"
        evidence_path = self._store_evidence(xml_text, evidence_filename)

        return AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data=parsed,
            metadata={
                "adapter": self.name,
                "timestamp": time.time(),
                "target": params["target"],
                "ports": params.get("ports"),
                "scripts": params.get("scripts"),
                "flags": default_flags + (params.get("extra_flags") or []),
            },
            evidence_path=evidence_path,
        )

    # ---- Builders/Parsers ----

    def _build_command(self, params: Dict[str, Any], cfg: Dict[str, Any]) -> List[str]:
        target: str = params["target"]
        ports: Optional[str] = params.get("ports")
        scripts: Optional[List[str]] = params.get("scripts")
        extra_flags: List[str] = params.get("extra_flags") or []
        default_flags: List[str] = cfg.get("default_flags", []) or []

        cmd: List[str] = ["nmap", "-oX", "-"]

        # default flags first
        for f in default_flags:
            if _SAFE_FLAG_RE.match(f):
                cmd.append(f)

        # sanitized extra flags
        for f in extra_flags:
            if _SAFE_FLAG_RE.match(f):
                cmd.append(f)

        if ports:
            cmd += ["-p", ports]

        if scripts:
            safe_scripts = [s for s in scripts if _SAFE_SCRIPT_RE.match(s)]
            if safe_scripts:
                cmd += ["--script", ",".join(safe_scripts)]

        cmd.append(target)
        return cmd

    def _parse_xml(self, xml_text: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "hosts": [],
            "summary": {"up": 0, "down": 0, "open_ports": 0},
        }
        if not xml_text.strip():
            return result

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            # return empty with no exception
            return result

        # runstats summary if present
        hosts_summary = root.find(".//runstats/hosts")
        if hosts_summary is not None:
            up = int(hosts_summary.get("up", "0") or "0")
            down = int(hosts_summary.get("down", "0") or "0")
            result["summary"]["up"] = up
            result["summary"]["down"] = down

        # hosts
        open_ports_total = 0
        for h in root.findall(".//host"):
            host_state = (h.find("status").get("state") if (h.find("status") is not None) else None) or ""
            addr_node = h.find("address")
            address = addr_node.get("addr") if addr_node is not None else None

            hostname = None
            hn_parent = h.find("hostnames")
            if hn_parent is not None:
                hn = hn_parent.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            ports_list: List[Dict[str, str]] = []
            ports_parent = h.find("ports")
            if ports_parent is not None:
                for p in ports_parent.findall("port"):
                    portid = p.get("portid")
                    state_node = p.find("state")
                    serv_node = p.find("service")
                    state = state_node.get("state") if state_node is not None else ""
                    service = serv_node.get("name") if serv_node is not None else None
                    if state == "open":
                        ports_list.append(
                            {
                                "port": portid or "",
                                "state": state,
                                "service": service or "",
                            }
                        )
                        open_ports_total += 1

            host_entry = {"address": address or "", "hostname": hostname, "ports": ports_list, "state": host_state}
            result["hosts"].append(host_entry)

        # if runstats wasn't present, derive up/down counts
        if result["summary"]["up"] == 0 and result["summary"]["down"] == 0 and result["hosts"]:
            ups = sum(1 for h in result["hosts"] if (h.get("state") == "up"))
            downs = sum(1 for h in result["hosts"] if (h.get("state") == "down"))
            result["summary"]["up"] = ups
            result["summary"]["down"] = downs

        result["summary"]["open_ports"] = open_ports_total
        return result

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Nmap scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "Nmap scan returned no data."
            
        hosts_up = 0
        total_open_ports = 0
        summary_lines = []
        
        # The _parse_xml method returns a dictionary with 'hosts' and 'summary' keys.
        hosts = data.get("hosts", [])
        
        for host in hosts:
            if not isinstance(host, dict): continue
            
            addr = host.get("address", "unknown")
            # The _parse_xml method does not return 'hostnames' as a list directly in the host dict,
            # but rather a single 'hostname' string. Let's adapt.
            hostname = host.get("hostname")
            hostname_str = f" ({hostname})" if hostname else ""
            
            ports = host.get("ports", [])
            open_ports = [p for p in ports if p.get("state") == "open"]
            
            if open_ports:
                hosts_up += 1
                total_open_ports += len(open_ports)
                summary_lines.append(f"Host: {addr}{hostname_str}")
                for p in open_ports:
                    port_id = p.get("port") # Changed from 'portid' to 'port' based on _parse_xml output
                    service = p.get("service", "unknown") # Changed from p.get("service", {}).get("name", "unknown")
                    # _parse_xml does not extract product/version, so simplify service_desc
                    
                    service_desc = f"{service}"
                    
                    summary_lines.append(f"  - Port {port_id}/tcp: {service_desc}")
            else:
                # Host up but no open ports?
                if host.get("state") == "up": # Changed from host.get("status") to host.get("state")
                    hosts_up += 1
                    summary_lines.append(f"Host: {addr}{hostname_str} is UP but no open ports found.")
        
        if not summary_lines:
             # Check for overall summary from _parse_xml
             summary = data.get("summary", {})
             if summary.get("up", 0) > 0 and summary.get("open_ports", 0) == 0:
                 return f"Nmap completed. {summary['up']} hosts were up, but no open ports were found."
             return "Nmap completed but found no live hosts or open ports."
             
        header = f"Nmap Scan Results: {hosts_up} hosts up, {total_open_ports} open ports."
        return header + "\n" + "\n".join(summary_lines)

    # ---- Info ----

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        
        # Check availability (system or bundled)
        is_installed = bool(shutil.which("nmap")) or Path(self._nmap_path).exists()
        status_msg = "" if is_installed else " [WARNING: nmap executable not found on system or in bin/nmap/]"

        base_info.update(
            {
                "name": "NmapAdapter",
                "version": self.version,
                "description": f"Local nmap execution for network scanning. Use for IP addresses or hostnames.{status_msg}",
                "capabilities": base_info["capabilities"]
                + ["network_scan", "service_detection", "xml_parsing", "evidence_storage"],
                "requirements": ["nmap"],
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The target IP address, hostname, or CIDR range to scan (e.g., '192.168.1.1', 'example.com', '192.168.1.0/24')"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Optional: Port range to scan (e.g., '1-1024', '22,80,443')"
                        },
                        "extra_flags": {
                            "type": "array",
                            "description": "Optional: Additional nmap flags (e.g., ['-Pn', '-sV'])"
                        }
                    },
                    "required": ["target"]
                },
                "example_usage": {
                    "target": "192.168.1.1",
                    "ports": "1-1024",
                    "extra_flags": ["-Pn", "-sV", "-T3"],
                },
            }
        )
        return base_info

# Factory
def create_nmap_adapter(config: Dict[str, Any] = None) -> NmapAdapter:
    if config is None:
        config = {}
    return NmapAdapter(config)
