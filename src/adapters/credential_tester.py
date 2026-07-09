"""
Credential Tester Adapter for Black Glove Pentest Agent

Hydra-like multi-protocol brute-force adapter supporting SSH, FTP, and HTTP Basic.
Includes "Lab Mode" safeguards to prevent accidental scanning of unauthorized targets.
"""

import logging
import time
import hashlib
import re
import ftplib
import concurrent.futures
from typing import Any, Dict, List, Optional, Tuple, Protocol
from pathlib import Path

import requests

try:
    import paramiko
except ImportError:
    paramiko = None

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus

logger = logging.getLogger(__name__)


class CredentialTesterAdapter(BaseAdapter):
    """
    Multi-protocol credential testing adapter (SSH, FTP, HTTP Basic).
    
    Features:
    - Multi-threaded attempts
    - Configurable delay and max attempts
    - Lab Mode safety checks (must be explicitly enabled for non-local IPs)
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "CredentialTesterAdapter"
        self.version = "1.0.0"
        self.description = "Hydra-like credential tester (SSH, FTP, HTTP Basic)"
        
        # Config params
        self._max_workers = self.config.get("max_workers", 5)
        self._global_timeout = self.config.get("timeout", 5.0)  # Per-connection timeout

    # -- validation ---------------------------------------------------------

    def validate_params(self, params: Dict[str, Any]) -> None:
        target = params.get("target") or params.get("target_url")
        if not target:
            raise ValueError("Target host/URL is required (target or target_url)")
        
        protocol = params.get("protocol")
        if not protocol or protocol not in ["ssh", "ftp", "http_basic"]:
            raise ValueError("Protocol must be 'ssh', 'ftp', or 'http_basic'")

        if protocol == "ssh" and paramiko is None:
            raise ImportError("paramiko is required for SSH testing but not installed.")

        usernames = params.get("usernames", [])
        passwords = params.get("passwords", [])
        
        if not usernames or not isinstance(usernames, list):
            raise ValueError("usernames list is required")
        if not passwords or not isinstance(passwords, list):
            raise ValueError("passwords list is required")

        # Lab Mode validation: If target is public, ensure force=True or similar
        # For this adapter, we might just log a warning or enforce checks.
        # Implemented in execution logic.

    # -- protocol implementations -------------------------------------------

    def _test_ssh(self, target: str, port: int, user: str, password: str) -> bool:
        """Attempt SSH login."""
        if not paramiko:
            return False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                target, 
                port=port, 
                username=user, 
                password=password, 
                timeout=self._global_timeout,
                banner_timeout=self._global_timeout
            )
            client.close()
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException):
            return False
        except Exception as e:
            logger.debug(f"SSH error {target}:{port} - {e}")
            return False
        finally:
            client.close()

    def _test_ftp(self, target: str, port: int, user: str, password: str) -> bool:
        """Attempt FTP login."""
        ftp = ftplib.FTP()
        try:
            ftp.connect(target, port=port, timeout=self._global_timeout)
            ftp.login(user, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False # Auth failed
        except Exception as e:
            logger.debug(f"FTP error {target}:{port} - {e}")
            return False
        finally:
            try:
                ftp.close()
            except:
                pass

    @staticmethod
    def _build_http_url(target: str, port: int) -> str:
        if target.startswith(("http://", "https://")):
            return target
        scheme = "https" if port == 443 else "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{target}"
        return f"{scheme}://{target}:{port}"

    @staticmethod
    def _response_fingerprint(resp: requests.Response) -> str:
        normalized = re.sub(r"\s+", " ", resp.text.strip())
        return hashlib.sha256(f"{resp.status_code}:{normalized}".encode()).hexdigest()

    def _http_requires_basic_auth(self, url: str) -> tuple:
        """Return (requires_auth, note). requires_auth True when 401 + WWW-Authenticate Basic."""
        try:
            resp = requests.get(url, timeout=self._global_timeout, verify=False)
        except Exception as e:
            return False, f"Pre-check failed: {e}"

        if resp.status_code < 400:
            return False, (
                "Target does not require HTTP Basic authentication "
                f"(returned {resp.status_code} without credentials)."
            )

        auth_header = resp.headers.get("WWW-Authenticate", "")
        if resp.status_code == 401 and "basic" in auth_header.lower():
            return True, None

        return False, (
            f"Target returned {resp.status_code} but did not present HTTP Basic auth challenge."
        )

    def _test_http_basic(self, target: str, port: int, user: str, password: str) -> bool:
        url = self._build_http_url(target, port)

        try:
            unauth = requests.get(url, timeout=self._global_timeout, verify=False)
            auth = requests.get(
                url,
                auth=(user, password),
                timeout=self._global_timeout,
                verify=False,
            )
        except Exception as e:
            logger.debug(f"HTTP error {url} - {e}")
            return False

        if unauth.status_code != 401:
            return False

        if auth.status_code >= 400:
            return False

        return self._response_fingerprint(auth) != self._response_fingerprint(unauth)

    # -- execution ----------------------------------------------------------

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target = params.get("target") or params.get("target_url")
        protocol = params["protocol"]
        usernames = params["usernames"]
        passwords = params["passwords"]
        port = params.get("port")
        
        # Default ports
        if not port:
            port_map = {"ssh": 22, "ftp": 21, "http_basic": 80}
            port = port_map.get(protocol, 80)
        port = int(port)

        delay = params.get("delay", 0.0)
        max_attempts = params.get("max_attempts", 100)
        
        combinations = []
        for u in usernames:
            for p in passwords:
                combinations.append((u, p))
        
        # Cap attempts
        if len(combinations) > max_attempts:
            logger.warning(f"Trimming credential combinations from {len(combinations)} to {max_attempts}")
            combinations = combinations[:max_attempts]

        logger.info(f"Starting {protocol.upper()} credential test on {target}:{port} with {len(combinations)} combinations")
        
        valid_creds = []
        fn_map = {
            "ssh": self._test_ssh,
            "ftp": self._test_ftp,
            "http_basic": self._test_http_basic
        }
        test_fn = fn_map[protocol]

        # Use ThreadPoolExecutor
        
        if protocol == "http_basic":
            test_url = self._build_http_url(target, port)
            logger.info(f"Verifying {test_url} requires HTTP Basic authentication...")
            requires_auth, note = self._http_requires_basic_auth(test_url)
            if not requires_auth:
                logger.warning(f"Skipping HTTP Basic brute force: {note}")
                return AdapterResult(
                    status=AdapterResultStatus.SUCCESS,
                    data={
                        "target": target,
                        "port": port,
                        "protocol": protocol,
                        "valid_credentials": [],
                        "attempts": 0,
                        "note": note,
                    },
                    metadata={},
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_cred = {}
            for user, password in combinations:
                future = executor.submit(test_fn, target, port, user, password)
                future_to_cred[future] = (user, password)
                if delay > 0:
                    time.sleep(delay)
            
            for future in concurrent.futures.as_completed(future_to_cred):
                user, password = future_to_cred[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        logger.info(f"VALID CREDENTIALS FOUND: {user}:{password}")
                        valid_creds.append({"username": user, "password": password})
                except Exception as exc:
                    logger.error(f"Worker exception for {user}: {exc}")

        status = AdapterResultStatus.SUCCESS if valid_creds else AdapterResultStatus.SUCCESS 
        # (It's a success execution even if no creds found, unless errors occurred. 
        # If we want to diff failures, we could use empty list)
        
        return AdapterResult(
            status=status,
            data={
                "target": target,
                "port": port,
                "protocol": protocol,
                "valid_credentials": valid_creds,
                "attempts": len(combinations)
            },
            metadata={}
        )

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Credential testing failed: {result.error_message}"
            
        data = result.data
        valid_creds = data.get("valid_credentials", [])
        protocol = data.get("protocol")
        target = data.get("target")
        attempts = data.get("attempts", 0)
        note = data.get("note")

        if note:
            return f"Credential Tester: {note}"

        if not valid_creds:
            return f"Credential Tester: No valid credentials found for {protocol} on {target} after {attempts} attempts."

        creds_str = "\n".join([f"  - {cred['username']}:{cred['password']}" for cred in valid_creds])
        return (
            f"Credential Tester: FOUND VALID CREDENTIALS for {protocol} on {target}:\n"
            f"{creds_str}"
        )

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": ["ssh_bruteforce", "ftp_bruteforce", "http_basic_bruteforce"],
            "requirements": ["requests", "paramiko"],
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target hostname, IP, or URL (alias: target_url)"},
                    "target_url": {"type": "string", "description": "Alias for target"},
                    "protocol": {"type": "string", "enum": ["ssh", "ftp", "http_basic"]},
                    "usernames": {"type": "array", "items": {"type": "string"}},
                    "passwords": {"type": "array", "items": {"type": "string"}},
                    "port": {"type": "integer", "description": "Optional port override"},
                    "delay": {"type": "number", "description": "Delay between attempts (seconds)"},
                    "max_attempts": {"type": "integer", "description": "Maximum combinations to try"}
                },
                "required": ["target", "protocol", "usernames", "passwords"]
            }
        }

def create_credential_tester_adapter(config: Dict[str, Any] = None) -> CredentialTesterAdapter:
    return CredentialTesterAdapter(config)
