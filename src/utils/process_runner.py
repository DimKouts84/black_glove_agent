from __future__ import annotations

import subprocess
import time
import shutil
from typing import List, Dict, Optional, TypedDict, Literal

class ProcessRunSpec(TypedDict, total=False):
    command: str
    args: List[str]
    env: Dict[str, str]
    cwd: Optional[str]
    timeout: float

class ProcessRunResult(TypedDict):
    status: Literal["success", "timeout", "error"]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration: float

class ProcessRunner:
    """
    Execute a local process with timeouts and sanitization.
    """

    def run(self, spec: ProcessRunSpec) -> ProcessRunResult:
        """
        Run a process according to the provided spec.

        Args:
            spec: ProcessRunSpec including command, args, env, cwd, timeout

        Returns:
            ProcessRunResult with status, exit_code, stdout, stderr, duration

        Raises:
            ValueError: If the spec is invalid or arguments fail sanitization.
        """
        start = time.time()
        command = spec.get("command")
        if not command or not isinstance(command, str):
            raise ValueError("ProcessRunSpec.command must be a non-empty string")

        # Check if command exists
        if not shutil.which(command):
             raise ValueError(f"Command not found: {command}")

        args = spec.get("args", [])
        if args is not None and not isinstance(args, list):
            raise ValueError("ProcessRunSpec.args must be a list of strings")
        args = [str(a) for a in (args or [])]

        env = spec.get("env", {}) or {}
        if not isinstance(env, dict):
            raise ValueError("ProcessRunSpec.env must be a dict[str, str]")
        
        # Merge with system environment to ensure tools work correctly
        import os
        full_env = os.environ.copy()
        full_env.update(env)

        cwd = spec.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("ProcessRunSpec.cwd must be a string or None")

        timeout = float(spec.get("timeout", 300.0))

        # Sanitize args defensively
        safe_args = self._sanitize_args(args)

        cmd_list = [command] + safe_args

        try:
            cp = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=full_env,
                cwd=cwd
            )
            duration = time.time() - start
            status: Literal["success", "error"] = "success" if cp.returncode == 0 else "error"
            return ProcessRunResult(
                status=status,
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                duration=duration,
            )
        except subprocess.TimeoutExpired as te:
            duration = time.time() - start
            return ProcessRunResult(
                status="timeout",
                exit_code=None,
                stdout=te.stdout.decode() if isinstance(te.stdout, bytes) else (te.stdout or ""),
                stderr=te.stderr.decode() if isinstance(te.stderr, bytes) else (te.stderr or "Execution timed out"),
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - start
            return ProcessRunResult(
                status="error",
                exit_code=None,
                stdout="",
                stderr=str(e),
                duration=duration,
            )

    def _sanitize_args(self, args: List[str]) -> List[str]:
        """
        Basic sanitization to disallow obvious shell metacharacters.
        
        We execute with shell=False, so this is an extra layer of defense.
        """
        prohibited = set(";&|`$()><\n\r")
        for a in args:
            if any(ch in a for ch in prohibited):
                raise ValueError(f"Disallowed character in argument: {a!r}")
        return args
