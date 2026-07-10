from __future__ import annotations

import os
import signal
import subprocess
import time
import shutil
from typing import Dict, List, Literal, Optional, TypedDict

_active_processes: Dict[str, subprocess.Popen] = {}


class ProcessRunSpec(TypedDict, total=False):
    command: str
    args: List[str]
    env: Dict[str, str]
    cwd: Optional[str]
    timeout: float
    task_id: Optional[str]


class ProcessRunResult(TypedDict):
    status: Literal["success", "timeout", "error", "cancelled"]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration: float


def register_process(task_id: str, proc: subprocess.Popen) -> None:
    _active_processes[task_id] = proc


def cancel_process(task_id: str) -> bool:
    proc = _active_processes.pop(task_id, None)
    if not proc:
        return False
    try:
        if os.name == "nt":
            proc.terminate()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    return True


class ProcessRunner:
    """Execute a local process with timeouts, cancellation, and sanitization."""

    def run(self, spec: ProcessRunSpec) -> ProcessRunResult:
        start = time.time()
        command = spec.get("command")
        if not command or not isinstance(command, str):
            raise ValueError("ProcessRunSpec.command must be a non-empty string")

        if not shutil.which(command):
            raise ValueError(f"Command not found: {command}")

        args = spec.get("args", [])
        if args is not None and not isinstance(args, list):
            raise ValueError("ProcessRunSpec.args must be a list of strings")
        args = [str(a) for a in (args or [])]

        env = spec.get("env", {}) or {}
        if not isinstance(env, dict):
            raise ValueError("ProcessRunSpec.env must be a dict[str, str]")

        full_env = os.environ.copy()
        full_env.update(env)

        cwd = spec.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("ProcessRunSpec.cwd must be a string or None")

        timeout = float(spec.get("timeout", 300.0))
        task_id = spec.get("task_id")
        safe_args = self._sanitize_args(args)
        cmd_list = [command] + safe_args

        popen_kwargs: Dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "env": full_env,
            "cwd": cwd,
        }
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd_list, **popen_kwargs)
        if task_id:
            register_process(task_id, proc)

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            duration = time.time() - start
            if task_id:
                _active_processes.pop(task_id, None)
            status: Literal["success", "error"] = "success" if proc.returncode == 0 else "error"
            return ProcessRunResult(
                status=status,
                exit_code=proc.returncode,
                stdout=stdout or "",
                stderr=stderr or "",
                duration=duration,
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            if task_id:
                cancel_process(task_id)
            else:
                proc.kill()
                proc.communicate()
            return ProcessRunResult(
                status="timeout",
                exit_code=None,
                stdout="",
                stderr="Execution timed out",
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - start
            if task_id:
                cancel_process(task_id)
            else:
                try:
                    proc.kill()
                except Exception:
                    pass
            return ProcessRunResult(
                status="error",
                exit_code=None,
                stdout="",
                stderr=str(e),
                duration=duration,
            )

    def _sanitize_args(self, args: List[str]) -> List[str]:
        prohibited = set(";&|`$()><\n\r")
        for a in args:
            if any(ch in a for ch in prohibited):
                raise ValueError(f"Disallowed character in argument: {a!r}")
        return args
