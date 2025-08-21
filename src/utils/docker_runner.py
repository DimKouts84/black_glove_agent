from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Literal

try:
    # Lazy-initialize actual client in _run_with_sdk to ease mocking
    import docker  # type: ignore
    _DOCKER_AVAILABLE = True
except Exception:
    docker = None  # type: ignore
    _DOCKER_AVAILABLE = False


class DockerVolume(TypedDict):
    host_path: str
    container_path: str
    mode: Literal["ro", "rw"]


class DockerRunSpec(TypedDict, total=False):
    image: str
    args: List[str]
    env: Dict[str, str]
    volumes: List[DockerVolume]
    network: Optional[str]           # e.g. "host" (Linux), None (default bridge)
    workdir: Optional[str]
    timeout: float


class DockerRunResult(TypedDict):
    status: Literal["success", "timeout", "error"]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration: float


class DockerRunner:
    """
    Execute a containerized tool with SDK+CLI fallback, timeouts, volumes, network, and sanitization.

    Notes:
    - Prefers Docker SDK when available; otherwise falls back to 'docker' CLI via subprocess.
    - Enforces a hard timeout. On timeout, attempts to stop/remove the container and returns status 'timeout'.
    - Args are sanitized to disallow shell metacharacters. CLI execution uses shell=False.
    - Designed for unit testing via monkeypatching 'docker' and 'subprocess'.
    """

    def __init__(self, prefer_sdk: bool = True) -> None:
        self.prefer_sdk = prefer_sdk

    def run(self, spec: DockerRunSpec) -> DockerRunResult:
        """
        Run a container according to the provided spec.

        Args:
            spec: DockerRunSpec including image, args, env, volumes, network, workdir, timeout

        Returns:
            DockerRunResult with status, exit_code, stdout, stderr, duration

        Raises:
            ValueError: If the spec is invalid or arguments fail sanitization.
        """
        start = time.time()
        image = spec.get("image")
        if not image or not isinstance(image, str):
            raise ValueError("DockerRunSpec.image must be a non-empty string")

        args = spec.get("args", [])
        if args is not None and not isinstance(args, list):
            raise ValueError("DockerRunSpec.args must be a list of strings")
        args = [str(a) for a in (args or [])]

        env = spec.get("env", {}) or {}
        if not isinstance(env, dict):
            raise ValueError("DockerRunSpec.env must be a dict[str, str]")

        volumes = spec.get("volumes", []) or []
        if not isinstance(volumes, list):
            raise ValueError("DockerRunSpec.volumes must be a list[DockerVolume]")

        network = spec.get("network")
        if network is not None and not isinstance(network, str):
            raise ValueError("DockerRunSpec.network must be a string or None")

        workdir = spec.get("workdir")
        if workdir is not None and not isinstance(workdir, str):
            raise ValueError("DockerRunSpec.workdir must be a string or None")

        timeout = float(spec.get("timeout", 300.0))

        # Sanitize args defensively (even though shell=False)
        safe_args = self._sanitize_args(args)

        try:
            if self.prefer_sdk and _DOCKER_AVAILABLE:
                result = self._run_with_sdk(
                    image=image,
                    args=safe_args,
                    env=env,
                    volumes=volumes,
                    network=network,
                    workdir=workdir,
                    timeout=timeout,
                )
            else:
                result = self._run_with_cli(
                    image=image,
                    args=safe_args,
                    env=env,
                    volumes=volumes,
                    network=network,
                    workdir=workdir,
                    timeout=timeout,
                )
        except TimeoutError:
            duration = time.time() - start
            return DockerRunResult(
                status="timeout",
                exit_code=None,
                stdout="",
                stderr="Execution timed out",
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - start
            return DockerRunResult(
                status="error",
                exit_code=None,
                stdout="",
                stderr=str(e),
                duration=duration,
            )

        # Normalize duration (prefer result's duration if provided)
        if "duration" not in result or result["duration"] is None:
            result["duration"] = time.time() - start
        return result

    def _sanitize_args(self, args: List[str]) -> List[str]:
        """
        Basic sanitization to disallow obvious shell metacharacters.

        This runner executes with shell=False; however we still reject args that contain:
        ; & | ` $ ( ) > < \\n \\r

        Raises:
            ValueError on detection.
        """
        prohibited = set(";&|`$()><\n\r")
        for a in args:
            if any(ch in a for ch in prohibited):
                raise ValueError(f"Disallowed character in argument: {a!r}")
        return args

    def _run_with_cli(
        self,
        *,
        image: str,
        args: List[str],
        env: Dict[str, str],
        volumes: List[DockerVolume],
        network: Optional[str],
        workdir: Optional[str],
        timeout: float,
    ) -> DockerRunResult:
        """
        Execute using the 'docker' CLI.
        """
        cmd: List[str] = ["docker", "run", "--rm"]

        if network:
            cmd += ["--network", network]

        if workdir:
            cmd += ["-w", workdir]

        # Environment variables
        for k, v in env.items():
            cmd += ["-e", f"{k}={v}"]

        # Volumes
        for vol in volumes:
            host = self._normalize_host_path(vol["host_path"])
            container = vol["container_path"]
            mode = vol.get("mode", "ro")
            cmd += ["-v", f"{host}:{container}:{mode}"]

        cmd.append(image)
        cmd += args

        started = time.time()
        try:
            cp = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration = time.time() - started
            status: Literal["success", "error"] = "success" if cp.returncode == 0 else "error"
            return DockerRunResult(
                status=status,
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                duration=duration,
            )
        except subprocess.TimeoutExpired as te:
            # Best-effort: attempt to kill containers started (cannot know container id here)
            return DockerRunResult(
                status="timeout",
                exit_code=None,
                stdout=te.stdout.decode() if isinstance(te.stdout, bytes) else (te.stdout or ""),
                stderr=te.stderr.decode() if isinstance(te.stderr, bytes) else (te.stderr or "Execution timed out"),
                duration=timeout,
            )

    def _run_with_sdk(
        self,
        *,
        image: str,
        args: List[str],
        env: Dict[str, str],
        volumes: List[DockerVolume],
        network: Optional[str],
        workdir: Optional[str],
        timeout: float,
    ) -> DockerRunResult:
        """
        Execute using the Docker SDK for Python.
        """
        if not _DOCKER_AVAILABLE:
            raise RuntimeError("Docker SDK is not available")

        client = docker.from_env()  # type: ignore

        # Map volumes for SDK format
        volume_map: Dict[str, Dict[str, str]] = {}
        for vol in volumes:
            host = self._normalize_host_path(vol["host_path"])
            # SDK expects native path; avoid shlex here
            mode = vol.get("mode", "ro")
            volume_map[host] = {"bind": vol["container_path"], "mode": mode}

        # Create and start container
        started = time.time()
        container = client.containers.run(  # type: ignore
            image=image,
            command=args,
            environment=env or None,
            volumes=volume_map or None,
            working_dir=workdir or None,
            network=network or None,
            detach=True,
            stdout=True,
            stderr=True,
        )

        try:
            # Poll for completion respecting timeout
            while True:
                container.reload()
                state = container.attrs.get("State", {})
                if state.get("Running") is False:
                    break
                if (time.time() - started) > timeout:
                    container.stop()
                    container.remove(force=True)
                    return DockerRunResult(
                        status="timeout",
                        exit_code=None,
                        stdout="",
                        stderr="Execution timed out",
                        duration=time.time() - started,
                    )
                time.sleep(0.2)

            # Collect logs and exit code
            exit_code = state.get("ExitCode")
            try:
                stdout_bytes = container.logs(stdout=True, stderr=False)  # type: ignore
            except Exception:
                stdout_bytes = b""
            try:
                stderr_bytes = container.logs(stdout=False, stderr=True)  # type: ignore
            except Exception:
                stderr_bytes = b""

            stdout = stdout_bytes.decode(errors="replace") if isinstance(stdout_bytes, (bytes, bytearray)) else str(stdout_bytes)
            stderr = stderr_bytes.decode(errors="replace") if isinstance(stderr_bytes, (bytes, bytearray)) else str(stderr_bytes)

            status: Literal["success", "error"] = "success" if (exit_code == 0) else "error"
            return DockerRunResult(
                status=status,
                exit_code=int(exit_code) if exit_code is not None else None,
                stdout=stdout or "",
                stderr=stderr or "",
                duration=time.time() - started,
            )
        finally:
            # Ensure container is removed
            try:
                container.remove(force=True)
            except Exception:
                pass

    def _normalize_host_path(self, path_str: str) -> str:
        """
        Normalize host path for volume mounting.

        - Resolve to absolute path
        - Convert backslashes to forward slashes for cross-platform docker CLI tolerance
        """
        p = Path(path_str).expanduser().resolve()
        norm = str(p)
        # Avoid quoting; we pass as one argument in list form
        return norm.replace("\\", "/")
