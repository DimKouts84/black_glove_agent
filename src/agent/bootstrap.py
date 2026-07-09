"""
Bootstrap helpers for one-click web app launch.

Used by Launch-BlackGlove-Web.ps1, `python -m agent.bootstrap`, and `black-glove launch-web`.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("black_glove.bootstrap")

STATIC_INDEX = Path("src") / "webapp" / "static" / "index.html"
FRONTEND_DIR = Path("frontend")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


def get_project_root() -> Path:
    """Return repository root (parent of src/)."""
    # src/agent/bootstrap.py -> src/agent -> src -> root
    return Path(__file__).resolve().parent.parent.parent


def get_venv_python(project_root: Optional[Path] = None) -> Optional[Path]:
    """Path to venv Python executable if .venv exists."""
    root = project_root or get_project_root()
    if sys.platform == "win32":
        candidate = root / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = root / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else None


def _venv_import_probe(python_exe: Path, project_root: Path) -> Tuple[bool, str]:
    """Return (imports_ok, stderr_or_empty) for the venv CLI import check."""
    env = {**dict(__import__("os").environ), "PYTHONPATH": str(project_root / "src")}
    try:
        result = subprocess.run(
            [
                str(python_exe),
                "-c",
                "from webapp.app import create_app; create_app()",
            ],
            cwd=str(project_root),
            env=env,
            capture_output=True,
            timeout=30,
        )
        stderr = (result.stderr or b"").decode(errors="replace").strip()
        return result.returncode == 0, stderr
    except (subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)


def _venv_imports_ok(python_exe: Path, project_root: Path) -> bool:
    """Check whether core packages and CLI entrypoint imports work in the venv."""
    ok, _ = _venv_import_probe(python_exe, project_root)
    return ok


def _run_cmd(cmd: list, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    logger.info("Running: %s (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(cmd, cwd=str(cwd), check=check)


def _install_project_into_venv(venv_python: Optional[Path], root: Path) -> None:
    """Install declared dependencies and editable project into the venv."""
    lockfile = root / "uv.lock"
    pyproject = root / "pyproject.toml"

    if shutil.which("uv"):
        if lockfile.is_file():
            _run_cmd(["uv", "sync"], root)
            return
        if pyproject.is_file():
            _run_cmd(["uv", "pip", "install", "-r", str(pyproject)], root)
            _run_cmd(["uv", "pip", "install", "-e", ".", "--no-deps"], root)
            return
        raise RuntimeError(f"pyproject.toml not found in {root}")

    if not venv_python:
        if shutil.which("python"):
            _run_cmd([sys.executable, "-m", "venv", ".venv"], root)
        else:
            raise RuntimeError(
                "Python not found. Install Python 3.8+ from https://www.python.org/downloads/"
            )
        venv_python = get_venv_python(root)
        if not venv_python:
            raise RuntimeError("Failed to create .venv")

    pip = [str(venv_python), "-m", "pip"]
    try:
        subprocess.run([*pip, "--version"], cwd=str(root), check=True, capture_output=True)
    except subprocess.CalledProcessError:
        _run_cmd([str(venv_python), "-m", "ensurepip", "--upgrade"], root)
    _run_cmd([*pip, "install", "-e", "."], root)


def ensure_venv(project_root: Optional[Path] = None) -> Path:
    """
    Ensure .venv exists with project dependencies installed.

    Returns:
        Path to the venv Python executable.

    Raises:
        RuntimeError: If Python/uv unavailable or install fails.
    """
    root = project_root or get_project_root()
    venv_python = get_venv_python(root)

    if venv_python:
        ok, _ = _venv_import_probe(venv_python, root)
        if ok:
            logger.info("Virtual environment OK at %s", venv_python)
            return venv_python

    _install_project_into_venv(venv_python, root)

    venv_python = get_venv_python(root)
    if not venv_python:
        raise RuntimeError("Failed to create .venv")

    ok, probe_stderr = _venv_import_probe(venv_python, root)
    if not ok and shutil.which("uv") and (root / "uv.lock").is_file():
        logger.warning("Import check failed after uv sync; retrying with --reinstall")
        _run_cmd(["uv", "sync", "--reinstall"], root)
        venv_python = get_venv_python(root)
        if not venv_python:
            raise RuntimeError("Failed to create .venv")
        ok, probe_stderr = _venv_import_probe(venv_python, root)

    if not ok:
        detail = probe_stderr or "unknown import error"
        raise RuntimeError(
            f"Failed to install project dependencies into .venv: {detail}"
        )

    return venv_python


def static_bundle_exists(project_root: Optional[Path] = None) -> bool:
    root = project_root or get_project_root()
    return (root / STATIC_INDEX).is_file()


def ensure_frontend_built(
    project_root: Optional[Path] = None,
    force: bool = False,
) -> bool:
    """
    Build React frontend into src/webapp/static/ if missing or force=True.

    Returns:
        True if build ran or bundle already present.

    Raises:
        RuntimeError: If Node.js/npm missing or build fails.
    """
    root = project_root or get_project_root()
    if static_bundle_exists(root) and not force:
        logger.info("Frontend static bundle already present")
        return True

    if not shutil.which("npm"):
        raise RuntimeError(
            "Node.js/npm not found. Install from https://nodejs.org/ then re-run."
        )

    frontend = root / FRONTEND_DIR
    if not frontend.is_dir():
        raise RuntimeError(f"Frontend directory not found: {frontend}")

    _run_cmd(["npm", "install"], frontend)
    _run_cmd(["npm", "run", "build"], frontend)

    if not static_bundle_exists(root):
        raise RuntimeError("Frontend build completed but static/index.html is missing")

    return True


def get_web_host_port(project_root: Optional[Path] = None) -> Tuple[str, int]:
    """Read web_host/web_port from ConfigService, with defaults."""
    try:
        from agent.config_service import ConfigService

        cfg = ConfigService().load()
        return cfg.web_host or DEFAULT_HOST, int(cfg.web_port or DEFAULT_PORT)
    except Exception:
        return DEFAULT_HOST, DEFAULT_PORT


def get_web_port(project_root: Optional[Path] = None) -> int:
    return get_web_host_port(project_root)[1]


def is_server_running(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 2.0,
) -> bool:
    """Return True if Black Glove health endpoint responds."""
    url = f"http://{host}:{port}/api/health"
    try:
        import urllib.request

        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            body = json.loads(resp.read().decode())
            return body.get("status") == "ok"
    except Exception:
        return False


def wait_for_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 30.0,
    interval: float = 0.5,
) -> bool:
    """Poll health endpoint until ready or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_server_running(host, port):
            return True
        time.sleep(interval)
    return False


def ensure_all(
    project_root: Optional[Path] = None,
    force_frontend: bool = False,
) -> Tuple[Path, str, int]:
    """
    Bootstrap venv and frontend build.

    Returns:
        (venv_python_path, web_host, web_port)
    """
    root = project_root or get_project_root()
    python_exe = ensure_venv(root)
    ensure_frontend_built(root, force=force_frontend)
    host, port = get_web_host_port(root)
    return python_exe, host, port


def _cli_main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Black Glove web launch bootstrap")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check-only", help="Print bootstrap status as JSON")
    check.add_argument("--project-root", type=Path, default=None)

    ensure = sub.add_parser("ensure-all", help="Bootstrap venv and frontend")
    ensure.add_argument("--project-root", type=Path, default=None)
    ensure.add_argument("--force-rebuild", action="store_true")

    status = sub.add_parser("status", help="JSON status for launcher scripts")
    status.add_argument("--project-root", type=Path, default=None)

    args = parser.parse_args(argv)
    root = getattr(args, "project_root", None) or get_project_root()

    if args.command == "check-only" or args.command == "status":
        host, port = get_web_host_port(root)
        venv_py = get_venv_python(root)
        deps_ok = bool(venv_py and _venv_imports_ok(venv_py, root))
        payload = {
            "project_root": str(root),
            "venv_exists": venv_py is not None,
            "deps_ok": deps_ok,
            "static_built": static_bundle_exists(root),
            "server_running": is_server_running(host, port),
            "web_host": host,
            "web_port": port,
            "venv_python": str(venv_py) if venv_py else None,
        }
        print(json.dumps(payload))
        return 0

    if args.command == "ensure-all":
        try:
            python_exe, host, port = ensure_all(
                root, force_frontend=args.force_rebuild
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "venv_python": str(python_exe),
                        "web_host": host,
                        "web_port": port,
                    }
                )
            )
            return 0
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(_cli_main())
