"""Tests for web launch bootstrap helpers."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "src")

from agent import bootstrap


class TestBootstrapHelpers:
    def test_get_project_root(self):
        root = bootstrap.get_project_root()
        assert (root / "src" / "agent" / "bootstrap.py").is_file()
        assert (root / "pyproject.toml").is_file()

    def test_static_bundle_exists(self, tmp_path):
        assert bootstrap.static_bundle_exists(tmp_path) is False
        static = tmp_path / "src" / "webapp" / "static"
        static.mkdir(parents=True)
        (static / "index.html").write_text("<html></html>")
        assert bootstrap.static_bundle_exists(tmp_path) is True

    def test_get_web_port_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        host, port = bootstrap.get_web_host_port(tmp_path)
        assert host == bootstrap.DEFAULT_HOST
        assert port == bootstrap.DEFAULT_PORT

    def test_is_server_running_true(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"status": "ok"}).encode()

        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert bootstrap.is_server_running() is True

    def test_is_server_running_false(self):
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            assert bootstrap.is_server_running() is False

    def test_venv_import_probe_checks_webapp_create_app(self, tmp_path, monkeypatch):
        fake_python = tmp_path / "python.exe"
        fake_python.write_text("")
        called_with = {}

        def fake_run(cmd, **kwargs):
            called_with["cmd"] = cmd
            result = MagicMock()
            result.returncode = 1
            result.stderr = b"ModuleNotFoundError: chromadb"
            return result

        monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
        ok, stderr = bootstrap._venv_import_probe(fake_python, tmp_path)
        assert ok is False
        assert "create_app" in called_with["cmd"][-1]
        assert "webapp.app" in called_with["cmd"][-1]
        assert "chromadb" in stderr

    def test_cli_status_json(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        code = bootstrap._cli_main(["status", "--project-root", str(tmp_path)])
        assert code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "deps_ok" in data
        assert "web_port" in data

    def test_ensure_venv_skips_when_imports_ok(self, tmp_path, monkeypatch):
        fake_python = tmp_path / ".venv" / "Scripts" / "python.exe"
        fake_python.parent.mkdir(parents=True)
        fake_python.write_text("")

        monkeypatch.setattr(bootstrap, "get_venv_python", lambda root=None: fake_python)
        monkeypatch.setattr(
            bootstrap, "_venv_import_probe", lambda py, root: (True, "")
        )

        result = bootstrap.ensure_venv(tmp_path)
        assert result == fake_python

    def test_install_uses_uv_sync_when_lockfile_present(self, tmp_path, monkeypatch):
        (tmp_path / "uv.lock").write_text("version = 1\n")
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
        calls = []

        def fake_run(cmd, cwd, check=True):
            calls.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/uv" if name == "uv" else None)
        monkeypatch.setattr(bootstrap, "_run_cmd", fake_run)
        monkeypatch.setattr(bootstrap, "get_venv_python", lambda root=None: tmp_path / ".venv" / "Scripts" / "python.exe")
        monkeypatch.setattr(bootstrap, "_venv_import_probe", lambda py, root: (True, ""))

        bootstrap._install_project_into_venv(None, tmp_path)
        assert calls == [["uv", "sync"]]

    def test_install_falls_back_to_pip_without_uv(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
        fake_python = tmp_path / ".venv" / "Scripts" / "python.exe"
        fake_python.parent.mkdir(parents=True)
        fake_python.write_text("")
        calls = []

        def fake_run(cmd, cwd, check=True):
            calls.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(bootstrap.shutil, "which", lambda name: None)
        monkeypatch.setattr(bootstrap, "_run_cmd", fake_run)
        monkeypatch.setattr(
            bootstrap.subprocess,
            "run",
            lambda *a, **k: MagicMock(returncode=0),
        )

        bootstrap._install_project_into_venv(fake_python, tmp_path)
        assert any("pip" in str(c) and "install" in str(c) for c in calls)

    def test_ensure_venv_raises_with_import_stderr(self, tmp_path, monkeypatch):
        fake_python = tmp_path / ".venv" / "Scripts" / "python.exe"
        fake_python.parent.mkdir(parents=True)
        fake_python.write_text("")

        monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/uv" if name == "uv" else None)
        monkeypatch.setattr(bootstrap, "_install_project_into_venv", lambda py, root: None)
        monkeypatch.setattr(bootstrap, "get_venv_python", lambda root=None: fake_python)
        monkeypatch.setattr(
            bootstrap,
            "_venv_import_probe",
            lambda py, root: (False, "ModuleNotFoundError: No module named 'typer'"),
        )

        with pytest.raises(RuntimeError, match="typer"):
            bootstrap.ensure_venv(tmp_path)

    def test_ensure_venv_retries_uv_sync_reinstall_on_import_failure(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "uv.lock").write_text("version = 1\n")
        fake_python = tmp_path / ".venv" / "Scripts" / "python.exe"
        fake_python.parent.mkdir(parents=True)
        fake_python.write_text("")
        calls = []
        probe_results = [(False, "missing typer"), (False, "still missing"), (True, "")]

        def fake_probe(py, root):
            return probe_results.pop(0)

        def fake_install(py, root):
            calls.append("install")

        def fake_run(cmd, cwd, check=True):
            calls.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/uv" if name == "uv" else None)
        monkeypatch.setattr(bootstrap, "_install_project_into_venv", fake_install)
        monkeypatch.setattr(bootstrap, "get_venv_python", lambda root=None: fake_python)
        monkeypatch.setattr(bootstrap, "_venv_import_probe", fake_probe)
        monkeypatch.setattr(bootstrap, "_run_cmd", fake_run)

        result = bootstrap.ensure_venv(tmp_path)
        assert result == fake_python
        assert ["uv", "sync", "--reinstall"] in calls
