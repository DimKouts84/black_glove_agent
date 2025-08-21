import importlib
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
import os

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.utils.docker_runner import DockerRunner

class TestDockerRunnerCLI:
    def test_cli_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured_cmd: List[str] = []

        def fake_run(cmd, capture_output, text, timeout):
            nonlocal captured_cmd
            captured_cmd = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        runner = DockerRunner(prefer_sdk=False)
        res = runner.run(
            {
                "image": "alpine:latest",
                "args": ["echo", "hello"],
                "env": {"FOO": "bar"},
                "volumes": [],
                "network": "bridge",
                "workdir": "/work",
                "timeout": 5.0,
            }
        )

        assert res["status"] == "success"
        assert res["exit_code"] == 0
        assert "OK" in res["stdout"]
        assert res["duration"] >= 0

        # Command structure assertions
        assert captured_cmd[:3] == ["docker", "run", "--rm"]
        assert "-w" in captured_cmd and "/work" in captured_cmd
        assert "--network" in captured_cmd and "bridge" in captured_cmd
        # env passed
        assert "-e" in captured_cmd and "FOO=bar" in captured_cmd
        # image and args are present and in order
        idx = captured_cmd.index("alpine:latest")
        assert captured_cmd[idx + 1 : idx + 3] == ["echo", "hello"]

    def test_cli_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_run(cmd, capture_output, text, timeout):
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="Boom")

        monkeypatch.setattr(subprocess, "run", fake_run)

        runner = DockerRunner(prefer_sdk=False)
        res = runner.run(
            {
                "image": "alpine:latest",
                "args": ["false"],
                "env": {},
                "volumes": [],
                "timeout": 1.0,
            }
        )
        assert res["status"] == "error"
        assert res["exit_code"] == 2
        assert "Boom" in res["stderr"]

    def test_cli_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_run(cmd, capture_output, text, timeout):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout, output="OUT", stderr="ERR")

        monkeypatch.setattr(subprocess, "run", fake_run)

        runner = DockerRunner(prefer_sdk=False)
        res = runner.run(
            {
                "image": "alpine:latest",
                "args": ["sleep", "10"],
                "env": {},
                "volumes": [],
                "timeout": 0.1,
            }
        )
        assert res["status"] == "timeout"
        assert res["exit_code"] is None
        assert "ERR" in res["stderr"]
        assert res["duration"] == pytest.approx(0.1, rel=0.5, abs=0.5)

    def test_cli_arguments_mapping(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        captured_cmd: List[str] = []

        def fake_run(cmd, capture_output, text, timeout):
            nonlocal captured_cmd
            captured_cmd = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        host_dir = tmp_path / "evidence"
        host_dir.mkdir(parents=True, exist_ok=True)
        host_path = str(host_dir)
        container_path = "/evidence"
        expected_host = Path(host_path).resolve().as_posix()

        runner = DockerRunner(prefer_sdk=False)
        res = runner.run(
            {
                "image": "alpine:latest",
                "args": ["sh", "-c", "echo OK"],
                "env": {"K": "V"},
                "volumes": [{"host_path": host_path, "container_path": container_path, "mode": "ro"}],
                "network": "host",
                "workdir": "/work",
                "timeout": 5.0,
            }
        )
        assert res["status"] == "success"

        # Check -v mapping
        assert "-v" in captured_cmd
        vol_idx = captured_cmd.index("-v") + 1
        assert captured_cmd[vol_idx] == f"{expected_host}:{container_path}:ro"

        # Check network mode
        assert "--network" in captured_cmd
        assert "host" in captured_cmd

        # Check env mapping
        assert "-e" in captured_cmd and "K=V" in captured_cmd


class TestDockerRunnerSDK:
    class _FakeContainer:
        def __init__(self, running: bool = False, exit_code: int = 0):
            self.attrs = {"State": {"Running": running, "ExitCode": exit_code}}
            self.stopped = False
            self.removed = False

        def reload(self) -> None:
            # no-op; test controls state externally if needed
            return

        def logs(self, stdout: bool = True, stderr: bool = False):
            if stdout and not stderr:
                return b"STDOUT"
            if stderr and not stdout:
                return b"STDERR"
            return b""

        def stop(self) -> None:
            self.stopped = True

        def remove(self, force: bool = False) -> None:
            self.removed = True

    class _FakeContainers:
        def __init__(self):
            self.last_kwargs: Dict[str, Any] = {}
            self.next_container: TestDockerRunnerSDK._FakeContainer | None = None

        def run(self, **kwargs):
            self.last_kwargs = kwargs
            if self.next_container is not None:
                return self.next_container
            return TestDockerRunnerSDK._FakeContainer()

    class _FakeClient:
        def __init__(self):
            self.containers = TestDockerRunnerSDK._FakeContainers()

    class _FakeDockerModule:
        def __init__(self, client: "_FakeClient"):
            self._client = client

        def from_env(self):
            return self._client

    def _patch_sdk(self, monkeypatch: pytest.MonkeyPatch):
        # Import module to patch internal references
        dr = importlib.import_module("src.utils.docker_runner")
        client = self._FakeClient()
        fake_docker = self._FakeDockerModule(client)
        monkeypatch.setattr(dr, "_DOCKER_AVAILABLE", True)
        monkeypatch.setattr(dr, "docker", fake_docker, raising=True)
        return dr, client

    def test_sdk_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        dr, client = self._patch_sdk(monkeypatch)

        host_dir = tmp_path / "evidence"
        host_dir.mkdir(parents=True, exist_ok=True)
        host_path = str(host_dir)
        expected_host = Path(host_path).resolve().as_posix()

        container = self._FakeContainer(running=False, exit_code=0)
        client.containers.next_container = container

        runner = dr.DockerRunner(prefer_sdk=True)
        res = runner.run(
            {
                "image": "alpine:latest",
                "args": ["echo", "ok"],
                "env": {"A": "B"},
                "volumes": [{"host_path": host_path, "container_path": "/evidence", "mode": "ro"}],
                "network": "bridge",
                "workdir": "/work",
                "timeout": 5.0,
            }
        )

        assert res["status"] == "success"
        assert res["exit_code"] == 0
        assert "STDOUT" in res["stdout"]

        # Validate containers.run kwargs
        kwargs = client.containers.last_kwargs
        assert kwargs["image"] == "alpine:latest"
        assert kwargs["command"] == ["echo", "ok"]
        assert kwargs["environment"] == {"A": "B"}
        assert kwargs["working_dir"] == "/work"
        assert kwargs["network"] == "bridge"
        assert kwargs["detach"] is True
        assert kwargs["stdout"] is True and kwargs["stderr"] is True
        assert kwargs["volumes"][expected_host]["bind"] == "/evidence"
        assert kwargs["volumes"][expected_host]["mode"] == "ro"

        # Container should be removed
        assert container.removed is True

    def test_sdk_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dr, client = self._patch_sdk(monkeypatch)

        # Container that never stops running
        container = self._FakeContainer(running=True, exit_code=137)
        client.containers.next_container = container

        runner = dr.DockerRunner(prefer_sdk=True)
        start = time.time()
        res = runner.run(
            {
                "image": "alpine:latest",
                "args": ["sleep", "10"],
                "env": {},
                "volumes": [],
                "network": None,
                "workdir": None,
                "timeout": 0.05,
            }
        )
        end = time.time()

        assert res["status"] == "timeout"
        assert res["exit_code"] is None
        # Ensure it didn't block for too long (loop sleeps ~0.2s)
        assert (end - start) <= 0.5
        assert container.stopped is True
        assert container.removed is True


class TestSanitization:
    def test_disallowed_characters_raise(self) -> None:
        runner = DockerRunner(prefer_sdk=False)
        with pytest.raises(ValueError):
            runner.run(
                {
                    "image": "alpine:latest",
                    "args": ["echo", "bad;rm -rf /"],
                    "env": {},
                    "volumes": [],
                    "timeout": 1.0,
                }
            )
