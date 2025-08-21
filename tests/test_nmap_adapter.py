import os
from pathlib import Path
from typing import Any, Dict, List
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.adapters.nmap import NmapAdapter, create_nmap_adapter
from src.agent.plugin_manager import PluginManager

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10"/>
    <hostnames><hostname name="test.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <runstats>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
""".strip()


class FakeRunner:
    def __init__(self, result: Dict[str, Any]):
        self.result = result
        self.last_spec: Dict[str, Any] | None = None

    def run(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        self.last_spec = spec
        return dict(self.result)


class TestNmapValidation:
    def test_validate_config_flags_and_timeouts(self):
        # Valid config
        adapter = create_nmap_adapter({"timeout": 10.0, "default_flags": ["-Pn", "-sV"]})
        assert adapter.validate_config() is True

        # Invalid timeout
        with pytest.raises(ValueError):
            create_nmap_adapter({"timeout": -1}).validate_config()

        # Invalid docker_network
        with pytest.raises(ValueError):
            create_nmap_adapter({"docker_network": 123}).validate_config()

        # Unsafe default flag
        with pytest.raises(ValueError, match="Unsafe default flag"):
            create_nmap_adapter({"default_flags": ["-sV", "bad;flag"]}).validate_config()

        # Invalid rate limit
        with pytest.raises(ValueError):
            create_nmap_adapter({"rate_limit_rpm": 0}).validate_config()

    def test_validate_params(self):
        adapter = create_nmap_adapter()

        # Valid
        params = {
            "target": "example.com",
            "ports": "80,443",
            "scripts": ["http-title", "http-headers"],
            "extra_flags": ["-Pn", "-T3"],
            "output_xml": True,
        }
        assert adapter.validate_params(params) is True

        # Invalid target
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "bad target !", "output_xml": True})

        # Invalid ports
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "example.com", "ports": "80,abc", "output_xml": True})

        # Invalid script name
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "example.com", "scripts": ["good", "bad;name"], "output_xml": True})

        # Unsafe extra flag
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "example.com", "extra_flags": ["-T3", "bad;flag"], "output_xml": True})

        # Enforce XML
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "example.com", "output_xml": False})


class TestNmapBuildersParsers:
    def test_build_command_composition(self):
        adapter = create_nmap_adapter({"default_flags": ["-sV"]})
        cmd = adapter._build_command(  # type: ignore[attr-defined]
            params={
                "target": "example.com",
                "ports": "80,443",
                "scripts": ["http-title", "http-server-header"],
                "extra_flags": ["-T3"],
                "output_xml": True,
            },
            cfg={"default_flags": ["-sV"]},
        )

        assert cmd[:3] == ["nmap", "-oX", "-"]
        # flags order: default then extra
        assert "-sV" in cmd
        assert "-T3" in cmd
        # ports
        assert "-p" in cmd and "80,443" in cmd
        # scripts combined
        assert "--script" in cmd
        si = cmd.index("--script")
        assert cmd[si + 1] == "http-title,http-server-header"
        # target last
        assert cmd[-1] == "example.com"

    def test_parse_xml_simple(self):
        adapter = create_nmap_adapter()
        parsed = adapter._parse_xml(SAMPLE_NMAP_XML)  # type: ignore[attr-defined]
        assert parsed["summary"]["up"] == 1
        assert parsed["summary"]["down"] == 0
        assert parsed["summary"]["open_ports"] == 1
        assert len(parsed["hosts"]) == 1
        host = parsed["hosts"][0]
        assert host["address"] == "192.168.1.10"
        assert host["hostname"] == "test.local"
        ports = host["ports"]
        assert any(p["port"] == "80" and p["state"] == "open" and p["service"] == "http" for p in ports)


class TestNmapExecution:
    def test_execute_success_and_evidence(self, tmp_path: Path):
        # Use tmp evidence dir by chdir
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner(
                {
                    "status": "success",
                    "exit_code": 0,
                    "stdout": SAMPLE_NMAP_XML,
                    "stderr": "",
                    "duration": 0.01,
                }
            )
            adapter = create_nmap_adapter({"_runner": runner, "default_flags": ["-sV"]})
            result = adapter.execute({"target": "192.168.1.10"})

            assert result.status.name == "SUCCESS"
            assert result.data["summary"]["up"] == 1
            assert result.evidence_path is not None
            # Evidence file exists and contains XML
            ev_path = Path(result.evidence_path)
            assert ev_path.exists()
            content = ev_path.read_text(encoding="utf-8")
            assert "<nmaprun>" in content
            # Volume mount should include evidence/nmapadapter
            spec = runner.last_spec
            assert spec is not None
            vols = spec.get("volumes", [])
            assert any(v.get("container_path") == "/evidence" for v in vols)
        finally:
            os.chdir(cwd)

    def test_execute_timeout_maps_status(self, tmp_path: Path):
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner({"status": "timeout", "exit_code": None, "stdout": "", "stderr": "Execution timed out", "duration": 0.2})
            adapter = create_nmap_adapter({"_runner": runner})
            result = adapter.execute({"target": "192.168.0.1"})
            assert result.status.name == "TIMEOUT"
            assert "timed out" in (result.error_message or "").lower()
        finally:
            os.chdir(cwd)


class TestPluginManagerIntegration:
    def test_plugin_manager_load_and_run(self, tmp_path: Path):
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner(
                {"status": "success", "exit_code": 0, "stdout": SAMPLE_NMAP_XML, "stderr": "", "duration": 0.01}
            )
            pm = PluginManager()
            adapter = pm.load_adapter("nmap", {"_runner": runner})
            assert isinstance(adapter, NmapAdapter)

            res = pm.run_adapter("nmap", {"target": "192.168.1.10"})
            assert res.status.name == "SUCCESS"
            assert res.data["summary"]["up"] == 1
        finally:
            os.chdir(cwd)
