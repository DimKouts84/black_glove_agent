import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).parent.parent))

from src.adapters.gobuster import GobusterAdapter, create_gobuster_adapter
from src.agent.plugin_manager import PluginManager

DIR_STDOUT = """
/admin (Status: 301) [Size: 0]
/images (Status: 200) [Size: 1243]
/index.php (Status: 200)
""".strip()

DNS_STDOUT = """
Found: admin.example.com
dev.example.com (A) 192.168.1.50
mail.example.com (CNAME) example.com
""".strip()

class FakeRunner:
    def __init__(self, result: Dict[str, Any]):
        self.result = result
        self.last_spec: Dict[str, Any] | None = None

    def run(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        self.last_spec = spec
        return dict(self.result)

class TestGobusterValidation:
    def test_validate_config(self):
        # Valid minimal config
        adapter = create_gobuster_adapter({"timeout": 10.0, "default_mode": "dir"})
        assert adapter.validate_config() is True

        # Invalid timeout
        with pytest.raises(ValueError):
            create_gobuster_adapter({"timeout": 0}).validate_config()

        # Invalid docker_network
        with pytest.raises(ValueError):
            create_gobuster_adapter({"docker_network": 123}).validate_config()

        # Invalid default mode
        with pytest.raises(ValueError):
            create_gobuster_adapter({"default_mode": "foo"}).validate_config()

        # Invalid wordlist type
        with pytest.raises(ValueError):
            create_gobuster_adapter({"wordlist": 123}).validate_config()

    def test_validate_params_dir_and_dns(self):
        adapter = create_gobuster_adapter()

        # Missing wordlist
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "http://example.com"})

        # DIR valid
        assert adapter.validate_params(
            {"mode": "dir", "url": "http://example.com", "wordlist": "/tmp/words.txt", "threads": 10, "extensions": ["php", "html"], "status_codes": [200, 301]}
        ) is True

        # DIR invalid URL
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "ftp://bad", "wordlist": "/tmp/w.txt"})

        # DIR invalid extensions
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "http://x", "wordlist": "/tmp/w.txt", "extensions": ["ok", "bad;ext"]})

        # DIR invalid status codes
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "http://x", "wordlist": "/tmp/w.txt", "status_codes": ["200"]})

        # DNS valid
        assert adapter.validate_params({"mode": "dns", "domain": "example.com", "wordlist": "/tmp/subs.txt"}) is True

        # DNS invalid domain
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dns", "domain": "bad domain", "wordlist": "/tmp/subs.txt"})

        # Threads bounds
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "http://x", "wordlist": "/tmp/w.txt", "threads": 0})
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "http://x", "wordlist": "/tmp/w.txt", "threads": 9999})

        # Unsafe flag
        with pytest.raises(ValueError):
            adapter.validate_params({"mode": "dir", "url": "http://x", "wordlist": "/tmp/w.txt", "extra_flags": ["-t", "bad;flag"]})

class TestGobusterBuildersParsers:
    def test_build_command_dir(self):
        adapter = create_gobuster_adapter()
        cmd = adapter._build_command(  # type: ignore[attr-defined]
            params={
                "mode": "dir",
                "url": "http://example.com",
                "threads": 20,
                "extensions": ["php", "html"],
                "status_codes": [200, 204, 301],
                "extra_flags": ["-q"],
            },
            wordlist="/path/to/wordlist.txt",
            mode="dir",
        )
        # base
        assert cmd[:2] == ["gobuster", "dir"]
        # wordlist
        assert "-w" in cmd and "/path/to/wordlist.txt" in cmd
        # url
        assert "-u" in cmd and "http://example.com" in cmd
        # threads
        assert "-t" in cmd and "20" in cmd
        # extensions combined
        assert "-x" in cmd and "php,html" in cmd
        # status codes combined
        assert "-s" in cmd and "200,204,301" in cmd
        # extra flag passed
        assert "-q" in cmd

    def test_build_command_dns(self):
        adapter = create_gobuster_adapter()
        cmd = adapter._build_command(  # type: ignore[attr-defined]
            params={"mode": "dns", "domain": "example.com"},
            wordlist="/path/to/subs.txt",
            mode="dns",
        )
        assert cmd[:2] == ["gobuster", "dns"]
        assert "-w" in cmd and "/path/to/subs.txt" in cmd
        assert "-d" in cmd and "example.com" in cmd

    def test_parse_output_dir(self):
        adapter = create_gobuster_adapter()
        parsed = adapter._parse_output(DIR_STDOUT, "dir")  # type: ignore[attr-defined]
        assert parsed["mode"] == "dir"
        assert any(e["path"] == "/admin" and e["status"] == 301 for e in parsed["entries"])
        assert any(e["path"] == "/images" and e["status"] == 200 and e["size"] == 1243 for e in parsed["entries"])
        assert any(e["path"] == "/index.php" and e["status"] == 200 for e in parsed["entries"])

    def test_parse_output_dns(self):
        adapter = create_gobuster_adapter()
        parsed = adapter._parse_output(DNS_STDOUT, "dns")  # type: ignore[attr-defined]
        assert parsed["mode"] == "dns"
        hosts = [e.get("host") for e in parsed["entries"] if "host" in e]
        assert "admin.example.com" in hosts
        assert any(e.get("record_type") == "A" and e.get("host") == "dev.example.com" for e in parsed["entries"])

class TestGobusterExecution:
    def test_execute_dir_success_and_evidence(self, tmp_path: Path):
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner({"status": "success", "exit_code": 0, "stdout": DIR_STDOUT, "stderr": "", "duration": 0.01})
            adapter = create_gobuster_adapter({"_runner": runner})
            result = adapter.execute({"mode": "dir", "url": "http://example.com", "wordlist": "/path/to/wordlist.txt", "threads": 10})

            assert result.status.name == "SUCCESS"
            assert result.evidence_path is not None
            ev = Path(result.evidence_path)
            assert ev.exists()
            content = ev.read_text(encoding="utf-8")
            assert "/admin (Status: 301)" in content

            # Volume mount includes evidence/gobusteradapter
            spec = runner.last_spec
            assert spec is not None
            vols = spec.get("volumes", [])
            assert any(v.get("container_path") == "/evidence" for v in vols)
        finally:
            os.chdir(cwd)

    def test_execute_timeout(self, tmp_path: Path):
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner({"status": "timeout", "exit_code": None, "stdout": "", "stderr": "Execution timed out", "duration": 0.2})
            adapter = create_gobuster_adapter({"_runner": runner})
            result = adapter.execute({"mode": "dns", "domain": "example.com", "wordlist": "/path/to/subs.txt"})
            assert result.status.name == "TIMEOUT"
            assert "timed out" in (result.error_message or "").lower()
        finally:
            os.chdir(cwd)

class TestPluginManagerIntegration:
    def test_plugin_manager_load_and_run_dir(self, tmp_path: Path):
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner({"status": "success", "exit_code": 0, "stdout": DIR_STDOUT, "stderr": "", "duration": 0.01})
            pm = PluginManager()
            adapter = pm.load_adapter("gobuster", {"_runner": runner})
            assert isinstance(adapter, GobusterAdapter)

            res = pm.run_adapter("gobuster", {"mode": "dir", "url": "http://example.com", "wordlist": "/wl.txt"})
            assert res.status.name == "SUCCESS"
            assert res.data["mode"] == "dir"
        finally:
            os.chdir(cwd)

    def test_plugin_manager_load_and_run_dns(self, tmp_path: Path):
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            runner = FakeRunner({"status": "success", "exit_code": 0, "stdout": DNS_STDOUT, "stderr": "", "duration": 0.01})
            pm = PluginManager()
            adapter = pm.load_adapter("gobuster", {"_runner": runner})
            assert isinstance(adapter, GobusterAdapter)

            res = pm.run_adapter("gobuster", {"mode": "dns", "domain": "example.com", "wordlist": "/subs.txt"})
            assert res.status.name == "SUCCESS"
            assert res.data["mode"] == "dns"
        finally:
            os.chdir(cwd)
