# Python
"""
Tests for PassiveReconAdapter (crt.sh + Wayback Machine)
"""

import pytest
from typing import Dict, Any

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.adapters.passive_recon import PassiveReconAdapter, create_passive_recon_adapter
from src.agent.plugin_manager import PluginManager


def _crt_json_many() -> str:
    # Three entries to test limiting
    return """[
      {
        "id": 1,
        "issuer_ca_id": 123,
        "issuer_name": "Test CA A",
        "name_value": "example.com\\nwww.example.com",
        "not_before": "2023-01-01",
        "not_after": "2024-01-01",
        "serial_number": "ABCD"
      },
      {
        "id": 2,
        "issuer_ca_id": 456,
        "issuer_name": "Test CA B",
        "name_value": "api.example.com",
        "not_before": "2023-02-01",
        "not_after": "2024-02-01",
        "serial_number": "EFGH"
      },
      {
        "id": 3,
        "issuer_ca_id": 789,
        "issuer_name": "Test CA C",
        "name_value": "*.example.com",
        "not_before": "2023-03-01",
        "not_after": "2024-03-01",
        "serial_number": "IJKL"
      }
    ]"""


def _wayback_json_many() -> str:
    # Three rows to test limiting
    return """[
      ["timestamp","original","mime","statuscode","length","digest"],
      ["20230101000000","http://example.com/","text/html","200","1234","D1"],
      ["20230201000000","http://example.com/login","text/html","200","2234","D2"],
      ["20230301000000","http://www.example.com/","text/html","200","3234","D3"]
    ]"""


def test_passive_recon_validate_params_invalid_domain():
    adapter = create_passive_recon_adapter()
    with pytest.raises(ValueError):
        adapter.validate_params({"domain": "not a domain"})


def test_passive_recon_success_both_sources(monkeypatch: pytest.MonkeyPatch):
    adapter = create_passive_recon_adapter({})

    def fake_http_get(self, url: str, timeout: float) -> str:
        if "crt.sh" in url:
            return _crt_json_many()
        if "web.archive.org" in url:
            return _wayback_json_many()
        return "[]"

    monkeypatch.setattr(PassiveReconAdapter, "_http_get", fake_http_get)

    result = adapter.execute({"domain": "example.com", "max_results": 2})

    assert result.status.value == "success"
    assert result.data["crt_sh"]["count"] == 2
    assert result.data["wayback"]["count"] == 2
    assert result.evidence_path is not None
    assert result.execution_time is not None or adapter.last_execution_time is not None


def test_passive_recon_partial_when_one_fails(monkeypatch: pytest.MonkeyPatch):
    adapter = create_passive_recon_adapter({})

    def fake_http_get(self, url: str, timeout: float) -> str:
        if "crt.sh" in url:
            return _crt_json_many()
        if "web.archive.org" in url:
            raise Exception("Wayback error")
        return "[]"

    monkeypatch.setattr(PassiveReconAdapter, "_http_get", fake_http_get)

    result = adapter.execute({"domain": "example.com", "max_results": 5})

    assert result.status.value == "partial"
    assert result.data["crt_sh"]["count"] > 0
    assert result.data["wayback"]["count"] == 0
    assert "wayback" in result.data["errors"]


def test_passive_recon_failure_when_both_fail(monkeypatch: pytest.MonkeyPatch):
    adapter = create_passive_recon_adapter({})

    def fake_http_get(self, url: str, timeout: float) -> str:
        raise Exception("Network down")

    monkeypatch.setattr(PassiveReconAdapter, "_http_get", fake_http_get)

    result = adapter.execute({"domain": "example.com"})

    assert result.status.value == "failure"
    assert result.data["crt_sh"]["count"] == 0
    assert result.data["wayback"]["count"] == 0
    assert "crt_sh" in result.data["errors"] or "wayback" in result.data["errors"]


def test_passive_recon_get_info():
    adapter = create_passive_recon_adapter({})
    info = adapter.get_info()
    assert info["name"] == "PassiveReconAdapter"
    assert "certificate_history" in info["capabilities"]
    assert "archived_url_discovery" in info["capabilities"]


def test_plugin_manager_integration_with_passive_recon(monkeypatch: pytest.MonkeyPatch):
    # Patch class method before loading via PluginManager
    def fake_http_get(self, url: str, timeout: float) -> str:
        if "crt.sh" in url:
            return _crt_json_many()
        if "web.archive.org" in url:
            return _wayback_json_many()
        return "[]"

    monkeypatch.setattr(PassiveReconAdapter, "_http_get", fake_http_get)

    pm = PluginManager()
    pm.discover_adapters()
    assert "passive_recon" in pm.list_available_adapters()

    result = pm.run_adapter("passive_recon", {"domain": "example.com", "max_results": 1})
    assert result.status.value in ("success",)  # with both sources mocked OK
    assert result.data["crt_sh"]["count"] == 1
    assert result.data["wayback"]["count"] == 1
