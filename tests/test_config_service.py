"""Tests for ConfigService."""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, "src")

from agent.config_service import ConfigService, MASK_PLACEHOLDER, mask_secret
from agent.models import ConfigModel


@pytest.fixture
def temp_config_dir(tmp_path, monkeypatch):
    """Use isolated home directory for config tests."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(tmp_path)
    return home


class TestConfigService:
    def test_load_defaults_when_missing(self, temp_config_dir):
        svc = ConfigService()
        config = svc.load()
        assert isinstance(config, ConfigModel)
        assert config.llm_provider == "lmstudio"

    def test_round_trip_save_load(self, temp_config_dir):
        svc = ConfigService()
        svc.save({
            "llm_provider": "openrouter",
            "llm_model": "test-model",
            "llm_api_key": "sk-secret-key-12345",
            "adapters": {"nmap": {"timeout": 600}},
        })
        reloaded = svc.reload()
        assert reloaded.llm_provider == "openrouter"
        assert reloaded.llm_model == "test-model"
        assert reloaded.llm_api_key == "sk-secret-key-12345"
        assert reloaded.adapters["nmap"]["timeout"] == 600

    def test_atomic_write_creates_file(self, temp_config_dir):
        svc = ConfigService()
        path = svc.setup_defaults()
        assert path.exists()
        data = yaml.safe_load(path.read_text())
        assert "llm_provider" in data

    def test_mask_secret(self):
        assert mask_secret("sk-or-v1-abcdefgh1234") == "sk-o...1234"
        assert mask_secret(None) is None
        masked = ConfigService().to_masked_dict({
            "llm_api_key": "sk-secret-key-12345",
            "llm_provider": "openrouter",
        })
        assert masked["llm_api_key"] != "sk-secret-key-12345"
        assert masked["llm_provider"] == "openrouter"

    def test_merge_preserves_api_key_on_mask_placeholder(self, temp_config_dir):
        svc = ConfigService()
        svc.save({"llm_api_key": "sk-real-key-abcdef"})
        updated = svc.save({"llm_api_key": MASK_PLACEHOLDER, "llm_model": "new-model"})
        assert updated.llm_api_key == "sk-real-key-abcdef"
        assert updated.llm_model == "new-model"

    def test_schema_returns_fields(self, temp_config_dir):
        svc = ConfigService()
        schema = svc.schema()
        names = {f["name"] for f in schema}
        assert "llm_provider" in names
        assert "require_approval" in names
        assert "adapters" in names

    def test_validate_partial(self, temp_config_dir):
        svc = ConfigService()
        svc.save({"llm_model": "original"})
        result = svc.validate_partial({"llm_model": "updated"})
        assert result.llm_model == "updated"

    def test_cwd_override_for_load(self, temp_config_dir, tmp_path):
        cwd_config = tmp_path / "config.yaml"
        cwd_config.write_text("llm_provider: ollama\nllm_model: llama\n")
        svc = ConfigService()
        config = svc.load(force_reload=True)
        assert config.llm_provider == "ollama"

    def test_home_prefers_over_cwd_for_load(self, temp_config_dir, tmp_path):
        home_config = temp_config_dir / ".homepentest" / "config.yaml"
        home_config.parent.mkdir(parents=True)
        home_config.write_text("llm_provider: openrouter\nllm_model: home-model\n")
        cwd_config = tmp_path / "config.yaml"
        cwd_config.write_text("llm_provider: ollama\nllm_model: cwd-model\n")
        svc = ConfigService()
        config = svc.load(force_reload=True)
        assert config.llm_provider == "openrouter"
        assert config.llm_model == "home-model"

    def test_save_then_reload_with_cwd_present(self, temp_config_dir, tmp_path):
        cwd_config = tmp_path / "config.yaml"
        cwd_config.write_text("llm_provider: ollama\nllm_model: llama\n")
        svc = ConfigService()
        svc.save({"llm_model": "updated-model"})
        reloaded = svc.reload()
        assert reloaded.llm_model == "updated-model"
        assert reloaded.llm_provider == "ollama"
        home_config = temp_config_dir / ".homepentest" / "config.yaml"
        assert home_config.exists()

    def test_merge_preserves_api_key_on_masked_display(self, temp_config_dir):
        svc = ConfigService()
        svc.save({"llm_api_key": "sk-or-v1-abcdefgh1234"})
        masked = mask_secret("sk-or-v1-abcdefgh1234")
        updated = svc.save({"llm_api_key": masked, "llm_model": "new-model"})
        assert updated.llm_api_key == "sk-or-v1-abcdefgh1234"
        assert updated.llm_model == "new-model"
