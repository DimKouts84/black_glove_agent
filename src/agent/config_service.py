"""
Centralized configuration service for Black Glove.

Single source of truth for loading, saving, masking, and schema export of config.yaml.
Used by CLI, web API, and AgentRuntime.
"""

from __future__ import annotations

import logging
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv

from .models import ConfigModel

logger = logging.getLogger("black_glove.config_service")

MASK_PLACEHOLDER = "__MASKED__"
SECRET_FIELDS = {"llm_api_key", "web_api_token"}


def _deep_merge(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge updates into base dict."""
    result = deepcopy(base)
    for key, value in updates.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def mask_secret(value: Optional[str]) -> Optional[str]:
    """Mask an API key for display: sk-...abcd."""
    if not value:
        return None
    if len(value) <= 8:
        return MASK_PLACEHOLDER
    return f"{value[:4]}...{value[-4:]}"


class ConfigService:
    """Load, save, and validate application configuration."""

    def __init__(self, config_path: Optional[Path] = None):
        load_dotenv()
        self._explicit_path = config_path
        self._cached: Optional[ConfigModel] = None
        self._active_path: Optional[Path] = None

    def resolve_path(self) -> Path:
        """
        Resolve active config path.

        Priority: explicit path > ~/.homepentest/config.yaml (if exists) >
        cwd config.yaml > ~/.homepentest/config.yaml (default for new files).
        Save always goes to canonical home path unless explicit path was set.
        """
        if self._explicit_path:
            return self._explicit_path

        cwd_config = Path.cwd() / "config.yaml"
        home_config = Path.home() / ".homepentest" / "config.yaml"

        if home_config.exists():
            return home_config
        if cwd_config.exists():
            return cwd_config
        return home_config

    def canonical_save_path(self) -> Path:
        """Path used when creating/saving config (always home unless explicit)."""
        if self._explicit_path:
            return self._explicit_path
        return Path.home() / ".homepentest" / "config.yaml"

    def load(self, force_reload: bool = False) -> ConfigModel:
        """Load configuration from disk with in-memory cache."""
        if self._cached is not None and not force_reload:
            return self._cached

        path = self.resolve_path()
        self._active_path = path

        if not path.exists():
            logger.warning("Configuration file not found at %s, using defaults", path)
            self._cached = ConfigModel()
            return self._cached

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                logger.warning("Invalid configuration format at %s", path)
                self._cached = ConfigModel()
                return self._cached
            self._cached = ConfigModel(**data)
            logger.info("Configuration loaded from %s", path)
            return self._cached
        except Exception as exc:
            logger.error("Failed to load config from %s: %s", path, exc)
            self._cached = ConfigModel()
            return self._cached

    def reload(self) -> ConfigModel:
        """Force reload from disk."""
        return self.load(force_reload=True)

    def to_dict(self, masked: bool = False) -> Dict[str, Any]:
        """Export config as dictionary, optionally masking secrets."""
        config = self.load()
        data = config.model_dump()
        if masked:
            return self.to_masked_dict(data)
        return data

    def to_masked_dict(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return config dict with secrets masked."""
        if data is None:
            data = self.load().model_dump()
        result = deepcopy(data)
        for field in SECRET_FIELDS:
            if field in result and result[field]:
                result[field] = mask_secret(str(result[field]))
        return result

    def schema(self) -> List[Dict[str, Any]]:
        """Return field metadata for auto-generating settings forms."""
        fields = []
        for name, field_info in ConfigModel.model_fields.items():
            annotation = field_info.annotation
            type_name = getattr(annotation, "__name__", str(annotation))
            if hasattr(annotation, "__origin__"):
                type_name = str(annotation)
            default = field_info.default
            if default is not None and hasattr(default, "default"):
                default = default.default
            fields.append({
                "name": name,
                "type": type_name,
                "default": default,
                "description": field_info.description or "",
                "required": field_info.is_required(),
                "secret": name in SECRET_FIELDS,
            })
        return fields

    def validate_partial(self, partial: Dict[str, Any]) -> ConfigModel:
        """Validate a partial update merged with current config (no save)."""
        current = self.load().model_dump()
        merged = self._apply_partial(current, partial)
        return ConfigModel(**merged)

    def save(self, partial: Dict[str, Any]) -> ConfigModel:
        """Deep-merge partial update, validate, and atomically write to disk."""
        current = self.load().model_dump()
        merged = self._apply_partial(current, partial)
        config = ConfigModel(**merged)

        save_path = self.canonical_save_path()
        save_path.parent.mkdir(parents=True, exist_ok=True)

        yaml_text = self._to_yaml(config)
        self._atomic_write(save_path, yaml_text)

        self._cached = config
        self._active_path = save_path
        logger.info("Configuration saved to %s", save_path)
        return config

    def setup_defaults(self, config: Optional[ConfigModel] = None) -> Path:
        """Create config file from defaults if it does not exist."""
        save_path = self.canonical_save_path()
        if save_path.exists():
            return save_path
        cfg = config or ConfigModel()
        save_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(save_path, self._to_yaml(cfg))
        self._cached = cfg
        self._active_path = save_path
        return save_path

    def _apply_partial(
        self, current: Dict[str, Any], partial: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge partial update, preserving secrets when mask placeholder sent."""
        merged = _deep_merge(current, partial)
        for field in SECRET_FIELDS:
            if field in partial:
                val = partial[field]
                current_val = current.get(field)
                if val in (None, "", MASK_PLACEHOLDER) or (
                    isinstance(val, str) and val.startswith("...")
                ) or (
                    isinstance(val, str)
                    and current_val
                    and mask_secret(str(current_val)) == val
                ):
                    merged[field] = current_val
        return merged

    def _to_yaml(self, config: ConfigModel) -> str:
        """Serialize config to YAML with header comment."""
        data = config.model_dump()
        header = (
            "# Black Glove Configuration File\n"
            "# Managed by ConfigService - edit via CLI or web UI\n\n"
        )
        return header + yaml.dump(
            data, default_flow_style=False, sort_keys=False, allow_unicode=True
        )

    def _atomic_write(self, path: Path, content: str) -> None:
        """Write file atomically via temp + replace."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent), prefix=".config_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise


# Module-level singleton for convenience
_default_service: Optional[ConfigService] = None


def get_config_service() -> ConfigService:
    """Get or create the default ConfigService singleton."""
    global _default_service
    if _default_service is None:
        _default_service = ConfigService()
    return _default_service
