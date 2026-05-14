"""Configuration loading for Tracepoint.

The loader is intentionally the only module that knows how configuration files
are discovered, merged, overridden by environment variables, and validated.
Everything else imports typed Settings through get_settings().
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import ValidationError

from tracepoint.core.config.errors import ConfigEnvError, ConfigFileError, ConfigValidationError
from tracepoint.core.config.schema import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONFIG_DIRECTORY = PROJECT_ROOT / "config"
ENVIRONMENT_PLACEHOLDER = re.compile(r"\$\{([A-Z0-9_]+)\}")

CONFIG_ENVIRONMENT_OVERRIDES: Mapping[str, str] = {
    "TRACEPOINT_ENV": "service.env",
    "TRACEPOINT_DEBUG": "runtime.debug",
    "TRACEPOINT_HOST": "server.host",
    "TRACEPOINT_PORT": "server.port",
    "TRACEPOINT_DB_URL": "db.url",
    "TRACEPOINT_LOG_LEVEL": "log.level",
    "TRACEPOINT_LLM_ENABLED": "llm.enabled",
    "TRACEPOINT_LLM_PROVIDER": "llm.provider",
    "TRACEPOINT_LLM_MODEL": "llm.model",
    "TRACEPOINT_LLM_API_KEY_ENV": "llm.api_key_env",
    "TRACEPOINT_LLM_BASE_URL": "llm.base_url",
}


class ConfigLoader:
    """Load layered YAML configuration and validate it as Tracepoint settings."""

    def __init__(self, config_directory: Path = CONFIG_DIRECTORY) -> None:
        self.config_directory = config_directory

    def load_settings(self, environment: str | None = None) -> Settings:
        """Return validated settings for the selected environment."""
        config_data = self.load_config_data(environment=environment)

        try:
            return Settings.model_validate(config_data)
        except ValidationError as exc:
            raise ConfigValidationError(str(exc)) from exc

    def load_config_data(self, environment: str | None = None) -> dict[str, Any]:
        """Return merged configuration data before schema validation."""
        active_environment = environment or os.getenv("TRACEPOINT_ENV", "local")

        config_data = self.read_yaml_mapping("config.yaml")
        config_data = self.merge_config_layers(
            config_data,
            self.read_yaml_mapping(f"config.{active_environment}.yaml"),
        )

        if active_environment == "local":
            config_data = self.merge_config_layers(
                config_data,
                self.read_yaml_mapping("config.local.yaml"),
            )

        config_data = self.apply_environment_overrides(config_data)
        resolved_config = self.resolve_environment_placeholders(config_data)

        if not isinstance(resolved_config, dict):
            raise ConfigValidationError("Resolved configuration must be a mapping")

        return cast(dict[str, Any], resolved_config)

    def read_yaml_mapping(self, file_name: str) -> dict[str, Any]:
        """Read a YAML mapping from the configured config directory."""
        file_path = self.config_directory / file_name

        if not file_path.exists():
            return {}

        try:
            with file_path.open("r", encoding="utf-8") as config_file:
                loaded_config = yaml.safe_load(config_file)
        except yaml.YAMLError as exc:
            raise ConfigFileError(f"Invalid YAML in config file: {file_path}") from exc
        except OSError as exc:
            raise ConfigFileError(f"Unable to read config file: {file_path}") from exc

        if loaded_config is None:
            return {}

        if not isinstance(loaded_config, dict):
            raise ConfigFileError(f"Config file must contain a YAML mapping: {file_path}")

        return cast(dict[str, Any], loaded_config)

    def merge_config_layers(
        self,
        base_config: Mapping[str, Any],
        override_config: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Recursively merge an override config layer into a base config layer."""
        merged_config = deepcopy(dict(base_config))

        for config_key, override_value in override_config.items():
            current_value = merged_config.get(config_key)

            if isinstance(current_value, dict) and isinstance(override_value, Mapping):
                merged_config[config_key] = self.merge_config_layers(current_value, override_value)
            else:
                merged_config[config_key] = deepcopy(override_value)

        return merged_config

    def apply_environment_overrides(self, config_data: dict[str, Any]) -> dict[str, Any]:
        """Apply explicitly allow-listed environment variable overrides."""
        config_with_overrides = deepcopy(config_data)

        for variable_name, config_path in CONFIG_ENVIRONMENT_OVERRIDES.items():
            variable_value = os.getenv(variable_name)

            if variable_value is None:
                continue

            self.set_value_at_path(
                config_with_overrides,
                config_path,
                self.parse_scalar_value(variable_value),
            )

        return config_with_overrides

    def set_value_at_path(self, config_data: dict[str, Any], config_path: str, value: Any) -> None:
        """Set a nested dictionary value using a dotted path."""
        current_section = config_data
        path_parts = config_path.split(".")

        for path_part in path_parts[:-1]:
            next_section = current_section.setdefault(path_part, {})

            if not isinstance(next_section, dict):
                raise ConfigValidationError(f"Cannot set nested config path: {config_path}")

            current_section = next_section

        current_section[path_parts[-1]] = value

    def resolve_environment_placeholders(self, value: Any) -> Any:
        """Resolve `${ENVIRONMENT_VARIABLE}` placeholders inside config values."""
        if isinstance(value, dict):
            return {key: self.resolve_environment_placeholders(item) for key, item in value.items()}

        if isinstance(value, list):
            return [self.resolve_environment_placeholders(item) for item in value]

        if not isinstance(value, str):
            return value

        def resolve_match(match: re.Match[str]) -> str:
            variable_name = match.group(1)
            variable_value = os.getenv(variable_name)

            if variable_value is None:
                raise ConfigEnvError(f"Missing required environment variable: {variable_name}")

            return variable_value

        return ENVIRONMENT_PLACEHOLDER.sub(resolve_match, value)

    @staticmethod
    def parse_scalar_value(value: str) -> Any:
        """Convert an environment variable string to a simple scalar value."""
        normalized_value = value.strip().lower()

        if normalized_value in {"true", "false"}:
            return normalized_value == "true"

        if normalized_value in {"none", "null"}:
            return None

        try:
            return int(value)
        except ValueError:
            pass

        try:
            return float(value)
        except ValueError:
            return value


@lru_cache(maxsize=8)
def get_settings(environment: str | None = None) -> Settings:
    """Return cached validated settings for the selected environment."""
    return ConfigLoader().load_settings(environment=environment)


def load_raw_config(environment: str | None = None) -> dict[str, Any]:
    """Return merged raw configuration for diagnostics and tests."""
    return ConfigLoader().load_config_data(environment=environment)


def clear_settings_cache() -> None:
    """Clear the settings cache, mainly for tests that mutate environment values."""
    get_settings.cache_clear()
