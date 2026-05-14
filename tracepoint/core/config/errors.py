"""Configuration exception hierarchy for Tracepoint."""

from __future__ import annotations


class ConfigError(RuntimeError):
    """Base exception for all configuration failures."""


class ConfigFileError(ConfigError):
    """Raised when a configuration file cannot be read or parsed."""


class ConfigEnvError(ConfigError):
    """Raised when an environment-backed configuration value is unavailable."""


class ConfigValidationError(ConfigError):
    """Raised when loaded configuration fails schema validation."""
