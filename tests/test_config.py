"""Configuration loading tests."""

from __future__ import annotations

from pytest import MonkeyPatch
from tracepoint.core.config import clear_settings_cache, get_settings


def test_base_config_loads_successfully() -> None:
    clear_settings_cache()
    settings = get_settings()

    assert settings.service.name == "tracepoint-api"
    assert settings.service.env == "local"
    assert settings.llm.provider == "openai"
    assert settings.llm.model == "gpt-5-nano"
    assert settings.llm.api_key_env == "OPENAI_API_KEY"


def test_llm_model_can_be_overridden(monkeypatch: MonkeyPatch) -> None:
    clear_settings_cache()
    monkeypatch.setenv("TRACEPOINT_LLM_MODEL", "gpt-5-mini")
    settings = get_settings()

    assert settings.llm.model == "gpt-5-mini"
    clear_settings_cache()
