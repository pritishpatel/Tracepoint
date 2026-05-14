"""Typed configuration schema for Tracepoint.

This module defines the validated runtime settings contract for the application.
The YAML loader returns plain dictionaries; this schema turns those dictionaries
into immutable, typed configuration objects used by the rest of the codebase.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model for all configuration sections.

    Unknown keys are rejected so configuration drift is detected early instead
    of silently being ignored at runtime.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class ServiceConfig(StrictModel):
    """Service identity and deployment environment."""

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    env: Literal["local", "test", "staging", "production"]


class RuntimeConfig(StrictModel):
    """Process-level runtime behavior."""

    debug: bool
    timezone: str = Field(min_length=1)


class DocsConfig(StrictModel):
    """OpenAPI and interactive documentation routes."""

    enabled: bool
    swagger: str
    redoc: str
    openapi: str


class CorsConfig(StrictModel):
    """CORS policy for browser-based clients."""

    enabled: bool
    origins: list[str]


class ServerLimitsConfig(StrictModel):
    """HTTP request and pagination limits."""

    timeout_s: int = Field(gt=0)
    body_mb: int = Field(gt=0)
    page: int = Field(gt=0)
    max_page: int = Field(gt=0)

    @model_validator(mode="after")
    def page_size_must_not_exceed_maximum(self) -> "ServerLimitsConfig":
        if self.page > self.max_page:
            raise ValueError("server.limits.page cannot exceed server.limits.max_page")
        return self


class ServerConfig(StrictModel):
    """API server configuration."""

    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    reload: bool
    prefix: str
    docs: DocsConfig
    cors: CorsConfig
    limits: ServerLimitsConfig


class DatabaseConfig(StrictModel):
    """Database connection and migration settings."""

    url: str = Field(min_length=1)
    echo: bool
    pre_ping: bool
    migrate: bool

    @model_validator(mode="after")
    def database_url_must_be_supported(self) -> "DatabaseConfig":
        supported_prefixes = (
            "sqlite:///",
            "postgresql://",
            "postgresql+psycopg://",
            "postgresql+psycopg2://",
        )

        if not self.url.startswith(supported_prefixes):
            raise ValueError("db.url must be sqlite or postgresql compatible")

        return self


class PathsConfig(StrictModel):
    """Local filesystem paths used by the application."""

    base: str
    cache: str
    evidence: str
    vectors: str


class LogConfig(StrictModel):
    """Application logging behavior."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    format: Literal["console", "json"]
    redact: bool
    requests: bool
    audit: bool


class SecurityConfig(StrictModel):
    """Global security policy switches and protected actions."""

    redact_secrets: bool
    redact_pii: bool
    approval: list[str]
    block: list[str]


class LLMConfig(StrictModel):
    """Single active LLM provider configuration.

    The committed config stores the environment variable name that contains the
    secret, not the secret value itself. Users switch providers by editing this
    single section instead of maintaining a separate provider catalogue.
    """

    enabled: bool
    provider: Literal["openai", "gemini", "anthropic", "xai", "kimi", "compatible"]
    model: str = Field(min_length=1)
    api_key_env: str = Field(min_length=1)
    base_url: str | None
    temperature: float = Field(ge=0.0, le=2.0)
    max_tokens: int = Field(gt=0)
    timeout_s: int = Field(gt=0)
    json_output: bool
    retries: int = Field(ge=0, le=5)
    redact_input: bool
    store_prompt_hash: bool
    store_raw_prompts: bool
    store_outputs: bool

    @model_validator(mode="after")
    def raw_prompt_storage_requires_redaction(self) -> "LLMConfig":
        if self.store_raw_prompts and not self.redact_input:
            raise ValueError("raw prompt storage requires input redaction")
        return self


class GuardrailsConfig(StrictModel):
    """AI guardrail and redaction behavior."""

    enabled: bool
    prompt_injection: Literal["off", "warn", "quarantine", "block"]
    min_confidence: float = Field(ge=0.0, le=1.0)
    secret_token: str
    pii_token: str
    case_boundary: bool


class IntakeConfig(StrictModel):
    """Finding intake source and text validation settings."""

    sources: list[str]
    title_min: int = Field(gt=0)
    title_max: int = Field(gt=0)
    report_min: int = Field(gt=0)
    report_max: int = Field(gt=0)

    @model_validator(mode="after")
    def minimum_lengths_must_not_exceed_maximums(self) -> "IntakeConfig":
        if self.title_min > self.title_max:
            raise ValueError("intake.title_min cannot exceed intake.title_max")
        if self.report_min > self.report_max:
            raise ValueError("intake.report_min cannot exceed intake.report_max")
        return self


class ConfidenceConfig(StrictModel):
    """Triage confidence thresholds."""

    accept: float = Field(ge=0.0, le=1.0)
    review: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def review_threshold_must_not_exceed_accept_threshold(self) -> "ConfidenceConfig":
        if self.review > self.accept:
            raise ValueError("triage.confidence.review cannot exceed triage.confidence.accept")
        return self


class DuplicateConfig(StrictModel):
    """Duplicate detection thresholds."""

    enabled: bool
    top_k: int = Field(gt=0)
    threshold: float = Field(ge=0.0, le=1.0)


class EnumListConfig(StrictModel):
    """Allowed enum-style values with a selected default or initial value."""

    default: str | None = None
    initial: str | None = None
    values: list[str]

    @model_validator(mode="after")
    def selected_value_must_be_allowed(self) -> "EnumListConfig":
        selected_value = self.default if self.default is not None else self.initial

        if selected_value is not None and selected_value not in self.values:
            raise ValueError(f"selected value '{selected_value}' is not allowed")

        return self


class TriageConfig(StrictModel):
    """Triage engine behavior and allowed workflow values."""

    auto: bool
    rules: bool
    confidence: ConfidenceConfig
    duplicates: DuplicateConfig
    severity: EnumListConfig
    status: EnumListConfig


class RiskConfig(StrictModel):
    """Weighted risk scoring configuration."""

    enabled: bool
    weights: dict[str, float]

    @model_validator(mode="after")
    def weights_must_sum_to_one(self) -> "RiskConfig":
        total_weight = sum(self.weights.values())

        if abs(total_weight - 1.0) > 0.001:
            raise ValueError("risk.weights must sum to 1.0")

        return self


class SLAConfig(StrictModel):
    """Severity-based remediation service-level targets."""

    critical: str
    high: str
    medium: str
    low: str


class InvestigationConfig(StrictModel):
    """Investigation enrichment settings and log source locations."""

    enabled: bool
    window_min: int = Field(gt=0)
    max_window_h: int = Field(gt=0)
    logs: dict[str, str]


class RemediationConfig(StrictModel):
    """Remediation workflow defaults."""

    enabled: bool
    recommend: bool
    require_retest: bool
    require_approval: bool
    owner: str = Field(min_length=1)


class EvidenceConfig(StrictModel):
    """Evidence generation settings."""

    enabled: bool
    path: str
    markdown: bool
    json_output: bool
    pdf: bool


class EmbeddingsConfig(StrictModel):
    """Embedding model settings for duplicate detection and retrieval."""

    enabled: bool
    model: str = Field(min_length=1)
    dim: int = Field(gt=0)
    normalize: bool
    batch: int = Field(gt=0)


class VectorsConfig(StrictModel):
    """Vector store configuration."""

    provider: Literal["faiss", "memory", "pgvector"]
    path: str | None


class DataConfig(StrictModel):
    """Demo and evaluation data paths."""

    seed: bool
    findings: str
    history: str
    services: str


class DevConfig(StrictModel):
    """Local developer behavior."""

    mock_llm: bool
    mock_integrations: bool
    debug_routes: bool


class Settings(StrictModel):
    """Fully validated application settings."""

    service: ServiceConfig
    runtime: RuntimeConfig
    server: ServerConfig
    db: DatabaseConfig
    paths: PathsConfig
    log: LogConfig
    security: SecurityConfig
    llm: LLMConfig
    guardrails: GuardrailsConfig
    intake: IntakeConfig
    triage: TriageConfig
    risk: RiskConfig
    sla: SLAConfig
    investigation: InvestigationConfig
    remediation: RemediationConfig
    evidence: EvidenceConfig
    embeddings: EmbeddingsConfig
    vectors: VectorsConfig
    data: DataConfig
    dev: DevConfig

    def redacted(self) -> dict[str, Any]:
        settings_data = self.model_dump()
        settings_data["llm"]["api_key_env"] = "[REDACTED_ENV_NAME]"
        return settings_data
