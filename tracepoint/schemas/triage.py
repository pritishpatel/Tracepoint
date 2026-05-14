"""Pydantic schemas for vulnerability triage requests and responses."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class TriageValidity(str, Enum):
    """Possible validity decisions for an incoming security report."""

    LIKELY_VALID = "likely_valid"
    DUPLICATE = "duplicate"
    SPAM = "spam"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class TriageSeverity(str, Enum):
    """Supported triage severity levels."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityCategory(str, Enum):
    """Supported vulnerability categories.

    The exposed-secret value is a classification label, not a credential.
    """

    UNKNOWN = "unknown"
    IDOR = "idor"
    XSS = "xss"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    EXPOSED_SECRET = "exposed_secret"  # nosec B105
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    SUSPICIOUS_AUTHENTICATION = "suspicious_authentication"


class TriageRequest(BaseModel):
    """Incoming vulnerability report submitted for first-pass triage."""

    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(..., min_length=5, max_length=300)
    description: str = Field(..., min_length=10, max_length=50_000)
    source: str = Field(default="manual", min_length=3, max_length=64)
    affected_asset: str | None = Field(default=None, max_length=512)
    reporter: str | None = Field(default=None, max_length=256)


class TriageResponse(BaseModel):
    """Structured deterministic triage result returned to API clients."""

    validity: TriageValidity
    category: VulnerabilityCategory
    severity: TriageSeverity

    cwe: str | None
    owasp: str | None
    affected_asset: str | None

    reproduction_steps: list[str]
    evidence_summary: list[str]
    routing_team: str
    remediation_guidance: list[str]
    human_review_questions: list[str]

    confidence: float = Field(ge=0.0, le=1.0)
