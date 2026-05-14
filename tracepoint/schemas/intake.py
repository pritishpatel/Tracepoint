"""Schemas for report intake workflows."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class HasValue(Protocol):
    """Protocol for enum-like values."""

    value: str


def enum_value(value: str | HasValue) -> str:
    """Return the raw enum value when present, otherwise a string value."""
    if isinstance(value, str):
        return value
    return value.value


class IntakeReportCreate(BaseModel):
    """Incoming security report payload for the intake workflow."""

    title: str = Field(min_length=5, max_length=300)
    description: str = Field(min_length=10)
    source: str = Field(min_length=2, max_length=64)
    category: str | None = Field(default=None, max_length=128)
    affected_asset: str | None = Field(default=None, max_length=512)
    reporter: str | None = Field(default=None, max_length=256)
    persist: bool = True
    check_duplicates: bool = True


class IntakeTriageRead(BaseModel):
    """Triage summary returned from intake."""

    validity: str
    category: str
    severity: str
    cwe: str | None = None
    owasp: str | None = None
    routing_team: str
    confidence: float
    evidence_summary: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    remediation_guidance: list[str] = Field(default_factory=list)
    human_review_questions: list[str] = Field(default_factory=list)

    model_config = ConfigDict(use_enum_values=True)


class IntakeDuplicateRead(BaseModel):
    """Duplicate-detection summary returned from intake."""

    decision: str
    highest_similarity: float
    matched_finding_id: str | None = None
    matched_finding_title: str | None = None
    reasons: list[str] = Field(default_factory=list)
    is_duplicate: bool = False
    score: float = 0.0
    finding_id: str | None = None
    title: str | None = None

    model_config = ConfigDict(use_enum_values=True)


class IntakeReportRead(BaseModel):
    """Response returned after report intake."""

    finding_id: str | None = None
    triage_result_id: str | None = None
    persisted: bool
    triage: IntakeTriageRead
    duplicate: IntakeDuplicateRead

    model_config = ConfigDict(use_enum_values=True)
