"""Duplicate detection API schemas."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class DuplicateDecision(str, Enum):
    """Possible duplicate detection decisions."""

    LIKELY_DUPLICATE = "likely_duplicate"
    POSSIBLE_DUPLICATE = "possible_duplicate"
    NOT_DUPLICATE = "not_duplicate"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class DuplicateCandidate(BaseModel):
    """A potentially similar historical finding."""

    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    title: str
    category: str | None = None
    affected_asset: str | None = None
    similarity: float = Field(ge=0.0, le=1.0)
    reason: str


class DuplicateCheckRequest(BaseModel):
    """Request body for duplicate detection."""

    title: str = Field(min_length=5, max_length=300)
    description: str = Field(min_length=10, max_length=50_000)
    category: str | None = Field(default=None, max_length=128)
    affected_asset: str | None = Field(default=None, max_length=512)
    top_k: int = Field(default=5, ge=1, le=20)


class DuplicateCheckResponse(BaseModel):
    """Duplicate detection response."""

    decision: DuplicateDecision
    highest_similarity: float = Field(ge=0.0, le=1.0)
    candidates: list[DuplicateCandidate]
    recommendation: str
