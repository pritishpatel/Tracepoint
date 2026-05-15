"""Schemas for bulk finding imports."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FindingImportItemCreate(BaseModel):
    """Single imported finding-like report."""

    title: str = Field(min_length=5, max_length=300)
    description: str = Field(min_length=10)
    source: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=64)
    category: str | None = Field(default=None, max_length=128)
    affected_asset: str | None = Field(default=None, max_length=512)
    reporter: str | None = Field(default=None, max_length=256)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class FindingImportCreate(BaseModel):
    """Bulk import payload for finding-like reports."""

    source: str = Field(default="bulk_import", min_length=2, max_length=64)
    persist: bool = True
    check_duplicates: bool = True
    items: list[FindingImportItemCreate] = Field(min_length=1, max_length=500)


class FindingImportFailureRead(BaseModel):
    """Failure record for a skipped imported item."""

    index: int
    title: str | None = None
    reason: str


class FindingImportItemRead(BaseModel):
    """Result for one imported item."""

    index: int
    title: str
    finding_id: str | None = None
    triage_result_id: str | None = None
    persisted: bool
    duplicate_decision: str
    duplicate_score: float
    category: str
    severity: str


class FindingImportSummaryRead(BaseModel):
    """Bulk import result summary."""

    received: int
    created: int
    duplicates: int
    failed: int
    results: list[FindingImportItemRead] = Field(default_factory=list)
    failures: list[FindingImportFailureRead] = Field(default_factory=list)
