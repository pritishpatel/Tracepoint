"""Schemas for export workflows."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExportFindingRead(BaseModel):
    """Finding record included in export responses."""

    id: str
    title: str
    description: str
    source: str
    severity: str
    status: str
    category: str | None = None
    affected_asset: str | None = None
    reporter: str | None = None
    confidence: float
    created_at: str
    updated_at: str


class ExportSummaryRead(BaseModel):
    """Structured export response."""

    format: str
    count: int
    records: list[ExportFindingRead] = Field(default_factory=list)
    content: str | None = None
