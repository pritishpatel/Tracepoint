"""Pydantic schemas for findings."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from tracepoint.models.finding import FindingSeverity, FindingSource, FindingStatus


class FindingCreate(BaseModel):
    """Request payload for creating a finding."""

    title: str = Field(min_length=5, max_length=300)
    description: str = Field(min_length=10, max_length=50_000)

    source: str = FindingSource.MANUAL
    severity: FindingSeverity = FindingSeverity.UNKNOWN
    status: FindingStatus = FindingStatus.NEW

    category: str | None = Field(default=None, max_length=128)
    affected_asset: str | None = Field(default=None, max_length=512)
    reporter: str | None = Field(default=None, max_length=256)

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class FindingRead(BaseModel):
    """Response payload for a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str

    source: str
    severity: FindingSeverity
    status: FindingStatus

    category: str | None
    affected_asset: str | None
    reporter: str | None

    confidence: float
    created_at: datetime
    updated_at: datetime


class FindingListResponse(BaseModel):
    """Paginated finding list response."""

    items: list[FindingRead]
    total: int
    limit: int
    offset: int


class FindingProvenanceRead(BaseModel):
    """Parsed source/provenance details for a finding."""

    finding_id: str
    title: str
    source: str
    source_dataset: str | None = None
    source_url: str | None = None
    catalog_version: str | None = None
    catalog_release_date: str | None = None
    catalog_total_records: int | None = None
    cve: str | None = None
    cwes: list[str] = Field(default_factory=list)
    vendor_project: str | None = None
    product: str | None = None
    vulnerability: str | None = None
    date_added_to_kev: str | None = None
    due_date: str | None = None
    known_ransomware_use: str | None = None
    notes: str | None = None
    raw: dict[str, str] = Field(default_factory=dict)
