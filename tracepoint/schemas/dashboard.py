"""Schemas for dashboard summary responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DashboardCountItem(BaseModel):
    """Named count item used in dashboard aggregates."""

    name: str
    count: int


class DashboardRecentFinding(BaseModel):
    """Recent finding summary for dashboard views."""

    id: str
    title: str
    severity: str
    status: str
    source: str
    category: str | None = None
    affected_asset: str | None = None
    created_at: str


class DashboardSummaryRead(BaseModel):
    """High-level operational dashboard summary."""

    total_findings: int
    open_findings: int
    triage_results: int
    high_severity_findings: int
    by_severity: list[DashboardCountItem] = Field(default_factory=list)
    by_status: list[DashboardCountItem] = Field(default_factory=list)
    by_source: list[DashboardCountItem] = Field(default_factory=list)
    by_category: list[DashboardCountItem] = Field(default_factory=list)
    recent_findings: list[DashboardRecentFinding] = Field(default_factory=list)
