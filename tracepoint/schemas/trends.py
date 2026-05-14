"""Schemas for dashboard trend analytics."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CountBucketRead(BaseModel):
    """Named count bucket."""

    name: str
    count: int


class DailyFindingCountRead(BaseModel):
    """Daily finding count bucket."""

    date: str
    count: int


class DashboardTrendsRead(BaseModel):
    """Dashboard trend analytics response."""

    total_findings: int
    severity_counts: list[CountBucketRead] = Field(default_factory=list)
    category_counts: list[CountBucketRead] = Field(default_factory=list)
    source_counts: list[CountBucketRead] = Field(default_factory=list)
    daily_findings: list[DailyFindingCountRead] = Field(default_factory=list)
