"""Schemas for activity timeline responses."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ActivityItemRead(BaseModel):
    """Single activity timeline item."""

    type: str
    entity_id: str
    title: str
    severity: str | None = None
    category: str | None = None
    source: str | None = None
    routing_team: str | None = None
    created_at: datetime


class ActivityTimelineRead(BaseModel):
    """Activity timeline response."""

    items: list[ActivityItemRead] = Field(default_factory=list)
    total: int
    limit: int
