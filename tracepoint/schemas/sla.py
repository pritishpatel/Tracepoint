"""Schemas for SLA and remediation timeline responses."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FindingSlaRead(BaseModel):
    """SLA timeline returned for a finding."""

    finding_id: str
    title: str
    priority: str
    risk_level: str
    risk_score: float = Field(ge=0.0, le=100.0)
    sla_hours: int = Field(gt=0)
    created_at: datetime
    due_at: datetime
    is_overdue: bool
    escalation_required: bool
    recommendation: str
