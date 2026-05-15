"""Schemas for finding risk scoring."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskFactorRead(BaseModel):
    """Single risk factor contribution."""

    name: str
    value: str
    weight: float
    contribution: float


class FindingRiskRead(BaseModel):
    """Risk score returned for a finding."""

    finding_id: str
    title: str
    severity: str
    category: str | None = None
    affected_asset: str | None = None
    confidence: float
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: str
    priority: str
    factors: list[RiskFactorRead] = Field(default_factory=list)
    recommendation: str
