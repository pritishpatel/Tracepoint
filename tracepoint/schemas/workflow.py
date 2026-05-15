"""Schemas for analyst workflow actions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

ALLOWED_FINDING_STATUSES = {
    "new",
    "triaged",
    "in_progress",
    "resolved",
    "false_positive",
    "duplicate",
    "accepted_risk",
}


class FindingStatusUpdate(BaseModel):
    """Request payload for updating a finding workflow status."""

    status: str = Field(min_length=2, max_length=64)
    note: str | None = Field(default=None, max_length=1000)


class FindingWorkflowRead(BaseModel):
    """Finding workflow update response."""

    finding_id: str
    title: str
    previous_status: str
    status: str
    note: str | None = None
    changed: bool

    model_config = ConfigDict(use_enum_values=True)
