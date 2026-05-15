"""Schemas for finding comments."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FindingCommentCreate(BaseModel):
    """Payload for adding an analyst comment to a finding."""

    author: str = Field(min_length=2, max_length=256)
    body: str = Field(min_length=2, max_length=4000)


class FindingCommentRead(BaseModel):
    """Comment returned for a finding."""

    id: str
    finding_id: str
    author: str
    body: str
    created_at: datetime


class FindingCommentListRead(BaseModel):
    """List of comments attached to a finding."""

    finding_id: str
    count: int
    comments: list[FindingCommentRead] = Field(default_factory=list)
