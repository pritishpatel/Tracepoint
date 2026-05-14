"""Evidence bundle API schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceBundleCreate(BaseModel):
    """Request payload for generating a finding evidence bundle."""

    include_triage: bool = Field(
        default=True,
        description="Include the latest persisted triage result when available.",
    )
    include_markdown: bool = Field(
        default=True,
        description="Generate a Markdown evidence artifact.",
    )
    include_json: bool = Field(
        default=True,
        description="Generate a JSON evidence artifact.",
    )


class EvidenceArtifact(BaseModel):
    """Single generated evidence artifact."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Artifact filename.",
    )
    content_type: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Artifact media type.",
    )
    content: str = Field(
        ...,
        min_length=1,
        description="Generated artifact content.",
    )


class EvidenceBundleRead(BaseModel):
    """Response payload for a generated evidence bundle."""

    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    generated_at: datetime
    artifact_count: int
    included_triage: bool
    markdown_path: str | None
    json_path: str | None
    artifacts: list[EvidenceArtifact]
