"""Schemas for persisted triage results."""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracepoint.schemas.triage import TriageResponse


class PersistedTriageResponse(BaseModel):
    """Response returned when a triage result is persisted."""

    triage: TriageResponse
    finding_id: str
    triage_result_id: str


class TriageResultRead(BaseModel):
    """Read schema for a persisted triage result."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str | None

    validity: str
    category: str
    severity: str

    cwe: str | None
    owasp: str | None
    routing_team: str

    confidence: float

    evidence_summary_json: str = Field(exclude=True)
    reproduction_steps_json: str = Field(exclude=True)
    remediation_guidance_json: str = Field(exclude=True)
    human_review_questions_json: str = Field(exclude=True)

    created_at: datetime
    updated_at: datetime

    @property
    def evidence_summary(self) -> list[str]:
        """Return decoded evidence summary."""
        return decode_json_list(self.evidence_summary_json)

    @property
    def reproduction_steps(self) -> list[str]:
        """Return decoded reproduction steps."""
        return decode_json_list(self.reproduction_steps_json)

    @property
    def remediation_guidance(self) -> list[str]:
        """Return decoded remediation guidance."""
        return decode_json_list(self.remediation_guidance_json)

    @property
    def human_review_questions(self) -> list[str]:
        """Return decoded human-review questions."""
        return decode_json_list(self.human_review_questions_json)

    @field_validator(
        "evidence_summary_json",
        "reproduction_steps_json",
        "remediation_guidance_json",
        "human_review_questions_json",
    )
    @classmethod
    def validate_json_list(cls, value: str) -> str:
        """Ensure stored list payloads remain JSON arrays."""
        decoded = json.loads(value)
        if not isinstance(decoded, list):
            raise ValueError("stored triage JSON payload must be a list")
        return value


def encode_json_list(values: list[str]) -> str:
    """Encode a list of strings as stable JSON."""
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def decode_json_list(value: str) -> list[str]:
    """Decode a JSON list of strings."""
    decoded = json.loads(value)
    if not isinstance(decoded, list):
        return []
    return [str(item) for item in decoded]
