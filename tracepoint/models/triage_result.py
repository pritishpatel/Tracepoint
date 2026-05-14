"""Triage result ORM model."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tracepoint.db.base import Base
from tracepoint.models.base import TimestampMixin

if TYPE_CHECKING:
    from tracepoint.models.finding import Finding


def generate_uuid() -> str:
    """Return a UUID string for primary keys."""
    return str(uuid.uuid4())


class TriageResult(TimestampMixin, Base):
    """Persisted output from the deterministic triage engine."""

    __tablename__ = "triage_results"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    validity: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    owasp: Mapped[str | None] = mapped_column(String(256), nullable=True)
    routing_team: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    evidence_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    reproduction_steps_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    remediation_guidance_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    human_review_questions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    finding: Mapped[Finding | None] = relationship("Finding")
