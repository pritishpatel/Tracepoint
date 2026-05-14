"""Activity timeline service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.models.triage_result import TriageResult
from tracepoint.schemas.activity import ActivityItemRead, ActivityTimelineRead


@dataclass(frozen=True)
class ActivityRecord:
    """Internal activity timeline record."""

    type: str
    entity_id: str
    title: str
    created_at: datetime
    severity: str | None = None
    category: str | None = None
    source: str | None = None
    routing_team: str | None = None

    def to_read_model(self) -> ActivityItemRead:
        """Convert the internal record to an API schema."""
        return ActivityItemRead(
            type=self.type,
            entity_id=self.entity_id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            source=self.source,
            routing_team=self.routing_team,
            created_at=self.created_at,
        )


class ActivityService:
    """Build a recent activity timeline from persisted records."""

    def __init__(self, session: Session) -> None:
        """Initialize the activity service."""
        self.session = session

    def timeline(self, limit: int = 20) -> ActivityTimelineRead:
        """Return recent product activity."""
        records = [
            *self.finding_activity(limit=limit),
            *self.triage_activity(limit=limit),
        ]

        sorted_records = sorted(
            records,
            key=lambda record: record.created_at,
            reverse=True,
        )
        limited_records = sorted_records[:limit]

        return ActivityTimelineRead(
            items=[record.to_read_model() for record in limited_records],
            total=len(limited_records),
            limit=limit,
        )

    def finding_activity(self, limit: int) -> list[ActivityRecord]:
        """Return finding-created activity."""
        statement: Select[tuple[Finding]] = (
            select(Finding).order_by(Finding.created_at.desc()).limit(limit)
        )

        findings = self.session.scalars(statement).all()

        return [
            ActivityRecord(
                type="finding_created",
                entity_id=finding.id,
                title=finding.title,
                severity=finding.severity,
                category=finding.category,
                source=finding.source,
                created_at=finding.created_at,
            )
            for finding in findings
        ]

    def triage_activity(self, limit: int) -> list[ActivityRecord]:
        """Return triage-completed activity."""
        statement: Select[tuple[TriageResult]] = (
            select(TriageResult).order_by(TriageResult.created_at.desc()).limit(limit)
        )

        triage_results = self.session.scalars(statement).all()

        return [
            ActivityRecord(
                type="triage_completed",
                entity_id=triage_result.id,
                title=f"Triage result for finding {triage_result.finding_id}",
                severity=triage_result.severity,
                category=triage_result.category,
                routing_team=triage_result.routing_team,
                created_at=triage_result.created_at,
            )
            for triage_result in triage_results
        ]
