"""Dashboard summary service."""

from __future__ import annotations

from sqlalchemy import Select, func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from tracepoint.models.finding import Finding
from tracepoint.models.triage_result import TriageResult
from tracepoint.schemas.dashboard import (
    DashboardCountItem,
    DashboardRecentFinding,
    DashboardSummaryRead,
)


class DashboardService:
    """Build dashboard summaries from persisted security workflow data."""

    def __init__(self, session: Session) -> None:
        """Initialize the dashboard service."""
        self.session = session

    def summary(self) -> DashboardSummaryRead:
        """Return a high-level dashboard summary."""
        return DashboardSummaryRead(
            total_findings=self.count_findings(),
            open_findings=self.count_open_findings(),
            triage_results=self.count_triage_results(),
            high_severity_findings=self.count_high_severity_findings(),
            by_severity=self.count_by_field(Finding.severity),
            by_status=self.count_by_field(Finding.status),
            by_source=self.count_by_field(Finding.source),
            by_category=self.count_by_field(Finding.category),
            recent_findings=self.recent_findings(),
        )

    def count_findings(self) -> int:
        """Return total finding count."""
        statement = select(func.count(Finding.id))
        return int(self.session.scalar(statement) or 0)

    def count_open_findings(self) -> int:
        """Return count of findings that are not closed."""
        statement = select(func.count(Finding.id)).where(Finding.status != "closed")
        return int(self.session.scalar(statement) or 0)

    def count_triage_results(self) -> int:
        """Return persisted triage-result count."""
        statement = select(func.count(TriageResult.id))
        return int(self.session.scalar(statement) or 0)

    def count_high_severity_findings(self) -> int:
        """Return high and critical severity finding count."""
        statement = select(func.count(Finding.id)).where(Finding.severity.in_(["high", "critical"]))
        return int(self.session.scalar(statement) or 0)

    def count_by_field(self, field: InstrumentedAttribute[str | None]) -> list[DashboardCountItem]:
        """Return aggregate counts for a Finding model field."""
        statement = (
            select(field, func.count(Finding.id))
            .group_by(field)
            .order_by(func.count(Finding.id).desc())
        )
        rows = self.session.execute(statement).all()

        return [
            DashboardCountItem(name=str(name or "unknown"), count=int(count))
            for name, count in rows
        ]

    def recent_findings(self, limit: int = 5) -> list[DashboardRecentFinding]:
        """Return recent findings ordered by creation time."""
        statement: Select[tuple[Finding]] = (
            select(Finding).order_by(Finding.created_at.desc()).limit(limit)
        )
        findings = self.session.scalars(statement).all()

        return [
            DashboardRecentFinding(
                id=finding.id,
                title=finding.title,
                severity=finding.severity,
                status=finding.status,
                source=finding.source,
                category=finding.category,
                affected_asset=finding.affected_asset,
                created_at=finding.created_at.isoformat(),
            )
            for finding in findings
        ]
