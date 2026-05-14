"""Dashboard trend analytics service."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.trends import (
    CountBucketRead,
    DailyFindingCountRead,
    DashboardTrendsRead,
)


class DashboardTrendsService:
    """Build dashboard-ready trend analytics from persisted findings."""

    def __init__(self, session: Session) -> None:
        """Initialize the trend service."""
        self.session = session

    def trends(self, days: int = 14) -> DashboardTrendsRead:
        """Return finding trend analytics."""
        findings = self.load_findings()
        recent_findings = self.filter_recent_findings(findings=findings, days=days)

        return DashboardTrendsRead(
            total_findings=len(findings),
            severity_counts=self.count_by_attribute(findings, "severity"),
            category_counts=self.count_by_attribute(findings, "category"),
            source_counts=self.count_by_attribute(findings, "source"),
            daily_findings=self.daily_counts(findings=recent_findings, days=days),
        )

    def load_findings(self) -> list[Finding]:
        """Load findings ordered by newest first."""
        statement: Select[tuple[Finding]] = select(Finding).order_by(Finding.created_at.desc())
        return list(self.session.scalars(statement).all())

    def filter_recent_findings(self, findings: list[Finding], days: int) -> list[Finding]:
        """Return findings created within the requested day window."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days - 1)

        return [
            finding for finding in findings if self.ensure_timezone(finding.created_at) >= cutoff
        ]

    def count_by_attribute(
        self,
        findings: list[Finding],
        attribute: str,
    ) -> list[CountBucketRead]:
        """Count findings by a nullable string attribute."""
        counter: Counter[str] = Counter()

        for finding in findings:
            value = getattr(finding, attribute)
            bucket = str(value) if value else "unknown"
            counter[bucket] += 1

        return [
            CountBucketRead(name=name, count=count)
            for name, count in sorted(
                counter.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]

    def daily_counts(
        self,
        findings: list[Finding],
        days: int,
    ) -> list[DailyFindingCountRead]:
        """Return daily finding counts for the requested window."""
        now = datetime.now(timezone.utc).date()
        dates = [now - timedelta(days=offset) for offset in reversed(range(days))]
        counter: Counter[str] = Counter()

        for finding in findings:
            finding_date = self.ensure_timezone(finding.created_at).date()
            counter[finding_date.isoformat()] += 1

        return [
            DailyFindingCountRead(
                date=date.isoformat(),
                count=counter[date.isoformat()],
            )
            for date in dates
        ]

    def ensure_timezone(self, value: datetime) -> datetime:
        """Ensure a datetime is timezone-aware."""
        if value.tzinfo is not None:
            return value

        return value.replace(tzinfo=timezone.utc)
