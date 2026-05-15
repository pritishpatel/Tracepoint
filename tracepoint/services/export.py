"""Finding export service."""

from __future__ import annotations

import csv
import io

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.export import ExportFindingRead, ExportSummaryRead


class FindingExportService:
    """Export persisted findings into integration-friendly formats."""

    def __init__(self, session: Session) -> None:
        """Initialize the export service."""
        self.session = session

    def export(self, export_format: str = "json") -> ExportSummaryRead:
        """Export findings as JSON-shaped records or CSV content."""
        findings = self.load_findings()
        records = [self.to_read_model(finding) for finding in findings]

        if export_format == "csv":
            return ExportSummaryRead(
                format="csv",
                count=len(records),
                records=[],
                content=self.to_csv(records),
            )

        return ExportSummaryRead(
            format="json",
            count=len(records),
            records=records,
            content=None,
        )

    def load_findings(self) -> list[Finding]:
        """Load all findings ordered by newest first."""
        statement: Select[tuple[Finding]] = select(Finding).order_by(Finding.created_at.desc())
        return list(self.session.scalars(statement).all())

    def to_read_model(self, finding: Finding) -> ExportFindingRead:
        """Convert a finding model into an export schema."""
        return ExportFindingRead(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            source=finding.source,
            severity=finding.severity,
            status=finding.status,
            category=finding.category,
            affected_asset=finding.affected_asset,
            reporter=finding.reporter,
            confidence=finding.confidence,
            created_at=finding.created_at.isoformat(),
            updated_at=finding.updated_at.isoformat(),
        )

    def to_csv(self, records: list[ExportFindingRead]) -> str:
        """Serialize finding records into CSV text."""
        output = io.StringIO()
        fieldnames = [
            "id",
            "title",
            "description",
            "source",
            "severity",
            "status",
            "category",
            "affected_asset",
            "reporter",
            "confidence",
            "created_at",
            "updated_at",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for record in records:
            writer.writerow(record.model_dump())

        return output.getvalue()
