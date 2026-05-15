"""Bulk finding import service."""

from __future__ import annotations

from sqlalchemy.orm import Session

from tracepoint.schemas.imports import (
    FindingImportCreate,
    FindingImportFailureRead,
    FindingImportItemCreate,
    FindingImportItemRead,
    FindingImportSummaryRead,
)
from tracepoint.schemas.intake import IntakeReportCreate
from tracepoint.services.intake import IntakeService


class FindingImportService:
    """Import finding-like records through the intake workflow."""

    def __init__(self, session: Session) -> None:
        """Initialize the import service."""
        self.session = session
        self.intake_service = IntakeService(session)

    def import_findings(self, payload: FindingImportCreate) -> FindingImportSummaryRead:
        """Import finding-like records and return a summary."""
        results: list[FindingImportItemRead] = []
        failures: list[FindingImportFailureRead] = []

        for index, item in enumerate(payload.items):
            try:
                result = self.import_item(
                    index=index,
                    item=item,
                    payload=payload,
                )
            except ValueError as exc:
                failures.append(
                    FindingImportFailureRead(
                        index=index,
                        title=item.title,
                        reason=str(exc),
                    )
                )
                continue

            results.append(result)

        created = sum(1 for result in results if result.finding_id is not None)
        duplicates = sum(
            1
            for result in results
            if result.duplicate_decision in {"likely_duplicate", "possible_duplicate"}
        )

        return FindingImportSummaryRead(
            received=len(payload.items),
            created=created,
            duplicates=duplicates,
            failed=len(failures),
            results=results,
            failures=failures,
        )

    def import_item(
        self,
        index: int,
        item: FindingImportItemCreate,
        payload: FindingImportCreate,
    ) -> FindingImportItemRead:
        """Import one finding-like record."""
        intake_payload = IntakeReportCreate(
            title=item.title,
            description=item.description,
            source=item.source or payload.source,
            category=item.category,
            affected_asset=item.affected_asset,
            reporter=item.reporter,
            persist=payload.persist,
            check_duplicates=payload.check_duplicates,
        )

        intake_result = self.intake_service.ingest(intake_payload)

        return FindingImportItemRead(
            index=index,
            title=item.title,
            finding_id=intake_result.finding_id,
            triage_result_id=intake_result.triage_result_id,
            persisted=intake_result.persisted,
            duplicate_decision=intake_result.duplicate.decision,
            duplicate_score=intake_result.duplicate.highest_similarity,
            category=intake_result.triage.category,
            severity=intake_result.triage.severity,
        )
