"""Finding service layer.

The service owns business operations for findings and keeps database access out
of API route handlers. Future triage, duplicate detection, remediation, and
audit evidence workflows should attach to this layer instead of bypassing it.
"""

from __future__ import annotations

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.finding import FindingCreate


class FindingService:
    """Application service for finding CRUD operations."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_finding(self, payload: FindingCreate) -> Finding:
        """Create and persist a finding."""
        finding = Finding(**payload.model_dump())
        self.session.add(finding)
        self.session.flush()
        self.session.refresh(finding)
        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        """Return a finding by ID, or None when not found."""
        return self.session.get(Finding, finding_id)

    def list_findings(self, limit: int, offset: int) -> tuple[list[Finding], int]:
        """Return a paginated list of findings and total row count."""
        total = self.session.scalar(select(func.count()).select_from(Finding)) or 0

        statement: Select[tuple[Finding]] = (
            select(Finding).order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        )

        findings = list(self.session.scalars(statement).all())
        return findings, total
