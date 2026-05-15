"""Finding service layer.

The service owns business operations for findings and keeps database access out
of API route handlers. Future triage, duplicate detection, remediation, and
audit evidence workflows should attach to this layer instead of bypassing it.
"""

from __future__ import annotations

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding, FindingSource
from tracepoint.schemas.finding import FindingCreate, FindingProvenanceRead


def _parse_key_value_description(description: str) -> dict[str, str]:
    """Parse simple 'Key: value' lines from a finding description."""
    parsed: dict[str, str] = {}

    for line in description.splitlines():
        if ": " not in line:
            continue

        key, value = line.split(": ", 1)
        key = key.strip()
        value = value.strip()

        if key and value:
            parsed[key] = value

    return parsed


def _parse_int(value: str | None) -> int | None:
    """Parse an integer value when available."""
    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def _parse_cwes(value: str | None) -> list[str]:
    """Parse a comma-separated CWE list."""
    if not value:
        return []

    return [item.strip() for item in value.split(",") if item.strip()]


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

    def get_provenance(self, finding_id: str) -> FindingProvenanceRead | None:
        """Return parsed provenance metadata for a finding."""
        finding = self.get_finding(finding_id)

        if finding is None:
            return None

        raw = _parse_key_value_description(finding.description)

        return FindingProvenanceRead(
            finding_id=finding.id,
            title=finding.title,
            source=FindingSource(finding.source),
            source_dataset=raw.get("Source dataset"),
            source_url=raw.get("Source URL"),
            catalog_version=raw.get("Catalog version"),
            catalog_release_date=raw.get("Catalog release date"),
            catalog_total_records=_parse_int(raw.get("Catalog total records")),
            cve=raw.get("CVE"),
            cwes=_parse_cwes(raw.get("CWE(s)")),
            vendor_project=raw.get("Vendor/Project"),
            product=raw.get("Product"),
            vulnerability=raw.get("Vulnerability"),
            date_added_to_kev=raw.get("Date added to KEV"),
            due_date=raw.get("Due date"),
            known_ransomware_use=raw.get("Known ransomware use"),
            notes=raw.get("Notes"),
            raw=raw,
        )

    def list_findings(self, limit: int, offset: int) -> tuple[list[Finding], int]:
        """Return a paginated list of findings and total row count."""
        total = self.session.scalar(select(func.count()).select_from(Finding)) or 0

        statement: Select[tuple[Finding]] = (
            select(Finding).order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        )

        findings = list(self.session.scalars(statement).all())
        return findings, total
