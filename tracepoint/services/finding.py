"""Finding service layer.

The service owns business operations for findings and keeps database access out
of API route handlers. Future triage, duplicate detection, remediation, and
audit evidence workflows should attach to this layer instead of bypassing it.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.finding import (
    FindingCreate,
    FindingKevDetailRead,
    FindingKevSummaryItemRead,
    FindingKevSummaryRead,
    FindingProvenanceRead,
)


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


def _parse_date(value: str | None) -> date | None:
    """Parse YYYY-MM-DD date values safely."""
    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _priority_reason(
    *,
    severity: str,
    is_overdue: bool,
    days_until_due: int | None,
    known_ransomware_use: bool,
    cve: str | None,
) -> str:
    """Return a concise operational prioritization reason."""
    cve_label = cve or "Finding"

    if is_overdue and known_ransomware_use:
        return f"{cve_label} is overdue and has known ransomware use"

    if is_overdue:
        return f"{cve_label} is past the CISA KEV remediation due date"

    if known_ransomware_use:
        return f"{cve_label} has known ransomware campaign use"

    if days_until_due is not None and days_until_due <= 3:
        return f"{cve_label} is due within {days_until_due} day(s)"

    if severity == "critical":
        return f"{cve_label} is a critical CISA KEV finding"

    if severity == "high":
        return f"{cve_label} is a high-severity CISA KEV finding"

    return f"{cve_label} is listed in the CISA KEV catalog"


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
            source=finding.source,
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

    def get_kev_detail(self, finding_id: str) -> FindingKevDetailRead | None:
        """Return operational CISA KEV details for a finding."""
        finding = self.get_finding(finding_id)

        if finding is None:
            return None

        provenance = self.get_provenance(finding_id)

        if provenance is None:
            return None

        due_date = _parse_date(provenance.due_date)
        today = date.today()
        days_until_due = (due_date - today).days if due_date is not None else None
        is_overdue = days_until_due is not None and days_until_due < 0
        known_ransomware_use = (provenance.known_ransomware_use or "").strip().lower() == "known"

        severity = str(finding.severity)
        priority_reason = _priority_reason(
            severity=severity,
            is_overdue=is_overdue,
            days_until_due=days_until_due,
            known_ransomware_use=known_ransomware_use,
            cve=provenance.cve,
        )

        return FindingKevDetailRead(
            finding_id=finding.id,
            title=finding.title,
            source=finding.source,
            cve=provenance.cve,
            vendor_project=provenance.vendor_project,
            product=provenance.product,
            vulnerability=provenance.vulnerability,
            cwes=provenance.cwes,
            kev_date_added=provenance.date_added_to_kev,
            kev_due_date=provenance.due_date,
            days_until_due=days_until_due,
            is_overdue=is_overdue,
            known_ransomware_use=known_ransomware_use,
            required_action=provenance.raw.get("Required action"),
            notes=provenance.notes,
            severity=severity,
            category=finding.category,
            priority_reason=priority_reason,
        )

    def get_kev_summary(self) -> FindingKevSummaryRead:
        """Return collection-level CISA KEV prioritization summary."""
        statement: Select[tuple[Finding]] = select(Finding).where(Finding.source == "cisa_kev")
        findings = list(self.session.scalars(statement).all())

        summary = FindingKevSummaryRead(total_kev_findings=len(findings))
        detail_items: list[FindingKevDetailRead] = []

        for finding in findings:
            detail = self.get_kev_detail(finding.id)
            if detail is None:
                continue

            detail_items.append(detail)

            severity = detail.severity.lower()
            if severity == "critical":
                summary.critical += 1
            elif severity == "high":
                summary.high += 1
            elif severity == "medium":
                summary.medium += 1
            elif severity == "low":
                summary.low += 1
            else:
                summary.unknown += 1

            if detail.is_overdue:
                summary.overdue += 1

            if detail.days_until_due is not None and 0 <= detail.days_until_due <= 7:
                summary.due_soon += 1

            if detail.known_ransomware_use:
                summary.known_ransomware_use += 1

        prioritized = sorted(
            detail_items,
            key=lambda item: (
                not item.is_overdue,
                item.days_until_due if item.days_until_due is not None else 999999,
                0 if item.severity == "critical" else 1,
            ),
        )

        summary.top_due_items = [
            FindingKevSummaryItemRead(
                finding_id=item.finding_id,
                title=item.title,
                cve=item.cve,
                vendor_project=item.vendor_project,
                product=item.product,
                severity=item.severity,
                category=item.category,
                kev_due_date=item.kev_due_date,
                days_until_due=item.days_until_due,
                is_overdue=item.is_overdue,
                known_ransomware_use=item.known_ransomware_use,
                priority_reason=item.priority_reason,
            )
            for item in prioritized[:10]
        ]

        return summary

    def list_findings(self, limit: int, offset: int) -> tuple[list[Finding], int]:
        """Return a paginated list of findings and total row count."""
        total = self.session.scalar(select(func.count()).select_from(Finding)) or 0

        statement: Select[tuple[Finding]] = (
            select(Finding).order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        )

        findings = list(self.session.scalars(statement).all())
        return findings, total
