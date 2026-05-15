"""SLA calculation service for finding remediation timelines."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import ClassVar

from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.sla import FindingSlaRead
from tracepoint.services.risk import FindingRiskService


class FindingSlaService:
    """Calculate SLA deadlines from deterministic finding risk scores."""

    SLA_HOURS_BY_PRIORITY: ClassVar[dict[str, int]] = {
        "P0": 4,
        "P1": 24,
        "P2": 72,
        "P3": 168,
        "P4": 720,
    }

    ESCALATION_PRIORITIES: ClassVar[set[str]] = {"P0", "P1"}

    def __init__(self, session: Session) -> None:
        """Initialize the SLA service."""
        self.session = session
        self.risk_service = FindingRiskService(session)

    def get_finding_sla(self, finding_id: str) -> FindingSlaRead | None:
        """Return SLA timeline for a finding."""
        finding = self.session.get(Finding, finding_id)

        if finding is None:
            return None

        risk = self.risk_service.score_finding(finding_id)

        if risk is None:
            return None

        created_at = self.ensure_datetime(finding.created_at)
        sla_hours = self.SLA_HOURS_BY_PRIORITY.get(risk.priority, 720)
        due_at = created_at + timedelta(hours=sla_hours)

        now = datetime.now(timezone.utc)
        remaining_seconds = int((due_at - now).total_seconds())
        is_overdue = remaining_seconds < 0
        escalation_required = self.escalation_required(
            priority=risk.priority,
            is_overdue=is_overdue,
        )

        return FindingSlaRead(
            finding_id=finding.id,
            title=finding.title,
            priority=risk.priority,
            risk_level=risk.risk_level,
            risk_score=risk.risk_score,
            sla_hours=sla_hours,
            created_at=self.to_response_datetime(created_at),
            due_at=self.to_response_datetime(due_at),
            is_overdue=is_overdue,
            escalation_required=escalation_required,
            recommendation=self.recommendation(
                priority=risk.priority,
                is_overdue=is_overdue,
                remaining_seconds=remaining_seconds,
            ),
        )

    def ensure_datetime(self, value: datetime) -> datetime:
        """Return a timezone-aware UTC datetime."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    def to_response_datetime(self, value: datetime) -> datetime:
        """Return Python 3.10 fromisoformat-compatible response datetime."""
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def escalation_required(self, priority: str, is_overdue: bool) -> bool:
        """Return whether the finding should be escalated."""
        return is_overdue or priority in self.ESCALATION_PRIORITIES

    def recommendation(
        self,
        priority: str,
        is_overdue: bool,
        remaining_seconds: int,
    ) -> str:
        """Return SLA-specific remediation guidance."""
        if is_overdue:
            return "SLA is overdue. Escalate immediately and assign ownership."

        if priority == "P0":
            return "Critical SLA. Start immediate incident response and remediation."

        if priority == "P1":
            return "High-priority SLA. Assign same-day owner and remediation plan."

        if priority == "P2":
            return "Medium-priority SLA. Schedule review and remediation within target window."

        if remaining_seconds <= 86_400:
            return "SLA is approaching. Confirm owner and next action."

        return "SLA is currently within target. Continue normal tracking."
