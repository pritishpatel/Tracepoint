"""Finding workflow service."""

from __future__ import annotations

from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.workflow import ALLOWED_FINDING_STATUSES, FindingWorkflowRead


class FindingWorkflowService:
    """Manage analyst workflow state for findings."""

    def __init__(self, session: Session) -> None:
        """Initialize workflow service."""
        self.session = session

    def update_status(
        self,
        finding_id: str,
        status: str,
        note: str | None = None,
    ) -> FindingWorkflowRead | None:
        """Update a finding status and return the workflow result."""
        finding = self.session.get(Finding, finding_id)

        if finding is None:
            return None

        normalized_status = self.normalize_status(status)
        previous_status = finding.status
        changed = previous_status != normalized_status

        if changed:
            finding.status = normalized_status
            self.session.add(finding)
            self.session.flush()
            self.session.refresh(finding)

        return FindingWorkflowRead(
            finding_id=finding.id,
            title=finding.title,
            previous_status=previous_status,
            status=finding.status,
            note=note,
            changed=changed,
        )

    def is_allowed_status(self, status: str) -> bool:
        """Return whether a status is supported."""
        return self.normalize_status(status) in ALLOWED_FINDING_STATUSES

    def normalize_status(self, status: str) -> str:
        """Normalize external status labels."""
        return status.strip().lower().replace("-", "_").replace(" ", "_")
