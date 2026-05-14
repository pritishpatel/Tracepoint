"""Persistence service for triage results."""

from __future__ import annotations

from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.models.triage_result import TriageResult
from tracepoint.schemas.finding import FindingCreate
from tracepoint.schemas.triage import TriageRequest, TriageResponse
from tracepoint.schemas.triage_result import encode_json_list


class TriageResultService:
    """Persist triage outputs and their linked finding records."""

    def __init__(self, session: Session) -> None:
        """Initialize the service with an active database session."""
        self.session = session

    def persist(
        self,
        request: TriageRequest,
        triage: TriageResponse,
    ) -> tuple[Finding, TriageResult]:
        """Persist a finding and the triage output linked to it."""
        finding = self._create_finding(request=request, triage=triage)
        result = self._create_triage_result(finding=finding, triage=triage)

        self.session.flush()
        self.session.refresh(finding)
        self.session.refresh(result)

        return finding, result

    def _create_finding(
        self,
        request: TriageRequest,
        triage: TriageResponse,
    ) -> Finding:
        """Create the finding row derived from the triage request and output."""
        payload = FindingCreate.model_validate(
            {
                "title": request.title,
                "description": request.description,
                "source": request.source,
                "severity": triage.severity,
                "status": "new",
                "category": triage.category,
                "affected_asset": request.affected_asset,
                "reporter": request.reporter,
                "confidence": triage.confidence,
            }
        )

        finding = Finding(**payload.model_dump())
        self.session.add(finding)
        self.session.flush()
        return finding

    def _create_triage_result(
        self,
        finding: Finding,
        triage: TriageResponse,
    ) -> TriageResult:
        """Create the persisted triage result row."""
        result = TriageResult(
            finding_id=finding.id,
            validity=str(triage.validity),
            category=str(triage.category),
            severity=str(triage.severity),
            cwe=triage.cwe,
            owasp=triage.owasp,
            routing_team=triage.routing_team,
            confidence=triage.confidence,
            evidence_summary_json=encode_json_list(triage.evidence_summary),
            reproduction_steps_json=encode_json_list(triage.reproduction_steps),
            remediation_guidance_json=encode_json_list(triage.remediation_guidance),
            human_review_questions_json=encode_json_list(triage.human_review_questions),
        )
        self.session.add(result)
        return result
