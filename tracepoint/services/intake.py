"""End-to-end report intake orchestration service."""

from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.models.triage_result import TriageResult
from tracepoint.schemas.intake import (
    IntakeDuplicateRead,
    IntakeReportCreate,
    IntakeReportRead,
    IntakeTriageRead,
    enum_value,
)
from tracepoint.schemas.triage import TriageRequest
from tracepoint.services.triage import TriageService


def encode_json_list(items: list[str]) -> str:
    """Encode a list of strings for persisted JSON text columns."""
    return json.dumps(items, sort_keys=True)


def normalize_text(value: str | None) -> set[str]:
    """Normalize text into a simple token set for deterministic duplicate checks."""
    if not value:
        return set()

    normalized = "".join(character.lower() if character.isalnum() else " " for character in value)
    return {token for token in normalized.split() if len(token) > 2}


def similarity_score(left: str, right: str) -> float:
    """Return a deterministic Jaccard similarity score for two text values."""
    left_tokens = normalize_text(left)
    right_tokens = normalize_text(right)

    if not left_tokens or not right_tokens:
        return 0.0

    intersection = left_tokens & right_tokens
    union = left_tokens | right_tokens

    return len(intersection) / len(union)


@dataclass(frozen=True)
class DuplicateCandidate:
    """Best duplicate candidate found during intake."""

    finding: Finding | None
    score: float

    @property
    def is_duplicate(self) -> bool:
        """Return whether the candidate crosses the duplicate threshold."""
        return self.finding is not None and self.score >= 0.30


class IntakeService:
    """Coordinate triage, duplicate detection, and persistence."""

    def __init__(self, session: Session) -> None:
        """Initialize the intake service."""
        self.session = session
        self.triage_service = TriageService()

    def ingest(self, payload: IntakeReportCreate) -> IntakeReportRead:
        """Process a raw security report through the intake workflow."""
        triage = self.triage_service.triage(
            TriageRequest(
                title=payload.title,
                description=payload.description,
                source=payload.source,
                affected_asset=payload.affected_asset,
            )
        )

        duplicate = (
            self.find_best_duplicate(payload)
            if payload.check_duplicates
            else DuplicateCandidate(finding=None, score=0.0)
        )

        finding: Finding | None = None
        triage_result: TriageResult | None = None

        if payload.persist:
            finding = self.create_finding(payload, triage)
            triage_result = self.create_triage_result(finding=finding, triage=triage)

        return IntakeReportRead(
            finding_id=finding.id if finding is not None else None,
            triage_result_id=triage_result.id if triage_result is not None else None,
            persisted=payload.persist,
            triage=IntakeTriageRead(
                validity=enum_value(triage.validity),
                category=enum_value(triage.category),
                severity=enum_value(triage.severity),
                cwe=triage.cwe,
                owasp=triage.owasp,
                routing_team=triage.routing_team,
                confidence=triage.confidence,
                evidence_summary=triage.evidence_summary,
                reproduction_steps=triage.reproduction_steps,
                remediation_guidance=triage.remediation_guidance,
                human_review_questions=triage.human_review_questions,
            ),
            duplicate=self.build_duplicate_response(duplicate),
        )

    def build_duplicate_response(
        self,
        duplicate: DuplicateCandidate,
    ) -> IntakeDuplicateRead:
        """Build the duplicate summary returned by intake responses."""
        is_duplicate = duplicate.is_duplicate
        score = round(duplicate.score, 4) if is_duplicate else 0.0
        finding_id = duplicate.finding.id if duplicate.finding is not None else None
        title = duplicate.finding.title if duplicate.finding is not None else None

        if not is_duplicate:
            finding_id = None
            title = None

        return IntakeDuplicateRead(
            decision="likely_duplicate" if is_duplicate else "not_duplicate",
            highest_similarity=score,
            matched_finding_id=finding_id,
            matched_finding_title=title,
            reasons=self.build_duplicate_reasons(duplicate) if is_duplicate else [],
            is_duplicate=is_duplicate,
            score=score,
            finding_id=finding_id,
            title=title,
        )

    def build_duplicate_reasons(self, duplicate: DuplicateCandidate) -> list[str]:
        """Build human-readable duplicate-match reasons."""
        if duplicate.finding is None:
            return []

        reasons = [
            f"Matched existing finding `{duplicate.finding.id}`.",
            f"Similarity score: {duplicate.score:.4f}.",
        ]

        if duplicate.finding.category:
            reasons.append(f"Existing category: {duplicate.finding.category}.")

        if duplicate.finding.affected_asset:
            reasons.append(f"Existing asset: {duplicate.finding.affected_asset}.")

        return reasons

    def create_finding(self, payload: IntakeReportCreate, triage: object) -> Finding:
        """Persist the finding produced by intake."""
        severity = enum_value(getattr(triage, "severity", "unknown"))
        category = payload.category or enum_value(getattr(triage, "category", "unknown"))

        finding = Finding(
            title=payload.title,
            description=payload.description,
            source=payload.source,
            severity=severity,
            status="new",
            category=category,
            affected_asset=payload.affected_asset,
            reporter=payload.reporter,
            confidence=float(getattr(triage, "confidence", 0.0)),
        )
        self.session.add(finding)
        self.session.flush()
        return finding

    def create_triage_result(self, finding: Finding, triage: object) -> TriageResult:
        """Persist the triage decision produced by intake."""
        result = TriageResult(
            finding_id=finding.id,
            validity=enum_value(getattr(triage, "validity", "needs_human_review")),
            category=enum_value(getattr(triage, "category", "unknown")),
            severity=enum_value(getattr(triage, "severity", "unknown")),
            cwe=getattr(triage, "cwe", None),
            owasp=getattr(triage, "owasp", None),
            routing_team=str(getattr(triage, "routing_team", "security-operations")),
            confidence=float(getattr(triage, "confidence", 0.0)),
            evidence_summary_json=encode_json_list(list(getattr(triage, "evidence_summary", []))),
            reproduction_steps_json=encode_json_list(
                list(getattr(triage, "reproduction_steps", []))
            ),
            remediation_guidance_json=encode_json_list(
                list(getattr(triage, "remediation_guidance", []))
            ),
            human_review_questions_json=encode_json_list(
                list(getattr(triage, "human_review_questions", []))
            ),
        )
        self.session.add(result)
        self.session.flush()
        return result

    def find_best_duplicate(self, payload: IntakeReportCreate) -> DuplicateCandidate:
        """Find the most similar existing finding."""
        statement: Select[tuple[Finding]] = select(Finding).limit(200)
        findings = self.session.scalars(statement).all()

        best_finding: Finding | None = None
        best_score = 0.0

        incoming_text = self.duplicate_text(
            title=payload.title,
            description=payload.description,
            category=payload.category,
            affected_asset=payload.affected_asset,
        )

        for finding in findings:
            candidate_text = self.duplicate_text(
                title=finding.title,
                description=finding.description,
                category=finding.category,
                affected_asset=finding.affected_asset,
            )
            score = similarity_score(incoming_text, candidate_text)

            if payload.affected_asset and payload.affected_asset == finding.affected_asset:
                score = min(score + 0.25, 1.0)

            if payload.category and payload.category == finding.category:
                score = min(score + 0.15, 1.0)

            if score > best_score:
                best_score = score
                best_finding = finding

        return DuplicateCandidate(finding=best_finding, score=best_score)

    def duplicate_text(
        self,
        title: str,
        description: str,
        category: str | None,
        affected_asset: str | None,
    ) -> str:
        """Build comparable text for duplicate detection."""
        return " ".join(
            part
            for part in [
                title,
                description,
                category or "",
                affected_asset or "",
            ]
            if part
        )
