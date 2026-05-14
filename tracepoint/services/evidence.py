"""Evidence bundle generation service."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.models.triage_result import TriageResult
from tracepoint.schemas.evidence import (
    EvidenceArtifact,
    EvidenceBundleCreate,
    EvidenceBundleRead,
)

EVIDENCE_OUTPUT_DIR = Path("artifacts/evidence")


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def decode_json_list(value: str | None) -> list[str]:
    """Decode a JSON list stored on a database model."""
    if not value:
        return []

    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return []

    if not isinstance(decoded, list):
        return []

    return [str(item) for item in decoded]


def encode_json(data: dict[str, Any]) -> str:
    """Encode JSON using stable formatting."""
    return json.dumps(data, indent=2, sort_keys=True)


def safe_filename(value: str) -> str:
    """Return a filesystem-safe filename fragment."""
    cleaned = "".join(character if character.isalnum() else "-" for character in value)
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned.lower() or "finding"


@dataclass(frozen=True)
class TriageEvidence:
    """Decoded triage evidence attached to a finding."""

    validity: str
    category: str
    severity: str
    cwe: str | None
    owasp: str | None
    routing_team: str
    confidence: float
    evidence_summary: list[str]
    reproduction_steps: list[str]
    remediation_guidance: list[str]
    human_review_questions: list[str]

    @classmethod
    def from_model(cls, triage_result: TriageResult) -> TriageEvidence:
        """Create decoded triage evidence from a persisted triage result."""
        return cls(
            validity=triage_result.validity,
            category=triage_result.category,
            severity=triage_result.severity,
            cwe=triage_result.cwe,
            owasp=triage_result.owasp,
            routing_team=triage_result.routing_team,
            confidence=triage_result.confidence,
            evidence_summary=decode_json_list(triage_result.evidence_summary_json),
            reproduction_steps=decode_json_list(triage_result.reproduction_steps_json),
            remediation_guidance=decode_json_list(triage_result.remediation_guidance_json),
            human_review_questions=decode_json_list(triage_result.human_review_questions_json),
        )


class EvidenceMarkdownRenderer:
    """Render findings and triage metadata as Markdown."""

    def render(
        self,
        finding: Finding,
        triage: TriageEvidence | None,
    ) -> str:
        """Render a complete Markdown evidence bundle."""
        sections = [
            self.render_finding_summary(finding),
            self.render_triage_summary(triage),
            self.render_evidence(triage),
            self.render_reproduction_steps(triage),
            self.render_remediation(triage),
            self.render_human_review(triage),
        ]

        return "\n\n".join(section for section in sections if section).strip() + "\n"

    def render_finding_summary(self, finding: Finding) -> str:
        """Render the finding summary section."""
        lines = [
            f"# Evidence Bundle: {finding.title}",
            "",
            "## Finding",
            f"- **Finding ID:** `{finding.id}`",
            f"- **Severity:** `{finding.severity}`",
            f"- **Status:** `{finding.status}`",
            f"- **Source:** `{finding.source}`",
            f"- **Category:** `{finding.category or 'unknown'}`",
            f"- **Affected Asset:** `{finding.affected_asset or 'unknown'}`",
            f"- **Reporter:** `{finding.reporter or 'unknown'}`",
            f"- **Confidence:** `{finding.confidence:.2f}`",
            "",
            "## Description",
            finding.description,
        ]

        return "\n".join(lines)

    def render_triage_summary(self, triage: TriageEvidence | None) -> str:
        """Render the triage summary section."""
        if triage is None:
            return ""

        lines = [
            "## Triage",
            f"- **Validity:** `{triage.validity}`",
            f"- **Category:** `{triage.category}`",
            f"- **Severity:** `{triage.severity}`",
            f"- **CWE:** `{triage.cwe or 'unknown'}`",
            f"- **OWASP:** `{triage.owasp or 'unknown'}`",
            f"- **Routing Team:** `{triage.routing_team}`",
            f"- **Confidence:** `{triage.confidence:.2f}`",
        ]

        return "\n".join(lines)

    def render_evidence(self, triage: TriageEvidence | None) -> str:
        """Render evidence summary bullets."""
        if triage is None or not triage.evidence_summary:
            return ""

        return self.render_bullets("## Evidence Summary", triage.evidence_summary)

    def render_reproduction_steps(self, triage: TriageEvidence | None) -> str:
        """Render reproduction steps."""
        if triage is None or not triage.reproduction_steps:
            return ""

        lines = ["## Reproduction Steps"]
        lines.extend(
            f"{index}. {step}" for index, step in enumerate(triage.reproduction_steps, start=1)
        )
        return "\n".join(lines)

    def render_remediation(self, triage: TriageEvidence | None) -> str:
        """Render remediation guidance."""
        if triage is None or not triage.remediation_guidance:
            return ""

        return self.render_bullets("## Remediation Guidance", triage.remediation_guidance)

    def render_human_review(self, triage: TriageEvidence | None) -> str:
        """Render human-review questions."""
        if triage is None or not triage.human_review_questions:
            return ""

        return self.render_bullets(
            "## Human Review Questions",
            triage.human_review_questions,
        )

    def render_bullets(self, title: str, items: list[str]) -> str:
        """Render a titled bullet list."""
        lines = [title]
        lines.extend(f"- {item}" for item in items)
        return "\n".join(lines)


class EvidenceJsonRenderer:
    """Render findings and triage metadata as JSON."""

    def render(
        self,
        finding: Finding,
        triage: TriageEvidence | None,
    ) -> str:
        """Render a complete JSON evidence bundle."""
        payload: dict[str, Any] = {
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "source": finding.source,
                "severity": finding.severity,
                "status": finding.status,
                "category": finding.category,
                "affected_asset": finding.affected_asset,
                "reporter": finding.reporter,
                "confidence": finding.confidence,
                "created_at": finding.created_at.isoformat(),
                "updated_at": finding.updated_at.isoformat(),
            },
            "triage": None,
        }

        if triage is not None:
            payload["triage"] = {
                "validity": triage.validity,
                "category": triage.category,
                "severity": triage.severity,
                "cwe": triage.cwe,
                "owasp": triage.owasp,
                "routing_team": triage.routing_team,
                "confidence": triage.confidence,
                "evidence_summary": triage.evidence_summary,
                "reproduction_steps": triage.reproduction_steps,
                "remediation_guidance": triage.remediation_guidance,
                "human_review_questions": triage.human_review_questions,
            }

        return encode_json(payload)


class EvidenceBundleService:
    """Generate evidence artifacts for findings."""

    def __init__(self, session: Session) -> None:
        """Initialize the evidence service."""
        self.session = session
        self.markdown_renderer = EvidenceMarkdownRenderer()
        self.json_renderer = EvidenceJsonRenderer()

    def create_bundle(
        self,
        finding_id: str,
        payload: EvidenceBundleCreate,
    ) -> EvidenceBundleRead | None:
        """Create an evidence bundle for a finding."""
        finding = self.session.get(Finding, finding_id)

        if finding is None:
            return None

        generated_at = utc_now()
        triage = self.get_latest_triage(finding_id) if payload.include_triage else None
        artifacts = self.build_artifacts(finding=finding, triage=triage, payload=payload)
        artifact_paths = self.write_artifacts(
            finding=finding,
            artifacts=artifacts,
            generated_at=generated_at,
        )

        markdown_path = None
        json_path = None

        for artifact in artifacts:
            artifact_path = artifact_paths.get(artifact.name)

            if artifact.content_type == "text/markdown":
                markdown_path = artifact_path
            elif artifact.content_type == "application/json":
                json_path = artifact_path

        return EvidenceBundleRead(
            finding_id=finding.id,
            generated_at=generated_at,
            artifact_count=len(artifacts),
            included_triage=triage is not None,
            markdown_path=markdown_path,
            json_path=json_path,
            artifacts=artifacts,
        )

    def get_latest_triage(self, finding_id: str) -> TriageEvidence | None:
        """Return the latest persisted triage result for a finding."""
        statement: Select[tuple[TriageResult]] = (
            select(TriageResult)
            .where(TriageResult.finding_id == finding_id)
            .order_by(TriageResult.created_at.desc())
            .limit(1)
        )

        triage_result = self.session.scalars(statement).first()

        if triage_result is None:
            return None

        return TriageEvidence.from_model(triage_result)

    def build_artifacts(
        self,
        finding: Finding,
        triage: TriageEvidence | None,
        payload: EvidenceBundleCreate,
    ) -> list[EvidenceArtifact]:
        """Build all requested evidence artifacts."""
        artifacts: list[EvidenceArtifact] = []

        if payload.include_markdown:
            artifacts.append(
                EvidenceArtifact(
                    name="evidence.md",
                    content_type="text/markdown",
                    content=self.markdown_renderer.render(finding=finding, triage=triage),
                )
            )

        if payload.include_json:
            artifacts.append(
                EvidenceArtifact(
                    name="evidence.json",
                    content_type="application/json",
                    content=self.json_renderer.render(finding=finding, triage=triage),
                )
            )

        return artifacts

    def write_artifacts(
        self,
        finding: Finding,
        artifacts: list[EvidenceArtifact],
        generated_at: datetime,
    ) -> dict[str, str]:
        """Write generated artifacts to disk and return paths by artifact name."""
        bundle_dir = self.bundle_directory(finding=finding, generated_at=generated_at)
        bundle_dir.mkdir(parents=True, exist_ok=True)

        paths: dict[str, str] = {}

        for artifact in artifacts:
            artifact_path = bundle_dir / artifact.name
            artifact_path.write_text(artifact.content, encoding="utf-8")
            paths[artifact.name] = str(artifact_path)

        return paths

    def bundle_directory(self, finding: Finding, generated_at: datetime) -> Path:
        """Return the filesystem directory for one evidence bundle."""
        timestamp = generated_at.strftime("%Y%m%d-%H%M%S")
        finding_slug = safe_filename(finding.id)

        return EVIDENCE_OUTPUT_DIR / f"{timestamp}-{finding_slug}"
