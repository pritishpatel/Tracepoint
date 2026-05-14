"""Deterministic duplicate detection service.

This module provides a lightweight duplicate detector for the first production
slice of Tracepoint. It intentionally avoids embeddings for now so the API,
tests, and persistence workflow remain deterministic and cheap.

A later version can replace or augment this with vector search while preserving
the same schema contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Final

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.duplicate import (
    DuplicateCandidate,
    DuplicateCheckRequest,
    DuplicateCheckResponse,
    DuplicateDecision,
)

TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_/{}.-]+")
WHITESPACE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\s+")


@dataclass(frozen=True)
class SimilarityBreakdown:
    """Component similarity scores used to explain duplicate decisions."""

    title: float
    description: float
    category: float
    asset: float

    @property
    def weighted_score(self) -> float:
        """Return weighted duplicate similarity score."""

        score = (
            self.title * 0.30 + self.description * 0.35 + self.category * 0.15 + self.asset * 0.20
        )
        return round(score, 4)


class TextNormalizer:
    """Normalize security report text for deterministic comparison."""

    def normalize(self, value: str | None) -> str:
        """Normalize a nullable string."""

        if not value:
            return ""

        lowered = value.lower().strip()
        tokens = TOKEN_PATTERN.findall(lowered)
        return WHITESPACE_PATTERN.sub(" ", " ".join(tokens)).strip()


class SimilarityScorer:
    """Compute deterministic similarity between finding-like records."""

    def __init__(self, normalizer: TextNormalizer | None = None) -> None:
        """Initialize scorer dependencies."""

        self.normalizer = normalizer or TextNormalizer()

    def compare(
        self,
        request: DuplicateCheckRequest,
        finding: Finding,
    ) -> SimilarityBreakdown:
        """Compare a new report against a stored finding."""

        title_similarity = self.text_similarity(request.title, finding.title)
        description_similarity = self.text_similarity(
            request.description,
            finding.description,
        )
        category_similarity = self.exact_or_empty_similarity(
            request.category,
            finding.category,
        )
        asset_similarity = self.asset_similarity(
            request.affected_asset,
            finding.affected_asset,
        )

        return SimilarityBreakdown(
            title=title_similarity,
            description=description_similarity,
            category=category_similarity,
            asset=asset_similarity,
        )

    def text_similarity(self, left: str | None, right: str | None) -> float:
        """Return normalized sequence similarity for free text."""

        normalized_left = self.normalizer.normalize(left)
        normalized_right = self.normalizer.normalize(right)

        if not normalized_left or not normalized_right:
            return 0.0

        return round(SequenceMatcher(None, normalized_left, normalized_right).ratio(), 4)

    def exact_or_empty_similarity(self, left: str | None, right: str | None) -> float:
        """Return exact-match similarity for categorical values."""

        normalized_left = self.normalizer.normalize(left)
        normalized_right = self.normalizer.normalize(right)

        if not normalized_left or not normalized_right:
            return 0.0

        return 1.0 if normalized_left == normalized_right else 0.0

    def asset_similarity(self, left: str | None, right: str | None) -> float:
        """Return similarity for affected assets and endpoint-like strings."""

        normalized_left = self.normalizer.normalize(left)
        normalized_right = self.normalizer.normalize(right)

        if not normalized_left or not normalized_right:
            return 0.0

        if normalized_left == normalized_right:
            return 1.0

        left_parts = set(normalized_left.split("/"))
        right_parts = set(normalized_right.split("/"))

        if left_parts and right_parts:
            overlap = len(left_parts & right_parts) / len(left_parts | right_parts)
        else:
            overlap = 0.0

        sequence_score = SequenceMatcher(
            None,
            normalized_left,
            normalized_right,
        ).ratio()

        return round(max(overlap, sequence_score), 4)


class DuplicateDetectionService:
    """Detect duplicate findings using deterministic similarity scoring."""

    def __init__(
        self,
        session: Session,
        scorer: SimilarityScorer | None = None,
    ) -> None:
        """Initialize duplicate detection service."""

        self.session = session
        self.scorer = scorer or SimilarityScorer()

    def check_duplicate(
        self,
        request: DuplicateCheckRequest,
    ) -> DuplicateCheckResponse:
        """Return duplicate candidates and a review recommendation."""

        findings = self._load_candidate_findings()
        candidates = self._score_candidates(request, findings)
        limited_candidates = candidates[: request.top_k]
        highest_similarity = limited_candidates[0].similarity if limited_candidates else 0.0

        decision = self._decision(highest_similarity, limited_candidates)
        recommendation = self._recommendation(decision, limited_candidates)

        return DuplicateCheckResponse(
            decision=decision,
            highest_similarity=highest_similarity,
            candidates=limited_candidates,
            recommendation=recommendation,
        )

    def _load_candidate_findings(self) -> list[Finding]:
        """Load historical findings ordered by newest first."""

        statement: Select[tuple[Finding]] = select(Finding).order_by(Finding.created_at.desc())
        return list(self.session.scalars(statement).all())

    def _score_candidates(
        self,
        request: DuplicateCheckRequest,
        findings: list[Finding],
    ) -> list[DuplicateCandidate]:
        """Score all historical findings and keep meaningful candidates."""

        candidates: list[DuplicateCandidate] = []

        for finding in findings:
            breakdown = self.scorer.compare(request, finding)
            similarity = breakdown.weighted_score

            if similarity < 0.20:
                continue

            candidates.append(
                DuplicateCandidate(
                    finding_id=finding.id,
                    title=finding.title,
                    category=finding.category,
                    affected_asset=finding.affected_asset,
                    similarity=similarity,
                    reason=self._reason(breakdown),
                )
            )

        return sorted(candidates, key=lambda candidate: candidate.similarity, reverse=True)

    def _decision(
        self,
        highest_similarity: float,
        candidates: list[DuplicateCandidate],
    ) -> DuplicateDecision:
        """Convert similarity into a duplicate decision."""

        if not candidates:
            return DuplicateDecision.NOT_DUPLICATE

        if highest_similarity >= 0.82:
            return DuplicateDecision.LIKELY_DUPLICATE

        if highest_similarity >= 0.65:
            return DuplicateDecision.POSSIBLE_DUPLICATE

        if highest_similarity >= 0.45:
            return DuplicateDecision.NEEDS_HUMAN_REVIEW

        return DuplicateDecision.NOT_DUPLICATE

    def _recommendation(
        self,
        decision: DuplicateDecision,
        candidates: list[DuplicateCandidate],
    ) -> str:
        """Return analyst-facing recommendation."""

        if decision == DuplicateDecision.LIKELY_DUPLICATE:
            return "Likely duplicate. Ask an analyst to confirm before closure."

        if decision == DuplicateDecision.POSSIBLE_DUPLICATE:
            return "Possible duplicate. Compare reproduction path and affected asset."

        if decision == DuplicateDecision.NEEDS_HUMAN_REVIEW:
            return "Similarity is weak but non-trivial. Human review is recommended."

        if not candidates:
            return "No similar historical findings were found."

        return "No strong duplicate signal found."

    def _reason(self, breakdown: SimilarityBreakdown) -> str:
        """Explain which signals contributed to the duplicate score."""

        reasons: list[str] = []

        if breakdown.asset >= 0.75:
            reasons.append("similar affected asset")

        if breakdown.category >= 1.0:
            reasons.append("same vulnerability category")

        if breakdown.title >= 0.70:
            reasons.append("similar title")

        if breakdown.description >= 0.65:
            reasons.append("similar report narrative")

        if not reasons:
            reasons.append("partial textual overlap")

        return ", ".join(reasons)
