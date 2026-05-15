"""Finding risk scoring service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.risk import FindingRiskRead, RiskFactorRead

SEVERITY_WEIGHTS: Final[dict[str, float]] = {
    "critical": 40.0,
    "high": 32.0,
    "medium": 20.0,
    "low": 10.0,
    "informational": 4.0,
    "unknown": 8.0,
}

CATEGORY_WEIGHTS: Final[dict[str, float]] = {
    "idor": 20.0,
    "auth_bypass": 22.0,
    "exposed_secret": 20.0,  # nosec B105
    "account_compromise": 18.0,
    "cloud_misconfiguration": 16.0,
    "injection": 18.0,
    "xss": 12.0,
    "unknown": 6.0,
}

SOURCE_WEIGHTS: Final[dict[str, float]] = {
    "bug_bounty": 10.0,
    "secret_scan": 12.0,  # nosec B105
    "manual": 8.0,
    "customer_report": 8.0,
    "internal_scan": 7.0,
}

SENSITIVE_ASSET_KEYWORDS: Final[tuple[str, ...]] = (
    "invoice",
    "payment",
    "billing",
    "auth",
    "login",
    "session",
    "token",
    "secret",
    "admin",
    "user",
    "tenant",
)


@dataclass(frozen=True)
class RiskComputation:
    """Internal risk computation result."""

    score: float
    factors: list[RiskFactorRead]


class FindingRiskService:
    """Compute deterministic risk scores for findings."""

    def __init__(self, session: Session) -> None:
        """Initialize the risk service."""
        self.session = session

    def score_finding(self, finding_id: str) -> FindingRiskRead | None:
        """Score a finding by identifier."""
        finding = self.session.get(Finding, finding_id)

        if finding is None:
            return None

        computation = self.compute(finding)
        risk_level = self.risk_level(computation.score)

        return FindingRiskRead(
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity,
            category=finding.category,
            affected_asset=finding.affected_asset,
            confidence=finding.confidence,
            risk_score=computation.score,
            risk_level=risk_level,
            priority=self.priority(risk_level),
            factors=computation.factors,
            recommendation=self.recommendation(risk_level),
        )

    def compute(self, finding: Finding) -> RiskComputation:
        """Compute a deterministic risk score."""
        factors: list[RiskFactorRead] = []

        severity = self.normalized(finding.severity, default="unknown")
        severity_weight = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["unknown"])
        factors.append(
            RiskFactorRead(
                name="severity",
                value=severity,
                weight=severity_weight,
                contribution=severity_weight,
            )
        )

        category = self.normalized(finding.category, default="unknown")
        category_weight = CATEGORY_WEIGHTS.get(category, CATEGORY_WEIGHTS["unknown"])
        factors.append(
            RiskFactorRead(
                name="category",
                value=category,
                weight=category_weight,
                contribution=category_weight,
            )
        )

        source = self.normalized(finding.source, default="manual")
        source_weight = SOURCE_WEIGHTS.get(source, 6.0)
        factors.append(
            RiskFactorRead(
                name="source",
                value=source,
                weight=source_weight,
                contribution=source_weight,
            )
        )

        confidence_contribution = round(max(0.0, min(finding.confidence, 1.0)) * 18.0, 4)
        factors.append(
            RiskFactorRead(
                name="confidence",
                value=f"{finding.confidence:.2f}",
                weight=18.0,
                contribution=confidence_contribution,
            )
        )

        asset_contribution = self.asset_contribution(finding.affected_asset)
        factors.append(
            RiskFactorRead(
                name="affected_asset",
                value=finding.affected_asset or "unknown",
                weight=10.0,
                contribution=asset_contribution,
            )
        )

        score = min(sum(factor.contribution for factor in factors), 100.0)
        return RiskComputation(score=round(score, 2), factors=factors)

    def asset_contribution(self, affected_asset: str | None) -> float:
        """Return extra risk for sensitive-looking assets."""
        if not affected_asset:
            return 0.0

        normalized_asset = affected_asset.lower()
        if any(keyword in normalized_asset for keyword in SENSITIVE_ASSET_KEYWORDS):
            return 10.0

        if "/" in normalized_asset:
            return 5.0

        return 2.0

    def risk_level(self, score: float) -> str:
        """Map score to risk level."""
        if score >= 85.0:
            return "critical"

        if score >= 70.0:
            return "high"

        if score >= 45.0:
            return "medium"

        if score >= 20.0:
            return "low"

        return "informational"

    def priority(self, risk_level: str) -> str:
        """Map risk level to operational priority."""
        if risk_level == "critical":
            return "P0"

        if risk_level == "high":
            return "P1"

        if risk_level == "medium":
            return "P2"

        if risk_level == "low":
            return "P3"

        return "P4"

    def recommendation(self, risk_level: str) -> str:
        """Return remediation prioritization guidance."""
        if risk_level == "critical":
            return "Escalate immediately and assign an incident owner."

        if risk_level == "high":
            return "Prioritize for same-day security review and remediation planning."

        if risk_level == "medium":
            return "Schedule analyst review and validate exploitability."

        if risk_level == "low":
            return "Track in backlog unless new evidence increases impact."

        return "Record for visibility and monitor for related activity."

    def normalized(self, value: str | None, default: str) -> str:
        """Normalize nullable labels."""
        if not value:
            return default

        return value.strip().lower()
