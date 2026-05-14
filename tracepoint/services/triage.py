"""Deterministic vulnerability triage service.

This module provides the first production-safe version of Tracepoint's triage
engine. It intentionally uses explainable rules rather than hidden LLM behavior
so that the API can be tested, audited, and trusted before AI-assisted
classification is introduced.

The service maps common report patterns to vulnerability categories, severity,
CWE/OWASP references, routing teams, remediation guidance, and human review
questions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tracepoint.schemas.triage import (
    TriageRequest,
    TriageResponse,
    TriageSeverity,
    TriageValidity,
    VulnerabilityCategory,
)


@dataclass(frozen=True, slots=True)
class TriageRule:
    """A deterministic matching rule for vulnerability reports."""

    category: VulnerabilityCategory
    severity: TriageSeverity
    cwe: str | None
    owasp: str | None
    routing_team: str
    confidence: float
    keywords: tuple[str, ...]
    remediation_guidance: tuple[str, ...]
    human_review_questions: tuple[str, ...]


class TriageService:
    """Classify incoming vulnerability reports using deterministic rules."""

    def __init__(self) -> None:
        """Initialize the deterministic rule catalog."""
        self.rules = self._build_rules()

    def triage(self, request: TriageRequest) -> TriageResponse:
        """Return a structured triage decision for a vulnerability report."""
        normalized_text = self._normalize_text(
            " ".join(
                part
                for part in [
                    request.title,
                    request.description,
                    request.affected_asset or "",
                    request.source,
                ]
                if part
            )
        )

        rule = self._match_rule(normalized_text)
        reproduction_steps = self._extract_reproduction_steps(request.description)

        if rule is None:
            return self._fallback_response(request, reproduction_steps)

        return TriageResponse(
            validity=TriageValidity.LIKELY_VALID,
            category=rule.category,
            severity=rule.severity,
            cwe=rule.cwe,
            owasp=rule.owasp,
            affected_asset=request.affected_asset,
            reproduction_steps=reproduction_steps,
            evidence_summary=self._build_evidence_summary(request, rule),
            routing_team=rule.routing_team,
            remediation_guidance=list(rule.remediation_guidance),
            human_review_questions=list(rule.human_review_questions),
            confidence=rule.confidence,
        )

    def _match_rule(self, normalized_text: str) -> TriageRule | None:
        """Return the first rule whose keyword set matches the report text."""
        for rule in self.rules:
            if any(keyword in normalized_text for keyword in rule.keywords):
                return rule

        return None

    def _fallback_response(
        self,
        request: TriageRequest,
        reproduction_steps: list[str],
    ) -> TriageResponse:
        """Return a safe human-review response when no rule matches."""
        return TriageResponse(
            validity=TriageValidity.NEEDS_HUMAN_REVIEW,
            category=VulnerabilityCategory.UNKNOWN,
            severity=TriageSeverity.UNKNOWN,
            cwe=None,
            owasp=None,
            affected_asset=request.affected_asset,
            reproduction_steps=reproduction_steps,
            evidence_summary=[
                "No deterministic triage rule matched the submitted report.",
                "Manual analyst review is required before acceptance or closure.",
            ],
            routing_team="security-operations",
            remediation_guidance=[
                (
                    "Review the submitted report text and request additional "
                    "reproduction details if needed."
                )
            ],
            human_review_questions=[
                "What exact asset, endpoint, account, or tenant was affected?",
                "Can the reporter provide timestamps, payloads, or screenshots?",
                "Is there enough evidence to reproduce the reported behavior?",
            ],
            confidence=0.35,
        )

    def _build_evidence_summary(
        self,
        request: TriageRequest,
        rule: TriageRule,
    ) -> list[str]:
        """Build a concise evidence summary for the matched rule."""
        evidence = [
            f"Matched vulnerability category: {rule.category.value}.",
            f"Suggested severity: {rule.severity.value}.",
        ]

        if request.affected_asset:
            evidence.append(f"Affected asset supplied: {request.affected_asset}.")

        evidence.append(f"Report source: {request.source}.")

        return evidence

    def _extract_reproduction_steps(self, description: str) -> list[str]:
        """Extract simple numbered reproduction steps from report text."""
        steps: list[str] = []

        for line in description.splitlines():
            cleaned_line = line.strip()
            match = re.match(r"^\d+[\).\s-]+(.+)$", cleaned_line)

            if match is not None:
                steps.append(match.group(1).strip())

        if steps:
            return steps

        return ["No explicit numbered reproduction steps were provided."]

    def _build_rules(self) -> tuple[TriageRule, ...]:
        """Create the deterministic vulnerability rule catalog."""
        return (
            TriageRule(
                category=VulnerabilityCategory.IDOR,
                severity=TriageSeverity.HIGH,
                cwe="CWE-639",
                owasp="API1: Broken Object Level Authorization",
                routing_team="application-security",
                confidence=0.91,
                keywords=(
                    "idor",
                    "invoice_id",
                    "invoice id",
                    "another tenant",
                    "another customer",
                    "cross tenant",
                    "cross-tenant",
                    "object level authorization",
                ),
                remediation_guidance=(
                    ("Enforce object-level authorization before returning the requested resource."),
                    (
                        "Validate that the authenticated principal belongs to "
                        "the resource owner or tenant."
                    ),
                    ("Add regression tests for cross-tenant and cross-account access attempts."),
                    "Log denied object-access attempts for abuse monitoring.",
                ),
                human_review_questions=(
                    "Can the researcher provide both tenant/account IDs?",
                    "Was the accessed invoice returned with sensitive data?",
                    "Is the endpoint reachable by normal authenticated users?",
                ),
            ),
            TriageRule(
                category=VulnerabilityCategory.EXPOSED_SECRET,
                severity=TriageSeverity.HIGH,
                cwe="CWE-798",
                owasp="API8: Security Misconfiguration",
                routing_team="cloud-security",
                confidence=0.88,
                keywords=(
                    "api key",
                    "secret token",
                    "secret_scan",
                    "secret scan",
                    "github leak",
                    "committed",
                    "credential",
                    "public github",
                    "repository",
                ),
                remediation_guidance=(
                    "Immediately revoke or rotate the exposed credential.",
                    "Identify all systems where the credential was accepted.",
                    "Review logs for usage from unusual IPs, ASNs, or regions.",
                    "Add secret scanning and pre-commit protection if missing.",
                ),
                human_review_questions=(
                    "Is the credential still active?",
                    "Which service account, tenant, or environment owns the key?",
                    "Was the key used after public exposure?",
                ),
            ),
            TriageRule(
                category=VulnerabilityCategory.XSS,
                severity=TriageSeverity.MEDIUM,
                cwe="CWE-79",
                owasp="A03: Injection",
                routing_team="application-security",
                confidence=0.82,
                keywords=(
                    "xss",
                    "cross site scripting",
                    "cross-site scripting",
                    "script alert",
                    "<script",
                    "javascript:",
                    "html injection",
                ),
                remediation_guidance=(
                    "Escape untrusted output in HTML, JavaScript, and URLs.",
                    "Apply context-aware output encoding.",
                    "Validate and sanitize rich text inputs where required.",
                    "Add regression tests for reflected and stored XSS payloads.",
                ),
                human_review_questions=(
                    "Is the payload reflected, stored, or DOM-based?",
                    "Does the payload execute in another user's browser?",
                    "Which browser and account role were used during testing?",
                ),
            ),
            TriageRule(
                category=VulnerabilityCategory.SSRF,
                severity=TriageSeverity.HIGH,
                cwe="CWE-918",
                owasp="API7: Server Side Request Forgery",
                routing_team="platform-security",
                confidence=0.84,
                keywords=(
                    "ssrf",
                    "server side request forgery",
                    "metadata service",
                    "169.254.169.254",
                    "internal url",
                    "localhost",
                    "internal service",
                ),
                remediation_guidance=(
                    "Block requests to private, loopback, and metadata ranges.",
                    "Use allowlists for outbound fetch destinations.",
                    "Disable redirects to untrusted internal destinations.",
                    "Log blocked outbound fetch attempts for monitoring.",
                ),
                human_review_questions=(
                    "Can the reporter access cloud metadata endpoints?",
                    "Can the endpoint reach internal-only services?",
                    "Does the request include sensitive response data?",
                ),
            ),
            TriageRule(
                category=VulnerabilityCategory.AUTH_BYPASS,
                severity=TriageSeverity.CRITICAL,
                cwe="CWE-287",
                owasp="API2: Broken Authentication",
                routing_team="identity-security",
                confidence=0.9,
                keywords=(
                    "auth bypass",
                    "authentication bypass",
                    "bypass login",
                    "without authentication",
                    "missing authentication",
                    "jwt none",
                    "session fixation",
                ),
                remediation_guidance=(
                    "Enforce authentication checks at the route and service layer.",
                    "Reject unsigned, expired, malformed, or downgraded tokens.",
                    "Add negative authorization tests for protected endpoints.",
                    "Review logs for unauthorized access during the exposure window.",
                ),
                human_review_questions=(
                    "Which role or session state was used during reproduction?",
                    "Can the endpoint be accessed without a valid token?",
                    "Did the bypass expose customer or administrative data?",
                ),
            ),
            TriageRule(
                category=VulnerabilityCategory.SUSPICIOUS_AUTHENTICATION,
                severity=TriageSeverity.HIGH,
                cwe="CWE-308",
                owasp="API2: Broken Authentication",
                routing_team="security-operations",
                confidence=0.78,
                keywords=(
                    "impossible travel",
                    "unusual login",
                    "suspicious login",
                    "mfa not observed",
                    "credential stuffing",
                    "session hijack",
                    "token reuse",
                ),
                remediation_guidance=(
                    (
                        "Review authentication logs, MFA status, session "
                        "history, and device fingerprint."
                    ),
                    "Revoke suspicious active sessions if compromise is suspected.",
                    "Force password reset and verify MFA enrollment for users.",
                    (
                        "Open an incident ticket if data access occurred after "
                        "suspicious authentication."
                    ),
                ),
                human_review_questions=(
                    "Were both logins successful?",
                    "Was MFA completed or bypassed?",
                    "Was sensitive data accessed after the suspicious login?",
                ),
            ),
        )

    @staticmethod
    def _normalize_text(value: str) -> str:
        """Normalize free text for deterministic keyword matching."""
        return value.lower().replace("_", " ").replace("-", " ")
