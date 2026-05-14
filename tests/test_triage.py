"""Deterministic triage endpoint tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_triage_idor_report() -> None:
    """Classify a likely IDOR report with security mapping and routing."""
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/triage",
        json={
            "title": "IDOR in invoice retrieval",
            "description": (
                "Changing invoice_id in /v1/invoices/{invoice_id} allows "
                "access to another tenant invoice. "
                "1. Login as user A\n"
                "2. Request user B invoice ID\n"
                "3. Observe invoice data returned"
            ),
            "source": "bug_bounty",
            "affected_asset": "/v1/invoices/{invoice_id}",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["validity"] == "likely_valid"
    assert payload["category"] == "idor"
    assert payload["severity"] == "high"
    assert payload["cwe"] == "CWE-639"
    assert payload["owasp"] == "API1: Broken Object Level Authorization"
    assert payload["routing_team"] == "application-security"
    assert payload["confidence"] >= 0.70
    assert payload["human_review_questions"]


def test_triage_exposed_secret_report() -> None:
    """Classify exposed credential reports."""
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/triage",
        json={
            "title": "GitHub leak exposed API key",
            "description": (
                "A secret token and API key were committed to a public GitHub "
                "repository. The credential appears active."
            ),
            "source": "secret_scan",
            "affected_asset": "public repository",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["category"] == "exposed_secret"
    assert payload["severity"] == "high"
    assert payload["cwe"] == "CWE-798"
    assert payload["routing_team"] == "cloud-security"


def test_triage_unknown_report_needs_human_review() -> None:
    """Fallback safely when a report does not match a deterministic rule."""
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/triage",
        json={
            "title": "Unclear application behavior",
            "description": "The application behaved strangely after clicking around.",
            "source": "manual",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["validity"] == "needs_human_review"
    assert payload["category"] == "unknown"
    assert payload["severity"] == "unknown"
    assert payload["routing_team"] == "security-operations"


def test_triage_rejects_short_report() -> None:
    """Reject invalid triage requests at the schema boundary."""
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/triage",
        json={
            "title": "bad",
            "description": "too short",
            "source": "manual",
        },
    )

    assert response.status_code == 422
