"""Tests for finding risk scoring."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_score_high_risk_finding() -> None:
    """Score a high-impact finding."""
    with TestClient(create_app()) as client:
        create_response = client.post(
            "/api/v1/findings",
            json={
                "title": "IDOR in invoice retrieval",
                "description": "Changing invoice_id allows access to another tenant invoice.",
                "source": "bug_bounty",
                "severity": "high",
                "category": "idor",
                "affected_asset": "/v1/invoices/{invoice_id}",
                "reporter": "security-researcher",
                "confidence": 0.91,
            },
        )

        assert create_response.status_code == 201
        finding_id = create_response.json()["id"]

        response = client.get(f"/api/v1/risk/findings/{finding_id}")

    assert response.status_code == 200
    payload = response.json()

    assert payload["finding_id"] == finding_id
    assert payload["risk_score"] >= 70.0
    assert payload["risk_level"] in {"high", "critical"}
    assert payload["priority"] in {"P0", "P1"}
    assert len(payload["factors"]) >= 5
    assert payload["recommendation"]


def test_score_lower_risk_finding() -> None:
    """Score a lower-risk finding."""
    with TestClient(create_app()) as client:
        create_response = client.post(
            "/api/v1/findings",
            json={
                "title": "Minor security header missing",
                "description": "A non-critical informational header appears to be missing.",
                "source": "manual",
                "severity": "low",
                "category": "unknown",
                "affected_asset": "marketing page",
                "confidence": 0.4,
            },
        )

        assert create_response.status_code == 201
        finding_id = create_response.json()["id"]

        response = client.get(f"/api/v1/risk/findings/{finding_id}")

    assert response.status_code == 200
    payload = response.json()

    assert payload["risk_score"] < 45.0
    assert payload["risk_level"] in {"informational", "low"}
    assert payload["priority"] in {"P3", "P4"}


def test_score_missing_finding_returns_404() -> None:
    """Return 404 for missing finding."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/risk/findings/missing-finding-id")

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"
