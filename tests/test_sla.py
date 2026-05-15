"""Tests for SLA and remediation timeline endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_get_high_risk_finding_sla() -> None:
    """Return SLA timeline for a high-risk finding."""
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

        response = client.get(f"/api/v1/risk/findings/{finding_id}/sla")

    assert response.status_code == 200
    payload = response.json()

    assert payload["finding_id"] == finding_id
    assert payload["priority"] in {"P0", "P1", "P2"}
    assert payload["risk_level"] in {"critical", "high", "medium"}
    assert payload["sla_hours"] in {4, 24, 72, 168, 720}
    assert payload["risk_score"] >= 0.0
    assert payload["recommendation"]

    created_at = datetime.fromisoformat(payload["created_at"])
    due_at = datetime.fromisoformat(payload["due_at"])

    assert due_at > created_at


def test_get_low_risk_finding_sla() -> None:
    """Return longer SLA for lower-risk findings."""
    with TestClient(create_app()) as client:
        create_response = client.post(
            "/api/v1/findings",
            json={
                "title": "Informational UI issue",
                "description": "A minor visual issue appears on the settings page.",
                "source": "manual",
                "severity": "low",
                "category": "informational",
                "affected_asset": "settings page",
                "confidence": 0.4,
            },
        )

        assert create_response.status_code == 201
        finding_id = create_response.json()["id"]

        response = client.get(f"/api/v1/risk/findings/{finding_id}/sla")

    assert response.status_code == 200
    payload = response.json()

    assert payload["risk_score"] < 45.0
    assert payload["priority"] in {"P3", "P4"}
    assert payload["sla_hours"] in {168, 720}
    assert payload["recommendation"]


def test_get_sla_for_missing_finding_returns_404() -> None:
    """Return 404 when SLA is requested for a missing finding."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/risk/findings/missing-finding-id/sla")

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"
