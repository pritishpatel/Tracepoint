"""Tests for finding workflow endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_update_finding_status() -> None:
    """Update a finding workflow status."""
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

        response = client.patch(
            f"/api/v1/workflow/findings/{finding_id}/status",
            json={
                "status": "in_progress",
                "note": "Assigned to application security analyst.",
            },
        )

    assert response.status_code == 200
    payload = response.json()

    assert payload["finding_id"] == finding_id
    assert payload["previous_status"] == "new"
    assert payload["status"] == "in_progress"
    assert payload["changed"] is True
    assert payload["note"] == "Assigned to application security analyst."


def test_update_finding_status_is_idempotent() -> None:
    """Return changed=false when status is already set."""
    with TestClient(create_app()) as client:
        create_response = client.post(
            "/api/v1/findings",
            json={
                "title": "Suspicious login activity",
                "description": "User logged in from a new location after MFA reset.",
                "source": "manual",
                "severity": "medium",
                "category": "account_compromise",
                "affected_asset": "auth service",
                "confidence": 0.7,
            },
        )

        assert create_response.status_code == 201
        finding_id = create_response.json()["id"]

        first_response = client.patch(
            f"/api/v1/workflow/findings/{finding_id}/status",
            json={"status": "triaged"},
        )
        assert first_response.status_code == 200

        second_response = client.patch(
            f"/api/v1/workflow/findings/{finding_id}/status",
            json={"status": "triaged"},
        )

    assert second_response.status_code == 200
    payload = second_response.json()

    assert payload["previous_status"] == "triaged"
    assert payload["status"] == "triaged"
    assert payload["changed"] is False


def test_update_missing_finding_status_returns_404() -> None:
    """Return 404 for missing finding."""
    with TestClient(create_app()) as client:
        response = client.patch(
            "/api/v1/workflow/findings/missing-finding-id/status",
            json={"status": "resolved"},
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"


def test_update_finding_status_rejects_invalid_status() -> None:
    """Reject unsupported workflow statuses."""
    with TestClient(create_app()) as client:
        create_response = client.post(
            "/api/v1/findings",
            json={
                "title": "Weak cache policy",
                "description": "Sensitive page may be cached by browser.",
                "source": "manual",
                "severity": "low",
                "category": "configuration",
                "affected_asset": "web app",
                "confidence": 0.5,
            },
        )

        assert create_response.status_code == 201
        finding_id = create_response.json()["id"]

        response = client.patch(
            f"/api/v1/workflow/findings/{finding_id}/status",
            json={"status": "totally_invalid"},
        )

    assert response.status_code == 422
