"""Finding API tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_create_and_get_finding() -> None:
    """Create a finding and fetch it by ID."""
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
        created_finding = create_response.json()
        assert created_finding["title"] == "IDOR in invoice retrieval"
        assert created_finding["source"] == "bug_bounty"
        assert created_finding["severity"] == "high"
        assert created_finding["status"] == "new"

        get_response = client.get(f"/api/v1/findings/{created_finding['id']}")

        assert get_response.status_code == 200
        fetched_finding = get_response.json()
        assert fetched_finding["id"] == created_finding["id"]
        assert fetched_finding["affected_asset"] == "/v1/invoices/{invoice_id}"


def test_list_findings() -> None:
    """List findings using the default pagination window."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/findings")

        assert response.status_code == 200
        payload = response.json()
        assert "items" in payload
        assert "total" in payload
        assert payload["limit"] == 50
        assert payload["offset"] == 0


def test_get_missing_finding_returns_404() -> None:
    """Return 404 when a finding ID does not exist."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/findings/missing-finding-id")

        assert response.status_code == 404
        assert response.json()["detail"] == "Finding not found"
