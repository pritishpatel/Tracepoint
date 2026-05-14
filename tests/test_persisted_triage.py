"""Persisted triage workflow tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_triage_can_persist_finding_and_result() -> None:
    """Persisted triage creates both a finding and a triage result."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/triage?persist=true",
            json={
                "title": "IDOR in invoice retrieval",
                "description": (
                    "Changing invoice_id in /v1/invoices/{invoice_id} allows "
                    "access to another tenant invoice."
                ),
                "source": "bug_bounty",
                "affected_asset": "/v1/invoices/{invoice_id}",
                "reporter": "security-researcher",
            },
        )

        assert response.status_code == 200
        payload = response.json()

        assert payload["finding_id"]
        assert payload["triage_result_id"]
        assert payload["triage"]["category"] == "idor"
        assert payload["triage"]["severity"] == "high"

        finding_response = client.get(f"/api/v1/findings/{payload['finding_id']}")
        assert finding_response.status_code == 200

        finding = finding_response.json()
        assert finding["title"] == "IDOR in invoice retrieval"
        assert finding["category"] == "idor"
        assert finding["severity"] == "high"


def test_triage_without_persistence_does_not_return_ids() -> None:
    """Default triage remains analysis-only."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/triage",
            json={
                "title": "GitHub leak exposed API key",
                "description": (
                    "A secret token and API key were committed to a public GitHub repository."
                ),
                "source": "secret_scan",
                "affected_asset": "public repository",
            },
        )

        assert response.status_code == 200
        payload = response.json()

        assert "finding_id" not in payload
        assert "triage_result_id" not in payload
        assert payload["category"] == "exposed_secret"
