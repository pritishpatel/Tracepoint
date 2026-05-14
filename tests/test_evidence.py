"""Evidence bundle endpoint tests."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_generate_evidence_bundle_for_finding() -> None:
    """Generate Markdown and JSON evidence artifacts for a finding."""
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

        response = client.post(
            f"/api/v1/findings/{finding_id}/evidence",
            json={
                "include_triage": True,
                "include_markdown": True,
                "include_json": True,
            },
        )

    assert response.status_code == 201
    payload = response.json()

    assert payload["finding_id"] == finding_id
    assert payload["artifact_count"] == 2
    assert payload["markdown_path"] is not None
    assert payload["json_path"] is not None

    markdown_path = Path(payload["markdown_path"])
    json_path = Path(payload["json_path"])

    assert markdown_path.exists()
    assert json_path.exists()
    assert "IDOR in invoice retrieval" in markdown_path.read_text(encoding="utf-8")


def test_generate_evidence_bundle_without_json() -> None:
    """Generate only a Markdown evidence bundle when JSON is disabled."""
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

        response = client.post(
            f"/api/v1/findings/{finding_id}/evidence",
            json={
                "include_triage": False,
                "include_markdown": True,
                "include_json": False,
            },
        )

    assert response.status_code == 201
    payload = response.json()

    assert payload["artifact_count"] == 1
    assert payload["included_triage"] is False
    assert payload["markdown_path"] is not None
    assert payload["json_path"] is None


def test_generate_evidence_bundle_for_missing_finding_returns_404() -> None:
    """Return 404 when evidence is requested for a missing finding."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/findings/missing-finding-id/evidence",
            json={},
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"
