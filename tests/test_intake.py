"""Report intake endpoint tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_intake_report_persists_finding_and_triage() -> None:
    """Ingest a report, classify it, and persist the resulting records."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/intake/reports",
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

    assert response.status_code == 201
    payload = response.json()

    assert payload["persisted"] is True
    assert payload["finding_id"] is not None
    assert payload["triage_result_id"] is not None
    assert payload["triage"]["category"] == "idor"
    assert payload["triage"]["severity"] == "high"


def test_intake_report_can_run_without_persistence() -> None:
    """Allow analysis-only intake without writing records."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/intake/reports",
            json={
                "title": "GitHub leak exposed API key",
                "description": (
                    "A secret token and API key were committed to a public GitHub "
                    "repository. The credential appears active."
                ),
                "source": "secret_scan",
                "affected_asset": "public repository",
                "persist": False,
            },
        )

    assert response.status_code == 201
    payload = response.json()

    assert payload["persisted"] is False
    assert payload["finding_id"] is None
    assert payload["triage_result_id"] is None
    assert payload["triage"]["category"] == "exposed_secret"


def test_intake_detects_duplicate_against_existing_finding() -> None:
    """Detect a likely duplicate during intake."""
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

        response = client.post(
            "/api/v1/intake/reports",
            json={
                "title": "Invoice IDOR vulnerability",
                "description": (
                    "Changing invoice_id in /v1/invoices/{invoice_id} returns "
                    "another customer's invoice data."
                ),
                "source": "bug_bounty",
                "category": "idor",
                "affected_asset": "/v1/invoices/{invoice_id}",
            },
        )

    assert response.status_code == 201
    payload = response.json()

    assert payload["duplicate"]["is_duplicate"] is True
    assert payload["duplicate"]["finding_id"] is not None
    assert payload["duplicate"]["score"] >= 0.45


def test_intake_rejects_short_report() -> None:
    """Reject invalid intake payloads at the schema boundary."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/intake/reports",
            json={
                "title": "bad",
                "description": "short",
            },
        )

    assert response.status_code == 422
