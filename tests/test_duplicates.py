"""Duplicate detection endpoint tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_duplicate_check_finds_similar_finding() -> None:
    """Return likely duplicate when a report matches a stored finding."""

    with TestClient(create_app()) as client:
        create_response = client.post(
            "/api/v1/findings",
            json={
                "title": "IDOR in invoice retrieval",
                "description": ("Changing invoice_id allows access to another tenant invoice."),
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
            "/api/v1/duplicates/check",
            json={
                "title": "Invoice IDOR vulnerability",
                "description": (
                    "Changing invoice_id in /v1/invoices/{invoice_id} returns "
                    "another customer's invoice data."
                ),
                "category": "idor",
                "affected_asset": "/v1/invoices/{invoice_id}",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] in {"likely_duplicate", "possible_duplicate"}
    assert payload["highest_similarity"] > 0.65
    assert len(payload["candidates"]) >= 1
    assert payload["candidates"][0]["category"] == "idor"


def test_duplicate_check_returns_not_duplicate_without_history() -> None:
    """Return no duplicate when there are no historical findings."""

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/duplicates/check",
            json={
                "title": "Unrelated suspicious login",
                "description": "User logged in from a new location after MFA reset.",
                "category": "account_compromise",
                "affected_asset": "auth service",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "not_duplicate"
    assert payload["highest_similarity"] == 0.0
    assert payload["candidates"] == []


def test_duplicate_check_rejects_invalid_payload() -> None:
    """Reject invalid duplicate check requests at schema boundary."""

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/duplicates/check",
            json={
                "title": "bad",
                "description": "short",
            },
        )

    assert response.status_code == 422
