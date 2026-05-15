"""Tests for finding export endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_export_findings_json() -> None:
    """Export findings as JSON records."""
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

        response = client.get("/api/v1/export/findings?format=json")

    assert response.status_code == 200
    payload = response.json()

    assert payload["format"] == "json"
    assert payload["count"] >= 1
    assert payload["content"] is None
    assert any(record["title"] == "IDOR in invoice retrieval" for record in payload["records"])


def test_export_findings_csv() -> None:
    """Export findings as CSV content."""
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

        response = client.get("/api/v1/export/findings?format=csv")

    assert response.status_code == 200
    payload = response.json()

    assert payload["format"] == "csv"
    assert payload["count"] >= 1
    assert payload["records"] == []
    assert payload["content"] is not None
    assert payload["content"].startswith("id,title,description,source,severity,status,category,")
    assert "Suspicious login activity" in payload["content"]
    assert "account_compromise" in payload["content"]


def test_export_findings_rejects_invalid_format() -> None:
    """Reject unsupported export formats."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/export/findings?format=xml")

    assert response.status_code == 422
