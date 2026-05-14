"""Tests for dashboard trend analytics."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_dashboard_trends_returns_valid_shape() -> None:
    """Return trend analytics with stable response shape."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/dashboard/trends")

    assert response.status_code == 200
    payload = response.json()

    assert isinstance(payload["total_findings"], int)
    assert isinstance(payload["severity_counts"], list)
    assert isinstance(payload["category_counts"], list)
    assert isinstance(payload["source_counts"], list)
    assert len(payload["daily_findings"]) == 14

    for item in payload["daily_findings"]:
        assert set(item) == {"date", "count"}
        assert isinstance(item["date"], str)
        assert isinstance(item["count"], int)


def test_dashboard_trends_counts_findings() -> None:
    """Return severity, category, source, and daily finding counts."""
    with TestClient(create_app()) as client:
        first_response = client.post(
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
        second_response = client.post(
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

        assert first_response.status_code == 201
        assert second_response.status_code == 201

        response = client.get("/api/v1/dashboard/trends?days=7")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total_findings"] >= 2
    assert len(payload["daily_findings"]) == 7

    severity_counts = {bucket["name"]: bucket["count"] for bucket in payload["severity_counts"]}
    category_counts = {bucket["name"]: bucket["count"] for bucket in payload["category_counts"]}
    source_counts = {bucket["name"]: bucket["count"] for bucket in payload["source_counts"]}

    assert severity_counts["high"] >= 1
    assert severity_counts["medium"] >= 1
    assert category_counts["idor"] >= 1
    assert category_counts["account_compromise"] >= 1
    assert source_counts["bug_bounty"] >= 1
    assert source_counts["manual"] >= 1


def test_dashboard_trends_rejects_invalid_days() -> None:
    """Reject invalid day windows."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/dashboard/trends?days=0")

    assert response.status_code == 422
