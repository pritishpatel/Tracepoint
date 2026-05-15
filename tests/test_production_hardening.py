"""Tests for production-readiness hardening."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tracepoint.app import create_app
from tracepoint.db import get_database_manager


@pytest.fixture(autouse=True)
def reset_database_schema() -> None:
    """Create a clean local schema for production hardening tests."""
    database = get_database_manager()
    database.drop_schema_for_development()
    database.create_schema_for_development()


def test_security_headers_are_attached() -> None:
    """Attach baseline security and request identity headers."""
    with TestClient(create_app()) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Request-ID"]


def test_findings_support_filtering_and_search() -> None:
    """Filter findings by severity, source, category, and search text."""
    with TestClient(create_app()) as client:
        response = client.post(
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
        assert response.status_code == 201

        filtered = client.get(
            "/api/v1/findings",
            params={
                "severity": "high",
                "source": "bug_bounty",
                "category": "idor",
                "search": "invoice",
            },
        )

    assert filtered.status_code == 200
    payload = filtered.json()
    assert payload["total"] == 1
    assert payload["items"][0]["title"] == "IDOR in invoice retrieval"


def test_mutating_routes_can_require_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Require a bearer token for mutating routes when auth is enforced."""
    monkeypatch.setenv("TRACEPOINT_AUTH_REQUIRED", "true")

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/findings",
            json={
                "title": "Missing auth finding",
                "description": "This request should be rejected before persistence.",
                "source": "manual",
                "severity": "low",
            },
        )

    assert response.status_code == 401
