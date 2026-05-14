"""Finding API tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tracepoint.app import create_app
from tracepoint.db import get_database_manager


@pytest.fixture(autouse=True)
def reset_database_schema() -> None:
    """Create a clean local schema for each finding API test."""
    database = get_database_manager()
    database.drop_schema_for_development()
    database.create_schema_for_development()


def test_create_and_get_finding() -> None:
    client = TestClient(create_app())

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
    created_payload = create_response.json()
    assert created_payload["title"] == "IDOR in invoice retrieval"
    assert created_payload["source"] == "bug_bounty"
    assert created_payload["severity"] == "high"

    get_response = client.get(f"/api/v1/findings/{created_payload['id']}")

    assert get_response.status_code == 200
    fetched_payload = get_response.json()
    assert fetched_payload["id"] == created_payload["id"]
    assert fetched_payload["affected_asset"] == "/v1/invoices/{invoice_id}"


def test_list_findings() -> None:
    client = TestClient(create_app())

    response = client.get("/api/v1/findings")

    assert response.status_code == 200
    payload = response.json()
    assert "items" in payload
    assert "total" in payload
    assert payload["limit"] == 50
    assert payload["offset"] == 0


def test_get_missing_finding_returns_404() -> None:
    client = TestClient(create_app())

    response = client.get("/api/v1/findings/missing-finding-id")

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"
