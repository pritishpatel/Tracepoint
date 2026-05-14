"""Tests for activity timeline endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tracepoint.app import create_app
from tracepoint.db import get_database_manager


@pytest.fixture(autouse=True)
def reset_database_schema() -> None:
    """Create a clean local schema for each activity API test."""
    database = get_database_manager()
    database.drop_schema_for_development()
    database.create_schema_for_development()


def test_activity_timeline_starts_empty() -> None:
    """Return an empty timeline when no records exist."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/activity")

    assert response.status_code == 200
    payload = response.json()

    assert payload["items"] == []
    assert payload["total"] == 0
    assert payload["limit"] == 20


def test_activity_timeline_includes_findings_and_triage() -> None:
    """Return recent finding and triage events."""
    with TestClient(create_app()) as client:
        intake_response = client.post(
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

        assert intake_response.status_code == 201

        response = client.get("/api/v1/activity?limit=10")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total"] >= 2
    assert payload["limit"] == 10

    activity_types = {item["type"] for item in payload["items"]}
    assert "finding_created" in activity_types
    assert "triage_completed" in activity_types

    first_item = payload["items"][0]
    assert first_item["entity_id"] is not None
    assert first_item["title"]


def test_activity_timeline_rejects_invalid_limit() -> None:
    """Reject invalid activity limits at the schema boundary."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/activity?limit=0")

    assert response.status_code == 422
