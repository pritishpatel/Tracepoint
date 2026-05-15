"""Tests for bulk finding import routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tracepoint.app import create_app
from tracepoint.db import get_database_manager


@pytest.fixture(autouse=True)
def reset_database_schema() -> None:
    """Create a clean local schema for each import API test."""
    database = get_database_manager()
    database.drop_schema_for_development()
    database.create_schema_for_development()


def test_import_findings_creates_records() -> None:
    """Import multiple finding-like records through intake."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/import/findings",
            json={
                "source": "scanner",
                "items": [
                    {
                        "title": "Exposed API key in GitHub repository",
                        "description": (
                            "A secret scanning alert detected an active API key "
                            "committed to a public repository."
                        ),
                        "category": "exposed_secret",
                        "affected_asset": "github/example-repo",
                        "reporter": "secret-scanner",
                    },
                    {
                        "title": "IDOR in invoice retrieval",
                        "description": (
                            "Changing invoice_id allows access to another tenant invoice."
                        ),
                        "category": "idor",
                        "affected_asset": "/v1/invoices/{invoice_id}",
                        "reporter": "bug-bounty",
                    },
                ],
            },
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["received"] == 2
    assert payload["created"] == 2
    assert payload["failed"] == 0
    assert len(payload["results"]) == 2
    assert payload["results"][0]["finding_id"] is not None
    assert payload["results"][0]["triage_result_id"] is not None


def test_import_findings_supports_analysis_only() -> None:
    """Import records without persistence."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/import/findings",
            json={
                "source": "manual",
                "persist": False,
                "items": [
                    {
                        "title": "Suspicious login activity",
                        "description": ("User logged in from a new location after MFA reset."),
                        "category": "account_compromise",
                        "affected_asset": "auth service",
                    }
                ],
            },
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["received"] == 1
    assert payload["created"] == 0
    assert payload["failed"] == 0
    assert payload["results"][0]["persisted"] is False
    assert payload["results"][0]["finding_id"] is None
    assert payload["results"][0]["triage_result_id"] is None


def test_import_findings_rejects_empty_items() -> None:
    """Reject empty import payloads."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/import/findings",
            json={
                "source": "scanner",
                "items": [],
            },
        )

    assert response.status_code == 422
