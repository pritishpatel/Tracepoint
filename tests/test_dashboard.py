"""Tests for dashboard summary endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tracepoint.app import create_app
from tracepoint.db import get_database_manager


@pytest.fixture(autouse=True)
def reset_database_schema() -> None:
    """Create a clean local schema for each dashboard API test."""
    database = get_database_manager()
    database.drop_schema_for_development()
    database.create_schema_for_development()


def test_dashboard_summary_empty_state() -> None:
    """Return zero-count dashboard summary when no findings exist."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total_findings"] == 0
    assert payload["open_findings"] == 0
    assert payload["triage_results"] == 0
    assert payload["high_severity_findings"] == 0
    assert payload["by_severity"] == []
    assert payload["recent_findings"] == []


def test_dashboard_summary_counts_findings_and_triage_results() -> None:
    """Aggregate findings and persisted triage results for dashboard views."""
    with TestClient(create_app()) as client:
        finding_response = client.post(
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
        assert finding_response.status_code == 201

        triage_response = client.post(
            "/api/v1/triage?persist=true",
            json={
                "title": "GitHub leak exposed API key",
                "description": "A secret token and API key were committed publicly.",
                "source": "secret_scan",
                "affected_asset": "public repository",
            },
        )
        assert triage_response.status_code == 200

        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total_findings"] == 2
    assert payload["open_findings"] == 2
    assert payload["triage_results"] == 1
    assert payload["high_severity_findings"] >= 1
    assert payload["recent_findings"]

    severity_counts = {item["name"]: item["count"] for item in payload["by_severity"]}
    source_counts = {item["name"]: item["count"] for item in payload["by_source"]}
    category_counts = {item["name"]: item["count"] for item in payload["by_category"]}

    assert severity_counts["high"] >= 1
    assert source_counts["bug_bounty"] == 1
    assert category_counts["idor"] == 1
