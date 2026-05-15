"""Tests for finding comments."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tracepoint.app import create_app


def test_add_and_list_finding_comments() -> None:
    """Add and retrieve comments for a finding."""
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

        comment_response = client.post(
            f"/api/v1/findings/{finding_id}/comments",
            json={
                "author": "analyst@example.com",
                "body": "Validated reproduction path and assigned for remediation.",
            },
        )

        list_response = client.get(f"/api/v1/findings/{finding_id}/comments")

    assert comment_response.status_code == 201
    comment_payload = comment_response.json()

    assert comment_payload["finding_id"] == finding_id
    assert comment_payload["author"] == "analyst@example.com"
    assert "Validated reproduction path" in comment_payload["body"]

    assert list_response.status_code == 200
    list_payload = list_response.json()

    assert list_payload["finding_id"] == finding_id
    assert list_payload["count"] >= 1
    assert any(
        comment["body"] == "Validated reproduction path and assigned for remediation."
        for comment in list_payload["comments"]
    )


def test_add_comment_missing_finding_returns_404() -> None:
    """Return 404 when adding a comment to a missing finding."""
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/findings/missing-finding-id/comments",
            json={
                "author": "analyst@example.com",
                "body": "This should not be attached.",
            },
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"


def test_list_comments_missing_finding_returns_404() -> None:
    """Return 404 when listing comments for a missing finding."""
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/findings/missing-finding-id/comments")

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"
