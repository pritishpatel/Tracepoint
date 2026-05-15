"""Finding API tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tracepoint.app import app, create_app
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


def test_get_finding_provenance_returns_parsed_cisa_metadata(
    reset_database_schema,
) -> None:
    """Finding provenance endpoint should parse CISA KEV description fields."""
    client = TestClient(app)
    create_response = client.post(
        "/api/v1/findings",
        json={
            "title": "CVE-2026-20182: Cisco Catalyst SD-WAN",
            "description": (
                "Source dataset: CISA Known Exploited Vulnerabilities Catalog\n"
                "Source URL: https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json\n"
                "Catalog version: 2026.05.14\n"
                "Catalog release date: 2026-05-14T17:31:13.2397Z\n"
                "Catalog total records: 1591\n"
                "CVE: CVE-2026-20182\n"
                "Vendor/Project: Cisco\n"
                "Product: Catalyst SD-WAN\n"
                "Vulnerability: Cisco Catalyst SD-WAN Controller "
                "Authentication Bypass Vulnerability\n"
                "CWE(s): CWE-287, CWE-306\n"
                "Date added to KEV: 2026-05-14\n"
                "Due date: 2026-05-17\n"
                "Known ransomware use: Unknown\n"
                "Notes: https://nvd.nist.gov/vuln/detail/CVE-2026-20182"
            ),
            "source": "manual",
            "severity": "critical",
            "category": "auth_bypass",
            "affected_asset": "Cisco Catalyst SD-WAN CVE-2026-20182",
            "reporter": "cisa-kev-catalog",
            "confidence": 0.95,
        },
    )

    assert create_response.status_code == 201
    finding_id = create_response.json()["id"]

    response = client.get(f"/api/v1/findings/{finding_id}/provenance")

    assert response.status_code == 200
    payload = response.json()

    assert payload["finding_id"] == finding_id
    assert payload["source_dataset"] == "CISA Known Exploited Vulnerabilities Catalog"
    assert payload["catalog_version"] == "2026.05.14"
    assert payload["catalog_total_records"] == 1591
    assert payload["cve"] == "CVE-2026-20182"
    assert payload["cwes"] == ["CWE-287", "CWE-306"]
    assert payload["vendor_project"] == "Cisco"
    assert payload["product"] == "Catalyst SD-WAN"
    assert payload["known_ransomware_use"] == "Unknown"


def test_get_finding_provenance_returns_404_for_missing_finding(
    reset_database_schema,
) -> None:
    """Missing finding provenance should return 404."""
    client = TestClient(app)
    response = client.get("/api/v1/findings/not-a-real-id/provenance")

    assert response.status_code == 404


def test_get_finding_kev_detail_returns_prioritized_cisa_metadata(
    reset_database_schema,
) -> None:
    """KEV detail endpoint should return operational prioritization metadata."""
    client = TestClient(app)

    create_response = client.post(
        "/api/v1/findings",
        json={
            "title": "CVE-2026-20182: Cisco Catalyst SD-WAN",
            "description": (
                "Source dataset: CISA Known Exploited Vulnerabilities Catalog\n"
                "Source URL: https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json\n"
                "Catalog version: 2026.05.14\n"
                "Catalog release date: 2026-05-14T17:31:13.2397Z\n"
                "Catalog total records: 1591\n"
                "CVE: CVE-2026-20182\n"
                "Vendor/Project: Cisco\n"
                "Product: Catalyst SD-WAN\n"
                "Vulnerability: Cisco Catalyst SD-WAN Controller "
                "Authentication Bypass Vulnerability\n"
                "CWE(s): CWE-287\n"
                "Date added to KEV: 2026-05-14\n"
                "Required action: Apply emergency mitigation guidance.\n"
                "Due date: 2026-05-17\n"
                "Known ransomware use: Unknown\n"
                "Notes: https://nvd.nist.gov/vuln/detail/CVE-2026-20182"
            ),
            "source": "manual",
            "severity": "critical",
            "category": "auth_bypass",
            "affected_asset": "Cisco Catalyst SD-WAN CVE-2026-20182",
            "reporter": "cisa-kev-catalog",
            "confidence": 0.95,
        },
    )

    assert create_response.status_code == 201
    finding_id = create_response.json()["id"]

    response = client.get(f"/api/v1/findings/{finding_id}/kev-detail")

    assert response.status_code == 200
    payload = response.json()

    assert payload["finding_id"] == finding_id
    assert payload["cve"] == "CVE-2026-20182"
    assert payload["vendor_project"] == "Cisco"
    assert payload["product"] == "Catalyst SD-WAN"
    assert payload["cwes"] == ["CWE-287"]
    assert payload["kev_date_added"] == "2026-05-14"
    assert payload["kev_due_date"] == "2026-05-17"
    assert payload["known_ransomware_use"] is False
    assert payload["required_action"] == "Apply emergency mitigation guidance."
    assert payload["severity"] == "critical"
    assert payload["category"] == "auth_bypass"
    assert "CVE-2026-20182" in payload["priority_reason"]


def test_get_finding_kev_detail_returns_404_for_missing_finding(
    reset_database_schema,
) -> None:
    """Missing KEV detail should return 404."""
    client = TestClient(app)

    response = client.get("/api/v1/findings/not-a-real-id/kev-detail")

    assert response.status_code == 404


def test_get_finding_kev_summary_returns_collection_metrics(
    reset_database_schema,
) -> None:
    """KEV summary endpoint should aggregate CISA KEV operational metrics."""
    client = TestClient(app)

    records = [
        {
            "title": "CVE-2026-1001: Example Critical",
            "description": (
                "Source dataset: CISA Known Exploited Vulnerabilities Catalog\n"
                "CVE: CVE-2026-1001\n"
                "Vendor/Project: ExampleVendor\n"
                "Product: ExampleProduct\n"
                "Vulnerability: Example Critical Vulnerability\n"
                "CWE(s): CWE-287\n"
                "Date added to KEV: 2026-05-01\n"
                "Required action: Patch immediately.\n"
                "Due date: 2026-05-10\n"
                "Known ransomware use: Known\n"
                "Notes: https://nvd.nist.gov/vuln/detail/CVE-2026-1001"
            ),
            "source": "cisa_kev",
            "severity": "critical",
            "category": "auth_bypass",
            "affected_asset": "ExampleProduct CVE-2026-1001",
            "confidence": 0.95,
        },
        {
            "title": "CVE-2026-1002: Example High",
            "description": (
                "Source dataset: CISA Known Exploited Vulnerabilities Catalog\n"
                "CVE: CVE-2026-1002\n"
                "Vendor/Project: ExampleVendor\n"
                "Product: ExampleProductTwo\n"
                "Vulnerability: Example High Vulnerability\n"
                "CWE(s): CWE-22\n"
                "Date added to KEV: 2026-05-02\n"
                "Required action: Apply mitigations.\n"
                "Due date: 2099-05-10\n"
                "Known ransomware use: Unknown\n"
                "Notes: https://nvd.nist.gov/vuln/detail/CVE-2026-1002"
            ),
            "source": "cisa_kev",
            "severity": "high",
            "category": "path_traversal",
            "affected_asset": "ExampleProductTwo CVE-2026-1002",
            "confidence": 0.95,
        },
        {
            "title": "Manual finding should not be counted",
            "description": "This is a regular manual finding, not a CISA KEV item.",
            "source": "manual",
            "severity": "critical",
            "category": "manual",
            "affected_asset": "internal app",
            "confidence": 0.5,
        },
    ]

    for record in records:
        response = client.post("/api/v1/findings", json=record)
        assert response.status_code == 201

    response = client.get("/api/v1/findings/kev-summary")

    assert response.status_code == 200
    payload = response.json()

    assert payload["total_kev_findings"] == 2
    assert payload["critical"] == 1
    assert payload["high"] == 1
    assert payload["medium"] == 0
    assert payload["known_ransomware_use"] == 1
    assert payload["overdue"] >= 1
    assert len(payload["top_due_items"]) == 2
    assert payload["top_due_items"][0]["cve"] == "CVE-2026-1001"
    assert payload["top_due_items"][0]["known_ransomware_use"] is True
