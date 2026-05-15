"""Tests for the CISA KEV import script."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.import_cisa_kev import (
    build_tracepoint_payload,
    category_from_kev,
    load_json_from_file,
    map_kev_record,
    severity_from_kev,
)
from tracepoint.schemas.imports import FindingImportCreate


def test_load_cisa_kev_fixture() -> None:
    """Load local CISA KEV fixture."""
    payload = load_json_from_file(Path("tests/fixtures/cisa_kev_sample.json"))

    assert payload["count"] == 2
    assert len(payload["vulnerabilities"]) == 2


def test_map_kev_record_to_tracepoint_item() -> None:
    """Map one KEV record into Tracepoint import format."""
    payload = load_json_from_file(Path("tests/fixtures/cisa_kev_sample.json"))
    record = payload["vulnerabilities"][0]

    item = map_kev_record(record)

    assert item["source"] == "cisa_kev"
    assert item["severity"] == "critical"
    assert item["category"] == "remote_code_execution"
    assert item["confidence"] == 0.95
    assert "CVE-2025-0001" in item["title"]
    assert "Required action" in item["description"]


def test_build_tracepoint_payload_is_valid_import_schema() -> None:
    """Build a valid Tracepoint import payload from KEV data."""
    kev_payload = load_json_from_file(Path("tests/fixtures/cisa_kev_sample.json"))

    payload = build_tracepoint_payload(
        kev_payload=kev_payload,
        limit=1,
        newest_first=True,
        persist=True,
        check_duplicates=True,
    )

    parsed = FindingImportCreate.model_validate(payload)

    assert parsed.source == "cisa_kev"
    assert parsed.persist is True
    assert parsed.check_duplicates is True
    assert len(parsed.items) == 1


def test_kev_category_and_severity_mapping() -> None:
    """Map KEV text into deterministic category and severity labels."""
    record = {
        "cveID": "CVE-2025-9999",
        "vendorProject": "Example",
        "product": "Example Product",
        "vulnerabilityName": "SQL Injection Vulnerability",
        "shortDescription": "The product contains a SQL injection vulnerability.",
        "requiredAction": "Apply update.",
    }

    assert category_from_kev(record) == "injection"
    assert severity_from_kev(record) == "high"


def test_write_payload_shape_can_roundtrip_json() -> None:
    """Ensure generated payload can be serialized cleanly."""
    kev_payload = load_json_from_file(Path("tests/fixtures/cisa_kev_sample.json"))

    payload = build_tracepoint_payload(
        kev_payload=kev_payload,
        limit=2,
        newest_first=True,
        persist=False,
        check_duplicates=False,
    )

    encoded = json.dumps(payload)
    decoded = json.loads(encoded)

    assert decoded["persist"] is False
    assert decoded["check_duplicates"] is False
    assert len(decoded["items"]) == 2
