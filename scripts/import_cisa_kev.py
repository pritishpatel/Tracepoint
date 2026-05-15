"""Import real CISA KEV records into Tracepoint.

This script fetches the public CISA Known Exploited Vulnerabilities catalog,
maps KEV records into Tracepoint's bulk import schema, and posts them to the
existing /api/v1/import/findings endpoint.

Usage:
    python scripts/import_cisa_kev.py --limit 50
    python scripts/import_cisa_kev.py --limit 100 --base-url http://127.0.0.1:8000
    python scripts/import_cisa_kev.py --input-file tests/fixtures/cisa_kev_sample.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def load_json_from_file(path: Path) -> dict[str, Any]:
    """Load a KEV-like JSON document from disk."""
    if not path.exists():
        raise FileNotFoundError(f"Input file does not exist: {path}")

    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError("Input file must contain a JSON object.")

    return payload


def fetch_cisa_kev(url: str = CISA_KEV_JSON_URL) -> dict[str, Any]:
    """Fetch the public CISA KEV catalog."""
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        response = client.get(url)

    response.raise_for_status()
    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError("CISA KEV response was not a JSON object.")

    return payload


def parse_date(value: str | None) -> datetime:
    """Parse a KEV date safely for sorting."""
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def normalize_text(value: object) -> str:
    """Normalize nullable JSON values into strings."""
    if value is None:
        return ""

    return str(value).strip()


def severity_from_kev(record: dict[str, Any]) -> str:
    """Assign deterministic Tracepoint severity for a KEV record.

    KEV entries are known exploited vulnerabilities, so default severity should
    not be below high unless future enrichment says otherwise.
    """
    product = normalize_text(record.get("product")).lower()
    notes = " ".join(
        [
            normalize_text(record.get("vulnerabilityName")),
            normalize_text(record.get("shortDescription")),
            normalize_text(record.get("requiredAction")),
            normalize_text(record.get("notes")),
        ]
    ).lower()

    critical_keywords = (
        "remote code execution",
        "rce",
        "unauthenticated",
        "privilege escalation",
        "command injection",
        "arbitrary code",
    )

    if any(keyword in notes for keyword in critical_keywords):
        return "critical"

    if any(keyword in product for keyword in ("exchange", "fortinet", "citrix", "ivanti")):
        return "critical"

    return "high"


def category_from_kev(record: dict[str, Any]) -> str:
    """Map CISA KEV wording into Tracepoint categories."""
    text = " ".join(
        [
            normalize_text(record.get("vulnerabilityName")),
            normalize_text(record.get("shortDescription")),
            normalize_text(record.get("requiredAction")),
            normalize_text(record.get("notes")),
        ]
    ).lower()

    category_rules = [
        ("remote code execution", "remote_code_execution"),
        ("arbitrary code", "remote_code_execution"),
        ("code execution", "remote_code_execution"),
        ("command injection", "injection"),
        ("sql injection", "injection"),
        ("injection", "injection"),
        ("privilege escalation", "privilege_escalation"),
        ("authentication bypass", "auth_bypass"),
        ("authorization bypass", "auth_bypass"),
        ("path traversal", "path_traversal"),
        ("directory traversal", "path_traversal"),
        ("deserialization", "insecure_deserialization"),
        ("cross-site scripting", "xss"),
        ("xss", "xss"),
        ("information disclosure", "information_disclosure"),
        ("memory corruption", "memory_corruption"),
        ("buffer overflow", "memory_corruption"),
    ]

    for keyword, category in category_rules:
        if keyword in text:
            return category

    return "known_exploited_vulnerability"


def build_title(record: dict[str, Any]) -> str:
    """Build a concise finding title."""
    cve_id = normalize_text(record.get("cveID")) or "Unknown CVE"
    vendor = normalize_text(record.get("vendorProject"))
    product = normalize_text(record.get("product"))
    name = normalize_text(record.get("vulnerabilityName"))

    if vendor and product:
        return f"{cve_id}: {vendor} {product} - {name}"

    if name:
        return f"{cve_id}: {name}"

    return cve_id


def build_description(record: dict[str, Any]) -> str:
    """Build a detailed finding description from KEV fields."""
    fields = [
        ("CVE", record.get("cveID")),
        ("Vendor/Project", record.get("vendorProject")),
        ("Product", record.get("product")),
        ("Vulnerability", record.get("vulnerabilityName")),
        ("Description", record.get("shortDescription")),
        ("Date added to KEV", record.get("dateAdded")),
        ("Required action", record.get("requiredAction")),
        ("Due date", record.get("dueDate")),
        ("Known ransomware use", record.get("knownRansomwareCampaignUse")),
        ("Notes", record.get("notes")),
    ]

    lines = [
        f"{label}: {normalize_text(value)}" for label, value in fields if normalize_text(value)
    ]

    description = "\n".join(lines).strip()

    if len(description) < 10:
        return "Known exploited vulnerability from the CISA KEV catalog."

    return description


def map_kev_record(record: dict[str, Any]) -> dict[str, Any]:
    """Map one CISA KEV vulnerability into Tracepoint import item format."""
    cve_id = normalize_text(record.get("cveID"))
    vendor = normalize_text(record.get("vendorProject"))
    product = normalize_text(record.get("product"))

    affected_asset = " ".join(part for part in [vendor, product, cve_id] if part)

    return {
        "title": build_title(record),
        "description": build_description(record),
        "source": "cisa_kev",
        "severity": severity_from_kev(record),
        "category": category_from_kev(record),
        "affected_asset": affected_asset or cve_id or "unknown affected product",
        "reporter": "cisa-kev-catalog",
        "confidence": 0.95,
    }


def build_tracepoint_payload(
    kev_payload: dict[str, Any],
    limit: int,
    newest_first: bool,
    persist: bool,
    check_duplicates: bool,
) -> dict[str, Any]:
    """Build Tracepoint bulk import payload from CISA KEV data."""
    vulnerabilities = kev_payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV payload does not contain a vulnerabilities list.")

    records = [
        record
        for record in vulnerabilities
        if isinstance(record, dict) and normalize_text(record.get("cveID"))
    ]

    records = sorted(
        records,
        key=lambda record: parse_date(normalize_text(record.get("dateAdded"))),
        reverse=newest_first,
    )

    if limit > 0:
        records = records[:limit]

    return {
        "source": "cisa_kev",
        "persist": persist,
        "check_duplicates": check_duplicates,
        "items": [map_kev_record(record) for record in records],
    }


def post_to_tracepoint(base_url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Post transformed CISA KEV findings into Tracepoint."""
    endpoint = f"{base_url.rstrip('/')}/api/v1/import/findings"

    with httpx.Client(timeout=60.0) as client:
        response = client.post(endpoint, json=payload)

    response.raise_for_status()
    result = response.json()

    if not isinstance(result, dict):
        raise ValueError("Tracepoint returned an unexpected non-object response.")

    return result


def write_payload(path: Path, payload: dict[str, Any]) -> None:
    """Write transformed Tracepoint payload to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def print_summary(result: dict[str, Any]) -> None:
    """Print import result summary."""
    print("CISA KEV import complete")
    print(f"Received:   {result.get('received', 0)}")
    print(f"Created:    {result.get('created', 0)}")
    print(f"Duplicates: {result.get('duplicates', 0)}")
    print(f"Failed:     {result.get('failed', 0)}")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Import real CISA KEV vulnerabilities into Tracepoint.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Tracepoint API base URL.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of KEV records to import. Use 0 for all records.",
    )
    parser.add_argument(
        "--oldest-first",
        action="store_true",
        help="Import oldest KEV records first instead of newest first.",
    )
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="Run through intake without persisting findings.",
    )
    parser.add_argument(
        "--no-duplicate-check",
        action="store_true",
        help="Disable duplicate checking during import.",
    )
    parser.add_argument(
        "--input-file",
        type=Path,
        default=None,
        help="Optional local CISA KEV JSON file. If omitted, fetch from CISA.",
    )
    parser.add_argument(
        "--write-payload",
        type=Path,
        default=None,
        help="Optional path to write transformed Tracepoint import payload.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Transform data but do not post to Tracepoint.",
    )
    return parser.parse_args()


def main() -> int:
    """Run the CISA KEV import workflow."""
    args = parse_args()

    try:
        kev_payload = (
            load_json_from_file(args.input_file)
            if args.input_file is not None
            else fetch_cisa_kev()
        )

        tracepoint_payload = build_tracepoint_payload(
            kev_payload=kev_payload,
            limit=args.limit,
            newest_first=not args.oldest_first,
            persist=not args.analysis_only,
            check_duplicates=not args.no_duplicate_check,
        )

        if args.write_payload is not None:
            write_payload(args.write_payload, tracepoint_payload)

        if args.dry_run:
            print(json.dumps(tracepoint_payload, indent=2, sort_keys=True))
            return 0

        result = post_to_tracepoint(
            base_url=args.base_url,
            payload=tracepoint_payload,
        )
    except (FileNotFoundError, ValueError, httpx.HTTPError) as exc:
        print(f"CISA KEV import failed: {exc}", file=sys.stderr)
        return 1

    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
