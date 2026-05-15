"""Import CISA KEV catalog records into Tracepoint.

Examples:

Dry-run from local fixture:
    python scripts/import_cisa_kev.py \
      --input-file tests/fixtures/cisa_kev_sample.json \
      --dry-run

Dry-run from live CISA KEV feed:
    python scripts/import_cisa_kev.py \
      --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
      --dry-run

Import live CISA KEV feed into a running Tracepoint API:
    python scripts/import_cisa_kev.py \
      --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
      --api-url http://localhost:8000/api/v1/import/findings
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def load_json_from_file(path: Path) -> dict[str, Any]:
    """Load a KEV-like JSON document from disk."""
    if not path.exists():
        raise FileNotFoundError(f"Input file does not exist: {path}")

    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError("Input JSON must be an object.")

    return payload


def load_json_from_url(url: str) -> dict[str, Any]:
    """Load a KEV-like JSON document from a URL."""
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Tracepoint-CISA-KEV-Importer/1.0",
        },
    )

    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"Failed to fetch KEV feed: HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Failed to fetch KEV feed: {exc.reason}") from exc

    if not isinstance(payload, dict):
        raise ValueError("URL JSON response must be an object.")

    return payload


def infer_category(record: dict[str, Any]) -> str:
    """Infer Tracepoint category from KEV text fields."""
    text = " ".join(
        str(record.get(field, ""))
        for field in (
            "vulnerabilityName",
            "shortDescription",
            "requiredAction",
            "notes",
        )
    ).lower()

    if any(token in text for token in ("remote code execution", "rce", "arbitrary code")):
        return "remote_code_execution"

    if any(token in text for token in ("privilege escalation", "elevation of privilege")):
        return "privilege_escalation"

    if any(token in text for token in ("cross-site scripting", "xss")):
        return "xss"

    if any(token in text for token in ("sql injection", "command injection", "injection")):
        return "injection"

    if any(token in text for token in ("authentication bypass", "auth bypass")):
        return "auth_bypass"

    if any(token in text for token in ("path traversal", "directory traversal")):
        return "path_traversal"

    if any(token in text for token in ("deserialization", "deserialize")):
        return "insecure_deserialization"

    if any(token in text for token in ("information disclosure", "sensitive information")):
        return "information_disclosure"

    return "known_exploited_vulnerability"


def category_from_kev(record: dict[str, Any]) -> str:
    """Backward-compatible alias for KEV category inference."""
    return infer_category(record)


def infer_severity(record: dict[str, Any]) -> str:
    """Infer severity from KEV fields."""
    ransomware_use = str(record.get("knownRansomwareCampaignUse", "")).strip().lower()
    category = infer_category(record)

    if ransomware_use == "known":
        return "critical"

    if category in {
        "remote_code_execution",
        "auth_bypass",
        "privilege_escalation",
        "injection",
    }:
        return "high"

    return "medium"


def severity_from_kev(record: dict[str, Any]) -> str:
    """Backward-compatible alias for KEV severity inference."""
    return infer_severity(record)


def build_description(record: dict[str, Any]) -> str:
    """Build Tracepoint finding description from a KEV record."""
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

    return "\n".join(f"{label}: {value}" for label, value in fields if value not in (None, ""))


def map_kev_record_to_tracepoint_item(record: dict[str, Any]) -> dict[str, Any]:
    """Map one CISA KEV record into Tracepoint bulk import item format."""
    cve_id = str(record.get("cveID", "UNKNOWN-CVE")).strip()
    vendor = str(record.get("vendorProject", "Unknown vendor")).strip()
    product = str(record.get("product", "Unknown product")).strip()
    vulnerability_name = str(
        record.get("vulnerabilityName", "Known exploited vulnerability")
    ).strip()

    return {
        "title": f"{cve_id}: {vendor} {product} - {vulnerability_name}",
        "description": build_description(record),
        "source": "cisa_kev",
        "severity": infer_severity(record),
        "category": infer_category(record),
        "affected_asset": f"{vendor} {product} {cve_id}",
        "reporter": "cisa-kev-catalog",
        "confidence": 0.95,
    }


def extract_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract vulnerability records from a KEV payload."""
    records = payload.get("vulnerabilities", [])

    if not isinstance(records, list):
        raise ValueError("KEV payload must contain a vulnerabilities list.")

    return [record for record in records if isinstance(record, dict)]


def map_kev_record(record: dict[str, Any]) -> dict[str, Any]:
    """Map one CISA KEV vulnerability record to a Tracepoint import item."""
    cve_id = str(record.get("cveID", "")).strip()
    vendor = str(record.get("vendorProject", "")).strip()
    product = str(record.get("product", "")).strip()
    vulnerability_name = str(record.get("vulnerabilityName", "")).strip()

    title_parts = [
        part
        for part in [
            cve_id,
            f"{vendor} {product}".strip(),
            vulnerability_name,
        ]
        if part
    ]

    title = ": ".join(title_parts[:1])
    if len(title_parts) > 1:
        title = f"{title_parts[0]}: {title_parts[1]}"
    if len(title_parts) > 2:
        title = f"{title} - {title_parts[2]}"

    affected_asset = " ".join(part for part in [vendor, product, cve_id] if part)

    return {
        "title": title,
        "description": build_description(record),
        "source": "cisa_kev",
        "severity": severity_from_kev(record),
        "category": category_from_kev(record),
        "affected_asset": affected_asset,
        "reporter": "cisa-kev-catalog",
        "confidence": 0.95,
    }


def build_tracepoint_payload(
    kev_payload: dict[str, Any],
    limit: int | None = None,
    newest_first: bool = True,
    persist: bool = True,
    check_duplicates: bool = True,
) -> dict[str, Any]:
    """Build a Tracepoint bulk-import payload from a CISA KEV payload."""
    records = extract_records(kev_payload)

    records = sorted(
        records,
        key=lambda record: str(record.get("dateAdded", "")),
        reverse=newest_first,
    )

    if limit is not None:
        records = records[:limit]

    return {
        "source": "cisa_kev",
        "persist": persist,
        "check_duplicates": check_duplicates,
        "items": [map_kev_record(record) for record in records],
    }


def post_payload(api_url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Post import payload to Tracepoint API."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        api_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Tracepoint-CISA-KEV-Importer/1.0",
        },
    )

    try:
        with urlopen(request, timeout=60) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Tracepoint API import failed: HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Tracepoint API import failed: {exc.reason}") from exc

    if not isinstance(response_payload, dict):
        raise ValueError("Tracepoint API response must be a JSON object.")

    return response_payload


def resolve_api_url(base_url: str | None, api_url: str | None) -> str | None:
    """Resolve final import API URL."""
    if api_url:
        return api_url

    if not base_url:
        return None

    normalized = base_url.rstrip("/")

    if normalized.endswith("/api/v1/import/findings"):
        return normalized

    return f"{normalized}/api/v1/import/findings"


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Import CISA KEV catalog records into Tracepoint.")
    parser.add_argument(
        "--url",
        default=None,
        help=(
            "CISA KEV JSON feed URL. Defaults to the official CISA KEV feed "
            "when no input file is provided."
        ),
    )
    parser.add_argument(
        "--input-file",
        type=Path,
        default=None,
        help="Local KEV JSON file. Useful for tests and offline runs.",
    )
    parser.add_argument(
        "--api-url",
        default=None,
        help="Full Tracepoint bulk import endpoint, for example http://localhost:8000/api/v1/import/findings.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Tracepoint API base URL, for example http://localhost:8000.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of KEV records to import.",
    )
    parser.add_argument(
        "--oldest-first",
        action="store_true",
        help="Import oldest records first instead of feed order.",
    )
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="Build payload with persist=false.",
    )
    parser.add_argument(
        "--no-duplicate-check",
        action="store_true",
        help="Disable duplicate checks during import.",
    )
    parser.add_argument(
        "--write-payload",
        type=Path,
        default=None,
        help="Write generated Tracepoint import payload to a JSON file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated payload instead of posting to Tracepoint.",
    )

    return parser.parse_args()


def main() -> int:
    """Run importer."""
    args = parse_args()

    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be greater than 0.")

    if args.input_file is not None:
        kev_payload = load_json_from_file(args.input_file)
    else:
        kev_payload = load_json_from_url(args.url or DEFAULT_CISA_KEV_URL)

    tracepoint_payload = build_tracepoint_payload(
        kev_payload,
        limit=args.limit,
        oldest_first=args.oldest_first,
        persist=not args.analysis_only,
        check_duplicates=not args.no_duplicate_check,
    )

    if args.write_payload is not None:
        args.write_payload.parent.mkdir(parents=True, exist_ok=True)
        args.write_payload.write_text(
            json.dumps(tracepoint_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    if args.dry_run:
        print(json.dumps(tracepoint_payload, indent=2, sort_keys=True))
        return 0

    api_url = resolve_api_url(args.base_url, args.api_url)

    if api_url is None:
        print(
            "No API target provided. Use --dry-run, --api-url, or --base-url.",
            file=sys.stderr,
        )
        return 2

    response_payload = post_payload(api_url, tracepoint_payload)
    print(json.dumps(response_payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
