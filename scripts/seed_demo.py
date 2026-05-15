"""Seed Tracepoint with realistic local demo findings."""

from __future__ import annotations

import json
from pathlib import Path

from tracepoint.db import get_database_manager
from tracepoint.schemas.imports import FindingImportCreate, FindingImportItemCreate
from tracepoint.services.imports import FindingImportService

DEFAULT_SAMPLE_PATH = Path("sample_data/findings.json")


def main() -> None:
    """Load sample findings through the normal intake/import workflow."""
    raw_items = json.loads(DEFAULT_SAMPLE_PATH.read_text())
    payload = FindingImportCreate(
        source="demo_seed",
        persist=True,
        check_duplicates=False,
        items=[FindingImportItemCreate.model_validate(item) for item in raw_items],
    )

    database = get_database_manager()
    database.create_schema_for_development()

    with database.session_scope() as session:
        summary = FindingImportService(session).import_findings(payload)

    print(
        "Seeded Tracepoint demo data: "
        f"received={summary.received} created={summary.created} failed={summary.failed}"
    )


if __name__ == "__main__":
    main()
