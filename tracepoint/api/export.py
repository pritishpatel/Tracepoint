"""Finding export API routes."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.export import ExportSummaryRead
from tracepoint.services.export import FindingExportService

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/findings", response_model=ExportSummaryRead)
def export_findings(
    session: Annotated[Session, Depends(get_session)],
    export_format: Annotated[
        Literal["json", "csv"],
        Query(alias="format"),
    ] = "json",
) -> ExportSummaryRead:
    """Export findings as JSON records or CSV content."""
    return FindingExportService(session).export(export_format=export_format)
