"""Bulk finding import API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.imports import FindingImportCreate, FindingImportSummaryRead
from tracepoint.services.imports import FindingImportService

router = APIRouter(prefix="/import", tags=["import"])


@router.post("/findings", response_model=FindingImportSummaryRead, status_code=201)
def import_findings(
    payload: FindingImportCreate,
    session: Annotated[Session, Depends(get_session)],
) -> FindingImportSummaryRead:
    """Import finding-like records through the intake workflow."""
    return FindingImportService(session).import_findings(payload)
