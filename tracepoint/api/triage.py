"""Triage API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.triage import TriageRequest, TriageResponse
from tracepoint.schemas.triage_result import PersistedTriageResponse
from tracepoint.services.triage import TriageService
from tracepoint.services.triage_result import TriageResultService

router = APIRouter(tags=["triage"])


def triage_service() -> TriageService:
    """Return the deterministic triage service."""
    return TriageService()


@router.post(
    "/triage",
    response_model=TriageResponse | PersistedTriageResponse,
)
def triage_report(
    payload: TriageRequest,
    service: Annotated[TriageService, Depends(triage_service)],
    session: Annotated[Session, Depends(get_session)],
    persist: Annotated[
        bool,
        Query(description="Persist the triage result and create a linked finding."),
    ] = False,
) -> TriageResponse | PersistedTriageResponse:
    """Classify a vulnerability report and optionally persist the result."""
    triage = service.triage(payload)

    if not persist:
        return triage

    finding, triage_result = TriageResultService(session).persist(
        request=payload,
        triage=triage,
    )

    return PersistedTriageResponse(
        triage=triage,
        finding_id=finding.id,
        triage_result_id=triage_result.id,
    )
