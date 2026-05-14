"""Triage API routes."""

from __future__ import annotations

from fastapi import APIRouter

from tracepoint.schemas.triage import TriageRequest, TriageResponse
from tracepoint.services.triage import TriageService

router = APIRouter(
    prefix="/triage",
    tags=["triage"],
)


@router.post(
    "",
    response_model=TriageResponse,
)
def triage_report(payload: TriageRequest) -> TriageResponse:
    """Run deterministic first-pass vulnerability triage."""
    return TriageService().triage(payload)
