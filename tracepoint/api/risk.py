"""Risk scoring API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.risk import FindingRiskRead
from tracepoint.services.risk import FindingRiskService

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/findings/{finding_id}", response_model=FindingRiskRead)
def score_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> FindingRiskRead:
    """Return deterministic risk score for a finding."""
    result = FindingRiskService(session).score_finding(finding_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return result
