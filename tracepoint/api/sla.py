"""SLA API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.sla import FindingSlaRead
from tracepoint.services.sla import FindingSlaService

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/findings/{finding_id}/sla", response_model=FindingSlaRead)
def get_finding_sla(
    finding_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> FindingSlaRead:
    """Return remediation SLA timeline for a finding."""
    result = FindingSlaService(session).get_finding_sla(finding_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return result
