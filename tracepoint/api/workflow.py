"""Workflow API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.workflow import FindingStatusUpdate, FindingWorkflowRead
from tracepoint.services.workflow import FindingWorkflowService

router = APIRouter(prefix="/workflow", tags=["workflow"])


@router.patch("/findings/{finding_id}/status", response_model=FindingWorkflowRead)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    session: Annotated[Session, Depends(get_session)],
) -> FindingWorkflowRead:
    """Update analyst workflow status for a finding."""
    service = FindingWorkflowService(session)
    normalized_status = service.normalize_status(payload.status)

    if not service.is_allowed_status(normalized_status):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "Unsupported finding status. Use one of: "
                "new, triaged, in_progress, resolved, false_positive, "
                "duplicate, accepted_risk."
            ),
        )

    result = service.update_status(
        finding_id=finding_id,
        status=normalized_status,
        note=payload.note,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return result
