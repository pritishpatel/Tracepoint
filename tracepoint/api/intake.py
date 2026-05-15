"""Report intake API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from tracepoint.core.auth import Principal, require_roles
from tracepoint.db import get_session
from tracepoint.schemas.intake import IntakeReportCreate, IntakeReportRead
from tracepoint.services.intake import IntakeService

router = APIRouter(prefix="/intake", tags=["intake"])


def intake_service(
    session: Annotated[Session, Depends(get_session)],
) -> IntakeService:
    """Create an intake service for the active request."""
    return IntakeService(session=session)


@router.post(
    "/reports",
    response_model=IntakeReportRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_report(
    payload: IntakeReportCreate,
    service: Annotated[IntakeService, Depends(intake_service)],
    principal: Annotated[Principal, Depends(require_roles("analyst", "admin"))],
) -> IntakeReportRead:
    """Ingest a raw security report through the full Tracepoint workflow."""
    _ = principal
    return service.ingest(payload)
