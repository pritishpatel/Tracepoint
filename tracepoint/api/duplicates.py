"""Duplicate-detection API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.duplicate import DuplicateCheckRequest, DuplicateCheckResponse
from tracepoint.services.duplicate_detection import DuplicateDetectionService

router = APIRouter(prefix="/duplicates", tags=["duplicates"])


def duplicate_detection_service(
    session: Annotated[Session, Depends(get_session)],
) -> DuplicateDetectionService:
    """Create a duplicate-detection service for the current request."""
    return DuplicateDetectionService(session=session)


@router.post(
    "/check",
    response_model=DuplicateCheckResponse,
)
def check_duplicate(
    payload: DuplicateCheckRequest,
    service: Annotated[
        DuplicateDetectionService,
        Depends(duplicate_detection_service),
    ],
) -> DuplicateCheckResponse:
    """Check whether an incoming report likely duplicates an existing finding."""
    return service.check_duplicate(payload)
