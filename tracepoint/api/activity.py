"""Activity timeline API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.activity import ActivityTimelineRead
from tracepoint.services.activity import ActivityService

router = APIRouter(prefix="/activity", tags=["activity"])


@router.get("", response_model=ActivityTimelineRead)
def get_activity_timeline(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ActivityTimelineRead:
    """Return recent activity timeline."""
    return ActivityService(session).timeline(limit=limit)
