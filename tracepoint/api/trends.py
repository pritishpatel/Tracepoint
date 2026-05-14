"""Dashboard trend analytics API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.trends import DashboardTrendsRead
from tracepoint.services.trends import DashboardTrendsService

router = APIRouter(prefix="/dashboard/trends", tags=["dashboard"])


@router.get("", response_model=DashboardTrendsRead)
def get_dashboard_trends(
    session: Annotated[Session, Depends(get_session)],
    days: Annotated[int, Query(ge=1, le=90)] = 14,
) -> DashboardTrendsRead:
    """Return dashboard trend analytics."""
    return DashboardTrendsService(session).trends(days=days)
