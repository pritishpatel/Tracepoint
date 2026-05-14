"""Dashboard API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.dashboard import DashboardSummaryRead
from tracepoint.services.dashboard import DashboardService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryRead)
def get_dashboard_summary(
    session: Annotated[Session, Depends(get_session)],
) -> DashboardSummaryRead:
    """Return a high-level operational dashboard summary."""
    return DashboardService(session=session).summary()
