"""Finding comment API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.comment import (
    FindingCommentCreate,
    FindingCommentListRead,
    FindingCommentRead,
)
from tracepoint.services.comment import FindingCommentService

router = APIRouter(prefix="/findings", tags=["comments"])


@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentRead,
    status_code=status.HTTP_201_CREATED,
)
def add_finding_comment(
    finding_id: str,
    payload: FindingCommentCreate,
    session: Annotated[Session, Depends(get_session)],
) -> FindingCommentRead:
    """Attach an analyst comment to a finding."""
    result = FindingCommentService(session).add_comment(
        finding_id=finding_id,
        payload=payload,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return result


@router.get("/{finding_id}/comments", response_model=FindingCommentListRead)
def list_finding_comments(
    finding_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> FindingCommentListRead:
    """List analyst comments attached to a finding."""
    result = FindingCommentService(session).list_comments(finding_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return result
