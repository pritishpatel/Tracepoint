"""Evidence bundle API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.evidence import EvidenceBundleCreate, EvidenceBundleRead
from tracepoint.services.evidence import EvidenceBundleService

router = APIRouter(tags=["evidence"])


def evidence_service(
    session: Annotated[Session, Depends(get_session)],
) -> EvidenceBundleService:
    """Return an evidence bundle service for the current request."""
    return EvidenceBundleService(session=session)


@router.post(
    "/findings/{finding_id}/evidence",
    response_model=EvidenceBundleRead,
    status_code=status.HTTP_201_CREATED,
)
def create_evidence_bundle(
    finding_id: str,
    payload: EvidenceBundleCreate,
    service: Annotated[EvidenceBundleService, Depends(evidence_service)],
) -> EvidenceBundleRead:
    """Generate an evidence bundle for a finding."""
    bundle = service.create_bundle(finding_id=finding_id, payload=payload)

    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return bundle
