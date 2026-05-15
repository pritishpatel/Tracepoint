"""Finding API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from tracepoint.db import get_session
from tracepoint.schemas.finding import (
    FindingCreate,
    FindingListResponse,
    FindingProvenanceRead,
    FindingRead,
)
from tracepoint.services.finding import FindingService

router = APIRouter(prefix="/findings", tags=["findings"])


def finding_service(session: Annotated[Session, Depends(get_session)]) -> FindingService:
    """Provide a finding service bound to the current database session."""
    return FindingService(session)


@router.post(
    "",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    payload: FindingCreate,
    service: Annotated[FindingService, Depends(finding_service)],
) -> FindingRead:
    """Create a new security finding."""
    finding = service.create_finding(payload)
    return FindingRead.model_validate(finding)


@router.get(
    "",
    response_model=FindingListResponse,
)
def list_findings(
    service: Annotated[FindingService, Depends(finding_service)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingListResponse:
    """List security findings."""
    findings, total = service.list_findings(limit=limit, offset=offset)

    return FindingListResponse(
        items=[FindingRead.model_validate(finding) for finding in findings],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{finding_id}/provenance",
    response_model=FindingProvenanceRead,
)
def get_finding_provenance(
    finding_id: str,
    service: Annotated[FindingService, Depends(finding_service)],
) -> FindingProvenanceRead:
    """Return parsed provenance metadata for a finding."""
    provenance = service.get_provenance(finding_id)

    if provenance is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return provenance


@router.get(
    "/{finding_id}",
    response_model=FindingRead,
)
def get_finding(
    finding_id: str,
    service: Annotated[FindingService, Depends(finding_service)],
) -> FindingRead:
    """Return a single finding by ID."""
    finding = service.get_finding(finding_id)

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return FindingRead.model_validate(finding)
