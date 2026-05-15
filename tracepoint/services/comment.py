"""Finding comment service.

This first slice keeps comments in process memory so the product workflow can
be validated without adding a new migration yet. A later persistence slice can
move this behind a SQLAlchemy model while preserving the API contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from tracepoint.models.finding import Finding
from tracepoint.schemas.comment import (
    FindingCommentCreate,
    FindingCommentListRead,
    FindingCommentRead,
)


@dataclass(frozen=True)
class StoredFindingComment:
    """Internal stored comment representation."""

    id: str
    finding_id: str
    author: str
    body: str
    created_at: datetime


class FindingCommentService:
    """Manage comments attached to findings."""

    _comments: list[StoredFindingComment] = []

    def __init__(self, session: Session) -> None:
        """Initialize the comment service."""
        self.session = session

    def add_comment(
        self,
        finding_id: str,
        payload: FindingCommentCreate,
    ) -> FindingCommentRead | None:
        """Attach a comment to an existing finding."""
        finding = self.session.get(Finding, finding_id)

        if finding is None:
            return None

        comment = StoredFindingComment(
            id=str(uuid4()),
            finding_id=finding_id,
            author=payload.author,
            body=payload.body,
            created_at=datetime.now(timezone.utc),
        )
        self._comments.append(comment)

        return self.to_read(comment)

    def list_comments(self, finding_id: str) -> FindingCommentListRead | None:
        """List comments for an existing finding."""
        finding = self.session.get(Finding, finding_id)

        if finding is None:
            return None

        comments = [
            self.to_read(comment) for comment in self._comments if comment.finding_id == finding_id
        ]

        return FindingCommentListRead(
            finding_id=finding_id,
            count=len(comments),
            comments=comments,
        )

    def to_read(self, comment: StoredFindingComment) -> FindingCommentRead:
        """Convert a stored comment to API schema."""
        return FindingCommentRead(
            id=comment.id,
            finding_id=comment.finding_id,
            author=comment.author,
            body=comment.body,
            created_at=comment.created_at,
        )
