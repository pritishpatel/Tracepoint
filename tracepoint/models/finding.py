"""Finding ORM model.

A finding is the primary security work item in Tracepoint. It represents a
bug bounty report, DAST finding, cloud alert, EDR alert, secret exposure, or
manual security observation that needs triage, investigation, remediation, or
closure evidence.
"""

from __future__ import annotations

from enum import Enum
from uuid import uuid4

from sqlalchemy import Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tracepoint.db.base import Base
from tracepoint.models.base import TimestampMixin


class FindingSource(str, Enum):
    """Supported finding intake sources."""

    MANUAL = "manual"
    BUG_BOUNTY = "bug_bounty"
    DAST = "dast"
    SAST = "sast"
    SECRET_SCAN = "secret_scan"  # nosec B105
    CLOUD_ALERT = "cloud_alert"
    EDR_ALERT = "edr_alert"
    DLP_ALERT = "dlp_alert"
    DARKWEB = "darkweb"


class FindingSeverity(str, Enum):
    """Normalized finding severity values."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    """Lifecycle states for a finding."""

    NEW = "new"
    TRIAGED = "triaged"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    IN_REMEDIATION = "in_remediation"
    READY_FOR_RETEST = "ready_for_retest"
    CLOSED = "closed"


class Finding(Base, TimestampMixin):
    """Security finding tracked by Tracepoint."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        default=FindingSource.MANUAL.value,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        default=FindingSeverity.UNKNOWN.value,
    )
    status: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        default=FindingStatus.NEW.value,
    )

    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    affected_asset: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    reporter: Mapped[str | None] = mapped_column(String(256), nullable=True)

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
