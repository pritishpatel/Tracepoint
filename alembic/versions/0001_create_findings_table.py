"""Create findings table.

Revision ID: 0001
Revises:
Create Date: 2026-05-14 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the findings table and query indexes."""
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=True),
        sa.Column("affected_asset", sa.String(length=512), nullable=True),
        sa.Column("reporter", sa.String(length=256), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_title", "findings", ["title"])
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_affected_asset", "findings", ["affected_asset"])


def downgrade() -> None:
    """Drop the findings table and indexes."""
    op.drop_index("ix_findings_affected_asset", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_source", table_name="findings")
    op.drop_index("ix_findings_title", table_name="findings")
    op.drop_table("findings")
