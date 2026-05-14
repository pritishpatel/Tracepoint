"""Create triage results table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the triage results table."""
    op.create_table(
        "triage_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("validity", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("cwe", sa.String(length=64), nullable=True),
        sa.Column("owasp", sa.String(length=256), nullable=True),
        sa.Column("routing_team", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_summary_json", sa.Text(), nullable=False),
        sa.Column("reproduction_steps_json", sa.Text(), nullable=False),
        sa.Column("remediation_guidance_json", sa.Text(), nullable=False),
        sa.Column("human_review_questions_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_triage_results_finding_id", "triage_results", ["finding_id"])
    op.create_index("ix_triage_results_validity", "triage_results", ["validity"])
    op.create_index("ix_triage_results_category", "triage_results", ["category"])
    op.create_index("ix_triage_results_severity", "triage_results", ["severity"])
    op.create_index("ix_triage_results_cwe", "triage_results", ["cwe"])
    op.create_index(
        "ix_triage_results_routing_team",
        "triage_results",
        ["routing_team"],
    )


def downgrade() -> None:
    """Drop the triage results table and indexes."""
    op.drop_index("ix_triage_results_routing_team", table_name="triage_results")
    op.drop_index("ix_triage_results_cwe", table_name="triage_results")
    op.drop_index("ix_triage_results_severity", table_name="triage_results")
    op.drop_index("ix_triage_results_category", table_name="triage_results")
    op.drop_index("ix_triage_results_validity", table_name="triage_results")
    op.drop_index("ix_triage_results_finding_id", table_name="triage_results")
    op.drop_table("triage_results")
