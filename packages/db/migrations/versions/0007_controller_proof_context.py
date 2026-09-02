"""Preserve all non-secret fields covered by a controller proof signature.

Revision ID: 0007_controller_proof_context
Revises: 0006_verifier_candidates
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_controller_proof_context"
down_revision = "0006_verifier_candidates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add signed lab/timestamp context without changing historical outcomes."""

    # Nullable preserves existing M5 attempts. New successful attempts are
    # required by the domain contract to carry both values.
    op.add_column(
        "verification_attempts",
        sa.Column("controller_lab_id", sa.String(length=160), nullable=True),
    )
    op.add_column(
        "verification_attempts",
        sa.Column("controller_issued_at", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("verification_attempts", "controller_issued_at")
    op.drop_column("verification_attempts", "controller_lab_id")
