"""Record the transcript a continued Power session resumes from.

A finished run kept its Pi transcripts and its workspaces, but nothing could
adopt them: the store key is unique per session, so a new run could not point
at an old transcript, and every continuation started from recon again. The new
column names the source; the runner seeds the new transcript from it.

Revision ID: 0009_power_pi_resume
Revises: 0008_power_pi_sessions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_power_pi_resume"
down_revision = "0008_power_pi_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "power_pi_sessions",
        sa.Column("resumed_from_store_key", sa.String(length=160), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("power_pi_sessions", "resumed_from_store_key")
