"""Persist credential-free Power Pi session lifecycle metadata.

Revision ID: 0008_power_pi_sessions
Revises: 0007_controller_proof_context
Create Date: 2026-09-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_power_pi_sessions"
down_revision = "0007_controller_proof_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the isolated Power-session metadata table without secret columns."""

    op.create_table(
        "power_pi_sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("start_job_id", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=160), nullable=False),
        sa.Column("temperature", sa.Float(), nullable=False),
        sa.Column("archive_digest", sa.String(length=64), nullable=False),
        sa.Column("brief", sa.Text(), nullable=False),
        sa.Column("target_host", sa.String(length=253), nullable=True),
        sa.Column("target_port", sa.Integer(), nullable=True),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("runner_id", sa.String(length=128), nullable=True),
        sa.Column("session_store_key", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["start_job_id"], ["agent_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_store_key", name="uq_power_pi_sessions_store_key"),
        sa.UniqueConstraint("start_job_id", name="uq_power_pi_sessions_start_job"),
    )
    op.create_index(
        "ix_power_pi_sessions_run_state", "power_pi_sessions", ["run_id", "state"], unique=False
    )
    op.create_index("ix_power_pi_sessions_run_id", "power_pi_sessions", ["run_id"], unique=False)
    op.create_table(
        "power_pi_steers",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("message_digest", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["session_id"], ["power_pi_sessions.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["agent_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", name="uq_power_pi_steers_job"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_power_pi_steers_idempotency"),
    )
    op.create_index(
        "ix_power_pi_steers_session_state", "power_pi_steers", ["session_id", "state"], unique=False
    )
    op.create_index("ix_power_pi_steers_run_id", "power_pi_steers", ["run_id"], unique=False)
    op.create_index(
        "ix_power_pi_steers_session_id", "power_pi_steers", ["session_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_power_pi_steers_session_id", table_name="power_pi_steers")
    op.drop_index("ix_power_pi_steers_run_id", table_name="power_pi_steers")
    op.drop_index("ix_power_pi_steers_session_state", table_name="power_pi_steers")
    op.drop_table("power_pi_steers")
    op.drop_index("ix_power_pi_sessions_run_id", table_name="power_pi_sessions")
    op.drop_index("ix_power_pi_sessions_run_state", table_name="power_pi_sessions")
    op.drop_table("power_pi_sessions")
