"""Add durable Pi session and safe steering lifecycle state.

Revision ID: 0003_pi_runner_bridge
Revises: 0002_runtime_kernel
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_pi_runner_bridge"
down_revision = "0002_runtime_kernel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Persist only opaque Pi session metadata, never transcript or secrets."""

    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("start_job_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=64), nullable=False),
        sa.Column("context_manifest_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=160), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("runner_id", sa.String(length=128), nullable=True),
        sa.Column("session_store_key", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["context_manifest_id"], ["context_manifests.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["start_job_id"], ["agent_jobs.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["worker_tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_store_key", name="uq_agent_sessions_store_key"),
        sa.UniqueConstraint("start_job_id", name="uq_agent_sessions_start_job"),
    )
    op.create_index("ix_agent_sessions_run_id", "agent_sessions", ["run_id"], unique=False)
    op.create_index(
        "ix_agent_sessions_run_state", "agent_sessions", ["run_id", "state"], unique=False
    )

    op.create_table(
        "agent_steers",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("message_digest", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_agent_steers_idempotency"),
    )
    op.create_index("ix_agent_steers_run_id", "agent_steers", ["run_id"], unique=False)
    op.create_index(
        "ix_agent_steers_session_state",
        "agent_steers",
        ["session_id", "state"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_agent_steers_session_state", table_name="agent_steers")
    op.drop_index("ix_agent_steers_run_id", table_name="agent_steers")
    op.drop_table("agent_steers")
    op.drop_index("ix_agent_sessions_run_state", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_run_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")
