"""Persist typed gateway invocations and their artifact-backed outcomes.

Revision ID: 0004_tool_gateway
Revises: 0003_pi_runner_bridge
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_tool_gateway"
down_revision = "0003_pi_runner_bridge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create a durable, body-free ledger for gateway invocations."""

    op.create_table(
        "tool_invocations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("agent_job_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=64), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=True),
        sa.Column("tool_call_id", sa.String(length=160), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_decision", sa.String(length=16), nullable=False),
        sa.Column("policy_reason", sa.String(length=160), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("tool_budget_ledger_id", sa.String(length=64), nullable=True),
        sa.Column("http_budget_ledger_id", sa.String(length=64), nullable=True),
        sa.Column("result_artifact_id", sa.String(length=64), nullable=True),
        sa.Column("result_digest", sa.String(length=64), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("error_code", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["agent_job_id"], ["agent_jobs.id"]),
        sa.ForeignKeyConstraint(["branch_id"], ["run_branches.id"]),
        sa.ForeignKeyConstraint(["result_artifact_id"], ["artifacts.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["worker_tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "task_id",
            "tool_name",
            "idempotency_key",
            name="uq_tool_invocation_idempotency",
        ),
        sa.UniqueConstraint(
            "run_id",
            "session_id",
            "tool_call_id",
            name="uq_tool_invocation_call",
        ),
    )
    op.create_index("ix_tool_invocations_run_id", "tool_invocations", ["run_id"], unique=False)
    op.create_index(
        "ix_tool_invocations_agent_job_id", "tool_invocations", ["agent_job_id"], unique=False
    )
    op.create_index(
        "ix_tool_invocations_session_id", "tool_invocations", ["session_id"], unique=False
    )
    op.create_index("ix_tool_invocations_task_id", "tool_invocations", ["task_id"], unique=False)
    op.create_index(
        "ix_tool_invocations_run_state", "tool_invocations", ["run_id", "state"], unique=False
    )
    op.create_index(
        "ix_tool_invocations_session",
        "tool_invocations",
        ["session_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_tool_invocations_session", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_run_state", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_task_id", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_session_id", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_agent_job_id", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_run_id", table_name="tool_invocations")
    op.drop_table("tool_invocations")
