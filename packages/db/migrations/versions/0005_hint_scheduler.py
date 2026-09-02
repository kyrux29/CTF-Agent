"""Add durable M4 Hint Cards and scheduler metadata.

Revision ID: 0005_hint_scheduler
Revises: 0004_tool_gateway
Create Date: 2026-08-29
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_hint_scheduler"
down_revision = "0004_tool_gateway"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Persist hint lifecycle and deterministic branch/task scheduling inputs."""

    # Server defaults preserve compatibility for pre-M4 rows during an in-place
    # upgrade. New rows always provide an explicit reviewed value in Python.
    op.add_column(
        "run_branches",
        sa.Column(
            "technique_id",
            sa.String(length=160),
            nullable=False,
            server_default="general.review",
        ),
    )
    op.add_column(
        "run_branches",
        sa.Column("branch_scope", sa.String(length=160), nullable=False, server_default="run:all"),
    )
    op.add_column(
        "run_branches",
        sa.Column("evidence_strength", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "run_branches",
        sa.Column("expected_value", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "run_branches",
        sa.Column("normalized_cost", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "run_branches",
        sa.Column("repetition_penalty", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "run_branches",
        sa.Column("consecutive_no_observation", sa.Integer(), nullable=False, server_default="0"),
    )

    op.add_column(
        "worker_tasks",
        sa.Column(
            "technique_id",
            sa.String(length=160),
            nullable=False,
            server_default="general.review",
        ),
    )
    op.add_column(
        "worker_tasks",
        sa.Column("branch_scope", sa.String(length=160), nullable=False, server_default="run:all"),
    )
    op.add_column(
        "worker_tasks",
        sa.Column(
            "attempt_fingerprint",
            sa.String(length=64),
            nullable=False,
            server_default="0" * 64,
        ),
    )
    op.create_index(
        "ix_worker_tasks_run_fingerprint",
        "worker_tasks",
        ["run_id", "attempt_fingerprint"],
        # Historical M1–M3 rows receive the same compatibility default during
        # an in-place upgrade, so uniqueness is enforced by the M4 scheduler
        # for new active tasks rather than making a deployed migration fail.
        unique=False,
    )

    op.create_table(
        "hint_cards",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("template_id", sa.String(length=160), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("technique_id", sa.String(length=160), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("directive", sa.String(length=32), nullable=False),
        sa.Column("target_ref", sa.String(length=160), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("epistemic_status", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_hint_cards_idempotency"),
    )
    op.create_index("ix_hint_cards_run_id", "hint_cards", ["run_id"], unique=False)
    op.create_index("ix_hint_cards_run_status", "hint_cards", ["run_id", "status"], unique=False)
    op.create_index(
        "ix_hint_cards_run_technique", "hint_cards", ["run_id", "technique_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_hint_cards_run_technique", table_name="hint_cards")
    op.drop_index("ix_hint_cards_run_status", table_name="hint_cards")
    op.drop_index("ix_hint_cards_run_id", table_name="hint_cards")
    op.drop_table("hint_cards")
    op.drop_index("ix_worker_tasks_run_fingerprint", table_name="worker_tasks")
    op.drop_column("worker_tasks", "attempt_fingerprint")
    op.drop_column("worker_tasks", "branch_scope")
    op.drop_column("worker_tasks", "technique_id")
    op.drop_column("run_branches", "consecutive_no_observation")
    op.drop_column("run_branches", "repetition_penalty")
    op.drop_column("run_branches", "normalized_cost")
    op.drop_column("run_branches", "expected_value")
    op.drop_column("run_branches", "evidence_strength")
    op.drop_column("run_branches", "branch_scope")
    op.drop_column("run_branches", "technique_id")
