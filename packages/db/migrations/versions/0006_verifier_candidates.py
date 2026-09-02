"""Persist M5 declarative candidates and independent replay attempts.

Revision ID: 0006_verifier_candidates
Revises: 0005_hint_scheduler
Create Date: 2026-08-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_verifier_candidates"
down_revision = "0005_hint_scheduler"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add body-free candidate/proof projections without rewriting history."""

    op.create_table(
        "exploit_candidates",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("tool_call_id", sa.String(length=160), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("challenge_digest", sa.String(length=64), nullable=False),
        sa.Column("technique_id", sa.String(length=160), nullable=False),
        sa.Column("plan_artifact_id", sa.String(length=64), nullable=False),
        sa.Column("plan_artifact_digest", sa.String(length=64), nullable=False),
        sa.Column("plan_semantic_digest", sa.String(length=64), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("verification_job_id", sa.String(length=64), nullable=True),
        sa.Column("verification_id", sa.String(length=64), nullable=True),
        sa.Column("failure_code", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["branch_id"], ["run_branches.id"]),
        sa.ForeignKeyConstraint(["plan_artifact_id"], ["artifacts.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["worker_tasks.id"]),
        sa.ForeignKeyConstraint(["verification_id"], ["verifications.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id", "session_id", "tool_call_id", name="uq_exploit_candidate_tool_call"
        ),
        sa.UniqueConstraint(
            "run_id", "task_id", "idempotency_key", name="uq_exploit_candidate_idempotency"
        ),
    )
    op.create_index(
        "ix_exploit_candidates_run_status", "exploit_candidates", ["run_id", "status"], unique=False
    )
    op.create_index(
        "ix_exploit_candidates_branch_id", "exploit_candidates", ["branch_id"], unique=False
    )
    op.create_index(
        "ix_exploit_candidates_task_id", "exploit_candidates", ["task_id"], unique=False
    )
    op.create_index(
        "ix_exploit_candidates_session_id", "exploit_candidates", ["session_id"], unique=False
    )

    op.create_table(
        "verification_attempts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("candidate_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("verification_id", sa.String(length=64), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("reset_id", sa.String(length=160), nullable=False),
        sa.Column("target_generation", sa.Integer(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("started_from_clean_reset", sa.Boolean(), nullable=False),
        sa.Column("flag_sha256", sa.String(length=64), nullable=True),
        sa.Column("controller_proof_id", sa.String(length=160), nullable=True),
        sa.Column("controller_signature", sa.String(length=128), nullable=True),
        sa.Column("failure_code", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["exploit_candidates.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["verification_id"], ["verifications.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("candidate_id", "attempt", name="uq_verification_attempt_index"),
    )
    op.create_index(
        "ix_verification_attempts_run_candidate",
        "verification_attempts",
        ["run_id", "candidate_id"],
        unique=False,
    )
    op.create_index(
        "ix_verification_attempts_candidate_id",
        "verification_attempts",
        ["candidate_id"],
        unique=False,
    )
    op.create_index(
        "ix_verification_attempts_run_id", "verification_attempts", ["run_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_verification_attempts_run_id", table_name="verification_attempts")
    op.drop_index("ix_verification_attempts_candidate_id", table_name="verification_attempts")
    op.drop_index("ix_verification_attempts_run_candidate", table_name="verification_attempts")
    op.drop_table("verification_attempts")
    op.drop_index("ix_exploit_candidates_session_id", table_name="exploit_candidates")
    op.drop_index("ix_exploit_candidates_task_id", table_name="exploit_candidates")
    op.drop_index("ix_exploit_candidates_branch_id", table_name="exploit_candidates")
    op.drop_index("ix_exploit_candidates_run_status", table_name="exploit_candidates")
    op.drop_table("exploit_candidates")
