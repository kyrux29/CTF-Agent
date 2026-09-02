"""Add durable runtime state for the Pi v0.1 kernel.

Revision ID: 0002_runtime_kernel
Revises: 0001_initial
Create Date: 2026-08-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_runtime_kernel"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _create_event_append_only_guards() -> None:
    """Install a database-level last line of defense for the event ledger."""

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION ctfmesh_reject_run_event_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'run_events_append_only';
            END;
            $$;
            """
        )
        op.execute(
            """
            CREATE TRIGGER run_events_append_only_guard
            BEFORE UPDATE OR DELETE ON run_events
            FOR EACH ROW
            EXECUTE FUNCTION ctfmesh_reject_run_event_mutation();
            """
        )
        return
    op.execute(
        """
        CREATE TRIGGER run_events_no_update
        BEFORE UPDATE ON run_events
        BEGIN
            SELECT RAISE(ABORT, 'run_events_append_only');
        END;
        """
    )
    op.execute(
        """
        CREATE TRIGGER run_events_no_delete
        BEFORE DELETE ON run_events
        BEGIN
            SELECT RAISE(ABORT, 'run_events_append_only');
        END;
        """
    )


def _drop_event_append_only_guards() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS run_events_append_only_guard ON run_events")
        op.execute("DROP FUNCTION IF EXISTS ctfmesh_reject_run_event_mutation()")
        return
    op.execute("DROP TRIGGER IF EXISTS run_events_no_update")
    op.execute("DROP TRIGGER IF EXISTS run_events_no_delete")


def upgrade() -> None:
    with op.batch_alter_table("runs") as batch_op:
        batch_op.add_column(
            sa.Column("start_idempotency_key", sa.String(length=200), nullable=True)
        )
        batch_op.add_column(sa.Column("start_request_digest", sa.String(length=64), nullable=True))
        batch_op.create_unique_constraint("uq_runs_start_idempotency", ["start_idempotency_key"])

    op.add_column(
        "run_events",
        sa.Column("prev_hash", sa.String(length=64), server_default="", nullable=False),
    )
    op.add_column(
        "run_events",
        sa.Column("event_hash", sa.String(length=64), server_default="", nullable=False),
    )

    op.create_table(
        "run_branches",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("family", sa.String(length=100), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.Float(), nullable=False),
        sa.Column("novelty", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "family", "state", name="uq_run_branch_family_state"),
    )
    op.create_index("ix_run_branches_run_id", "run_branches", ["run_id"], unique=False)
    op.create_index("ix_run_branches_run_state", "run_branches", ["run_id", "state"], unique=False)

    op.create_table(
        "context_manifests",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("task_id", sa.String(length=64), nullable=False),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id"),
    )
    op.create_index("ix_context_manifests_run", "context_manifests", ["run_id"], unique=False)

    op.create_table(
        "worker_tasks",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=160), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("required_evidence", sa.JSON(), nullable=False),
        sa.Column("context_manifest_id", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_version", sa.Integer(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["branch_id"], ["run_branches.id"]),
        sa.ForeignKeyConstraint(["context_manifest_id"], ["context_manifests.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_worker_tasks_run_id", "worker_tasks", ["run_id"], unique=False)
    op.create_index("ix_worker_tasks_state", "worker_tasks", ["state"], unique=False)
    op.create_index("ix_worker_tasks_run_state", "worker_tasks", ["run_id", "state"], unique=False)
    op.create_index(
        "ix_worker_tasks_lease", "worker_tasks", ["state", "lease_expires_at"], unique=False
    )

    op.create_table(
        "agent_jobs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("payload_ref", sa.String(length=500), nullable=True),
        sa.Column("payload_digest", sa.String(length=64), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_version", sa.Integer(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_agent_job_idempotency"),
    )
    op.create_index("ix_agent_jobs_run_id", "agent_jobs", ["run_id"], unique=False)
    op.create_index(
        "ix_agent_jobs_claim",
        "agent_jobs",
        ["state", "lease_expires_at", "created_at"],
        unique=False,
    )

    op.create_table(
        "idempotency_records",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=80), nullable=False),
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("result_ref", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "scope", "key", name="uq_idempotency_record"),
    )
    op.create_index("ix_idempotency_records_run", "idempotency_records", ["run_id"], unique=False)

    op.create_table(
        "budget_ledger",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("dimension", sa.String(length=64), nullable=False),
        sa.Column("debit", sa.Float(), nullable=False),
        sa.Column("remaining_after", sa.Float(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_budget_ledger_run_dimension", "budget_ledger", ["run_id", "dimension"], unique=False
    )

    op.create_table(
        "outbox",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("payload_ref", sa.String(length=500), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["run_events.event_id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", name="uq_outbox_event"),
    )
    op.create_index("ix_outbox_run_id", "outbox", ["run_id"], unique=False)
    op.create_index("ix_outbox_pending", "outbox", ["published_at", "created_at"], unique=False)

    op.create_table(
        "preflight_observations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "kind", name="uq_preflight_observation_kind"),
    )
    op.create_index(
        "ix_preflight_observations_run", "preflight_observations", ["run_id"], unique=False
    )

    op.add_column(
        "verifications",
        sa.Column("verification_proof_ref", sa.String(length=64), nullable=True),
    )
    _create_event_append_only_guards()


def downgrade() -> None:
    _drop_event_append_only_guards()
    op.drop_column("verifications", "verification_proof_ref")
    op.drop_index("ix_preflight_observations_run", table_name="preflight_observations")
    op.drop_table("preflight_observations")
    op.drop_index("ix_outbox_pending", table_name="outbox")
    op.drop_index("ix_outbox_run_id", table_name="outbox")
    op.drop_table("outbox")
    op.drop_index("ix_budget_ledger_run_dimension", table_name="budget_ledger")
    op.drop_table("budget_ledger")
    op.drop_index("ix_idempotency_records_run", table_name="idempotency_records")
    op.drop_table("idempotency_records")
    op.drop_index("ix_agent_jobs_claim", table_name="agent_jobs")
    op.drop_index("ix_agent_jobs_run_id", table_name="agent_jobs")
    op.drop_table("agent_jobs")
    op.drop_index("ix_worker_tasks_lease", table_name="worker_tasks")
    op.drop_index("ix_worker_tasks_run_state", table_name="worker_tasks")
    op.drop_index("ix_worker_tasks_state", table_name="worker_tasks")
    op.drop_index("ix_worker_tasks_run_id", table_name="worker_tasks")
    op.drop_table("worker_tasks")
    op.drop_index("ix_context_manifests_run", table_name="context_manifests")
    op.drop_table("context_manifests")
    op.drop_index("ix_run_branches_run_state", table_name="run_branches")
    op.drop_index("ix_run_branches_run_id", table_name="run_branches")
    op.drop_table("run_branches")
    op.drop_column("run_events", "event_hash")
    op.drop_column("run_events", "prev_hash")
    with op.batch_alter_table("runs") as batch_op:
        batch_op.drop_constraint("uq_runs_start_idempotency", type_="unique")
        batch_op.drop_column("start_request_digest")
        batch_op.drop_column("start_idempotency_key")
