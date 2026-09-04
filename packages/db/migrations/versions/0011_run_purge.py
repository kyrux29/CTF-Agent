"""Let an operator remove a finished run without weakening the event ledger.

The append-only guard rejected every delete on ``run_events``, so a run could
be finished but never removed: thirteen test runs and ten thousand events
accumulated with no supported way to clear them, and the only alternative was
dropping the whole database.

The guard's purpose is that a run's own past can never be quietly rewritten.
Removing a finished experiment is a different act from editing one. This
migration teaches the trigger to tell them apart: a delete is accepted only
while a ``run_purges`` row names that exact run, and that row exists only
inside the deleting transaction. Updates stay refused unconditionally.

Revision ID: 0011_run_purge
Revises: 0010_power_workspace_release
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_run_purge"
down_revision = "0010_power_workspace_release"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_purges",
        sa.Column("run_id", sa.String(length=64), primary_key=True),
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION ctfmesh_reject_run_event_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'DELETE'
                   AND EXISTS (SELECT 1 FROM run_purges WHERE run_id = OLD.run_id)
                THEN
                    RETURN OLD;
                END IF;
                RAISE EXCEPTION 'run_events_append_only';
            END;
            $$;
            """
        )
        return
    op.execute("DROP TRIGGER IF EXISTS run_events_no_delete")
    op.execute(
        """
        CREATE TRIGGER run_events_no_delete
        BEFORE DELETE ON run_events
        WHEN NOT EXISTS (SELECT 1 FROM run_purges WHERE run_id = OLD.run_id)
        BEGIN
            SELECT RAISE(ABORT, 'run_events_append_only');
        END
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION ctfmesh_reject_run_event_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'run_events_append_only';
            END;
            $$;
            """
        )
    else:
        op.execute("DROP TRIGGER IF EXISTS run_events_no_delete")
        op.execute(
            """
            CREATE TRIGGER run_events_no_delete
            BEFORE DELETE ON run_events
            BEGIN
                SELECT RAISE(ABORT, 'run_events_append_only');
            END
            """
        )
    op.drop_table("run_purges")
