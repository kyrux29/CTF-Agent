"""Record when a Power session's workspace container was reclaimed.

Cleanup only ever ran from two places: an operator pressing Stop, and a
flag-router acceptance. A run that ended on its own - ``failed``,
``budget_exhausted``, every racer dead - scheduled nothing, so its containers
outlived it. The in-process cleanup task was also cancelled rather than
awaited at shutdown, so an API restart during the grace window leaked the
rest. Twenty-four containers survived thirteen finished runs.

A sweep can now find those workspaces, and this column is what stops it from
destroying the same one on every pass: ``workspace_id`` is not nullable, so
the release needs its own mark.

Revision ID: 0010_power_workspace_release
Revises: 0009_power_pi_resume
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_power_workspace_release"
down_revision = "0009_power_pi_resume"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "power_pi_sessions",
        sa.Column("workspace_released_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("power_pi_sessions", "workspace_released_at")
