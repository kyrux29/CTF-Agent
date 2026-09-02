from __future__ import annotations

import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pytest import MonkeyPatch
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


def test_migrations_create_the_durable_control_plane_schema(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """The deployment migration must work independently of create_schema()."""

    root = Path(__file__).resolve().parents[2]
    database_path = tmp_path / "migrated.db"
    monkeypatch.setenv("CTFMESH_DATABASE_URL", f"sqlite+aiosqlite:///{database_path}")

    config = Config(str(root / "packages/db/alembic.ini"))
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database_path}")
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert {
        "alembic_version",
        "challenges",
        "runs",
        "run_sequences",
        "run_events",
        "facts",
        "hypotheses",
        "experiments",
        "artifacts",
        "verifications",
        "agent_jobs",
        "agent_sessions",
        "agent_steers",
        "budget_ledger",
        "context_manifests",
        "idempotency_records",
        "outbox",
        "preflight_observations",
        "run_branches",
        "worker_tasks",
        "hint_cards",
        "tool_invocations",
    }.issubset(tables)

    # The migration itself, rather than only ``Database.create_schema()``, is
    # responsible for the last-line append-only event protection in deploys.
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO challenges (id, name, manifest, digest, created_at) "
                    "VALUES (:id, :name, :manifest, :digest, :created_at)"
                ),
                {
                    "id": "challenge-migration",
                    "name": "migration-case",
                    "manifest": json.dumps({"spec": {}}),
                    "digest": "a" * 64,
                    "created_at": "2026-08-28T00:00:00+00:00",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO runs (id, challenge_id, status, mode, provider, budget, result, "
                    "created_at, updated_at) VALUES "
                    "(:id, :challenge_id, :status, :mode, :provider, :budget, :result, "
                    ":created_at, :updated_at)"
                ),
                {
                    "id": "run-migration",
                    "challenge_id": "challenge-migration",
                    "status": "created",
                    "mode": "assisted",
                    "provider": "operator-pending",
                    "budget": json.dumps({}),
                    "result": None,
                    "created_at": "2026-08-28T00:00:00+00:00",
                    "updated_at": "2026-08-28T00:00:00+00:00",
                },
            )
            connection.execute(
                text("INSERT INTO run_sequences (run_id, current) VALUES (:run_id, :current)"),
                {"run_id": "run-migration", "current": 1},
            )
            connection.execute(
                text(
                    "INSERT INTO run_events (event_id, run_id, sequence, event_type, "
                    "schema_version, "
                    "actor, idempotency_key, payload, payload_sha256, created_at) VALUES "
                    "(:event_id, :run_id, :sequence, :event_type, :schema_version, :actor, "
                    ":idempotency_key, :payload, :payload_sha256, :created_at)"
                ),
                {
                    "event_id": "event-migration",
                    "run_id": "run-migration",
                    "sequence": 1,
                    "event_type": "run.created",
                    "schema_version": 1,
                    "actor": json.dumps({"kind": "system", "id": "migration"}),
                    "idempotency_key": "migration-event",
                    "payload": json.dumps({"safe": True}),
                    "payload_sha256": "b" * 64,
                    "created_at": "2026-08-28T00:00:00+00:00",
                },
            )

        with engine.connect() as connection:
            with pytest.raises(IntegrityError, match="run_events_append_only"):
                connection.execute(
                    text(
                        "UPDATE run_events SET event_type = 'run.changed' "
                        "WHERE event_id = :event_id"
                    ),
                    {"event_id": "event-migration"},
                )
            connection.rollback()
        with engine.connect() as connection:
            with pytest.raises(IntegrityError, match="run_events_append_only"):
                connection.execute(
                    text("DELETE FROM run_events WHERE event_id = :event_id"),
                    {"event_id": "event-migration"},
                )
            connection.rollback()
    finally:
        engine.dispose()
