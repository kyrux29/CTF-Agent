"""Durability and deny-path coverage for the Milestone 1 run kernel."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from ctfmesh_db import Database, Repository
from ctfmesh_domain import (
    ChallengeManifest,
    ContextBudgetSlice,
    ContextEvidenceRef,
    ContextManifest,
    PreflightObservation,
    PreflightObservationKind,
    RuntimeArtifact,
    RuntimeTask,
)
from ctfmesh_orchestrator import RunEngine, RunEngineError
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError


def kernel_manifest() -> ChallengeManifest:
    """Return a valid offline-only manifest used by deterministic kernel tests."""

    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {
                "name": "kernel-contract-case",
                "category": "web",
                "tags": ["kernel", "offline"],
            },
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "bundle/source.zip", "role": "source"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:-]+\}"],
                    "source_policy": {
                        "allow_from_target_response": True,
                        "allow_from_target_filesystem": True,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 2,
                },
                "limits": {
                    "wall_time_seconds": 600,
                    "max_worker_turns": 12,
                    "max_tool_calls": 16,
                    "max_http_requests": 16,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1.0,
                    "max_artifact_bytes": 1_000_000,
                },
                "providers": {"preferred": "operator-pending", "fallbacks": []},
                "memory": {
                    "namespace": "kernel-test",
                    "cutoff": "2026-08-28T00:00:00Z",
                    "internet_search": False,
                },
            },
        }
    )


def run_budget() -> dict[str, int | float]:
    """Stay inside the manifest limits while exercising ledger behavior."""

    return {
        "wall_time_seconds": 300,
        "max_tool_calls": 8,
        "max_http_requests": 8,
        "max_cost_usd": 0.5,
    }


async def create_challenge(repository: Repository) -> dict[str, Any]:
    manifest = kernel_manifest()
    return await repository.create_challenge(
        manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
        name=str(manifest.metadata.name),
    )


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[Repository]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'runtime.db'}")
    await database.create_schema()
    try:
        yield Repository(database)
    finally:
        await database.close()


def test_context_manifest_is_digest_pinned_and_rejects_untyped_worker_context() -> None:
    now = datetime.now(UTC)
    manifest = ContextManifest.issue(
        id="ctx-1",
        run_id="run-1",
        task_id="task-1",
        challenge_digest="a" * 64,
        role="source_auditor",
        objective="Review sealed evidence only.",
        allowed_tool_ids=("finding.submit",),
        evidence_refs=(
            ContextEvidenceRef(
                observation_id="obs-1",
                artifact_id="artifact-1",
                digest="b" * 64,
            ),
        ),
        hypothesis_refs=(),
        active_hint_refs=(),
        attempt_fingerprints=(),
        budget_slice=ContextBudgetSlice(tool_calls=1, input_tokens=100, output_tokens=10),
        created_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    serialized = manifest.model_dump(mode="json", by_alias=True)
    assert ContextManifest.model_validate(serialized) == manifest

    with pytest.raises(ValidationError, match="context_manifest_digest_mismatch"):
        ContextManifest.model_validate({**serialized, "digest": "0" * 64})
    with pytest.raises(ValidationError, match="extra_forbidden"):
        RuntimeTask.model_validate(
            {
                "id": "task-1",
                "run_id": "run-1",
                "branch_id": "branch-1",
                "role": "source_auditor",
                "objective": "Review sealed evidence only.",
                "required_evidence": ["obs-1"],
                "context_manifest_id": "ctx-1",
                "lease_version": 0,
                "deadline_at": now,
                "context": {"arbitrary": "input is forbidden"},
            }
        )


@pytest.mark.asyncio
async def test_run_engine_creates_preflight_evidence_context_task_and_outbox(
    repository: Repository,
    tmp_path: Path,
) -> None:
    challenge = await create_challenge(repository)
    source_root = tmp_path / "trusted-source"
    source_root.mkdir()
    (source_root / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.get('/health')\n"
        "def health(): return 'ok'\n",
        encoding="utf-8",
    )
    engine = RunEngine(
        repository=repository,
        artifact_root=tmp_path / "artifacts",
        source_roots={challenge["id"]: source_root},
    )

    first = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-kernel-1",
    )
    duplicate = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-kernel-1",
    )
    assert first["status"] == "preparing"
    assert duplicate["id"] == first["id"]
    assert len(await repository.list_agent_jobs(first["id"])) == 1

    completed = await engine.process_next_preflight(worker_id="preflight-test")
    assert completed is not None
    assert completed["run"]["status"] == "running"
    tasks = await repository.list_worker_tasks(first["id"])
    observations = await repository.list_preflight_observations(first["id"])
    context = await repository.get_context_manifest(tasks[0]["context_manifest_id"])
    events = await repository.list_events(first["id"])
    outbox = await repository.list_outbox(first["id"])

    assert len(tasks) == 1
    assert "context" not in tasks[0]
    assert len(observations) == len(PreflightObservationKind)
    assert context is not None
    assert set(tasks[0]["required_evidence"]) == {item["id"] for item in observations}
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert len(outbox) == len(events)
    assert {row["event_id"] for row in outbox} == {event["event_id"] for event in events}
    previous_hash = ""
    for event in events:
        integrity = event["integrity"]
        assert integrity["prev_hash"] == previous_hash
        assert len(integrity["event_hash"]) == 64
        previous_hash = integrity["event_hash"]


@pytest.mark.asyncio
async def test_agent_job_lease_claim_allows_exactly_one_concurrent_worker(
    repository: Repository,
    tmp_path: Path,
) -> None:
    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-lease-race",
    )

    claims = await asyncio.gather(
        *(
            repository.claim_agent_job(
                worker_id=f"lease-worker-{index}",
                lease_seconds=30,
                kinds=("preflight",),
            )
            for index in range(8)
        )
    )

    successful = [claim for claim in claims if claim is not None]
    assert len(successful) == 1
    assert successful[0]["run_id"] == run["id"]
    assert successful[0]["lease_version"] == 1
    assert (await repository.list_agent_jobs(run["id"]))[0]["state"] == "leased"


@pytest.mark.asyncio
async def test_agent_job_claim_can_be_scoped_without_leasing_another_run(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """An operator diagnostic cannot steal work from a concurrent live Pi run."""

    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    first = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-scope-first",
    )
    second = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="m3-operator-probe",
        budget=run_budget(),
        idempotency_key="run-start-scope-second",
    )

    claimed = await repository.claim_agent_job(
        worker_id="m3-operator-probe",
        lease_seconds=30,
        kinds=("preflight",),
        run_id=second["id"],
    )

    assert claimed is not None
    assert claimed["run_id"] == second["id"]
    assert (await repository.list_agent_jobs(first["id"]))[0]["state"] == "queued"
    with pytest.raises(ValueError, match="invalid_run_id"):
        await repository.claim_agent_job(
            worker_id="m3-operator-probe",
            run_id="../another-run",
        )


@pytest.mark.asyncio
async def test_preflight_failure_is_persisted_without_a_silent_retry(
    repository: Repository,
    tmp_path: Path,
) -> None:
    challenge = await create_challenge(repository)
    engine = RunEngine(
        repository=repository,
        artifact_root=tmp_path / "artifacts",
        source_roots={challenge["id"]: tmp_path / "missing-source-root"},
    )
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-preflight-failure",
    )

    with pytest.raises(RunEngineError, match="preflight_source_root_missing"):
        await engine.process_next_preflight(worker_id="preflight-failure-worker")

    persisted = await repository.get_run(run["id"])
    jobs = await repository.list_agent_jobs(run["id"])
    events = await repository.list_events(run["id"])
    assert persisted is not None
    assert persisted["status"] == "failed"
    assert jobs[0]["state"] == "failed"
    assert [event["type"] for event in events][-2:] == [
        "run.state.changed",
        "agent.job.failed",
    ]


@pytest.mark.asyncio
async def test_pi_runner_failure_stops_the_session_task_and_run_without_raw_error(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """A runner crash is fail-closed instead of leaving leased work runnable."""

    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-pi-failure",
    )
    assert await engine.process_next_preflight(worker_id="pi-failure-preflight") is not None
    start = await repository.claim_agent_job(
        worker_id="pi-failure-runner",
        lease_seconds=30,
        kinds=("start_session",),
    )
    assert start is not None
    reserved = await repository.reserve_pi_session(
        start["id"],
        worker_id="pi-failure-runner",
        lease_version=start["lease_version"],
    )
    await repository.activate_pi_session(
        start["id"],
        session_id=reserved["session"]["id"],
        worker_id="pi-failure-runner",
        lease_version=start["lease_version"],
    )
    turn = await repository.claim_agent_job(
        worker_id="pi-failure-runner",
        lease_seconds=30,
        kinds=("run_turn",),
    )
    assert turn is not None
    await repository.get_pi_agent_job_work(
        turn["id"],
        worker_id="pi-failure-runner",
        lease_version=turn["lease_version"],
    )

    failed = await repository.fail_pi_agent_job(
        turn["id"],
        worker_id="pi-failure-runner",
        lease_version=turn["lease_version"],
        reason="pi_turn_failed",
    )
    assert failed["state"] == "failed"
    persisted_run = await repository.get_run(run["id"])
    assert persisted_run is not None
    assert persisted_run["status"] == "failed"
    sessions = await repository.list_agent_sessions(run["id"])
    tasks = await repository.list_worker_tasks(run["id"])
    events = await repository.list_events(run["id"])
    assert sessions[0]["state"] == "failed"
    assert tasks[0]["state"] == "failed"
    assert all("CTF{" not in str(event) for event in events)


@pytest.mark.asyncio
async def test_corrupt_pi_session_enum_is_rejected_at_the_database_boundary(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """Closed domain enums must not silently accept a malformed durable row."""

    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-corrupt-session",
    )
    assert await engine.process_next_preflight(worker_id="corrupt-session-preflight") is not None
    start = await repository.claim_agent_job(
        worker_id="corrupt-session-runner",
        lease_seconds=30,
        kinds=("start_session",),
    )
    assert start is not None
    reserved = await repository.reserve_pi_session(
        start["id"],
        worker_id="corrupt-session-runner",
        lease_version=start["lease_version"],
    )
    async with repository.database.sessions() as session, session.begin():
        await session.execute(
            text("UPDATE agent_sessions SET state = 'invalid_state' WHERE id = :session_id"),
            {"session_id": reserved["session"]["id"]},
        )

    with pytest.raises(ValueError, match="stored_agent_session_invalid"):
        await repository.list_agent_sessions(run["id"])


@pytest.mark.asyncio
async def test_start_idempotency_survives_database_and_repository_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "restart.db"
    first_database = Database(f"sqlite+aiosqlite:///{database_path}")
    await first_database.create_schema()
    try:
        first_repository = Repository(first_database)
        challenge = await create_challenge(first_repository)
        first_engine = RunEngine(
            repository=first_repository,
            artifact_root=tmp_path / "artifacts",
        )
        first = await first_engine.start(
            challenge_id=challenge["id"],
            mode="assisted",
            provider="operator-pending",
            budget=run_budget(),
            idempotency_key="restart-safe-start",
        )
    finally:
        await first_database.close()

    second_database = Database(f"sqlite+aiosqlite:///{database_path}")
    await second_database.create_schema()
    try:
        second_repository = Repository(second_database)
        second_engine = RunEngine(
            repository=second_repository,
            artifact_root=tmp_path / "artifacts",
        )
        repeated = await second_engine.start(
            challenge_id=challenge["id"],
            mode="assisted",
            provider="operator-pending",
            budget=run_budget(),
            idempotency_key="restart-safe-start",
        )
        assert repeated["id"] == first["id"]
        assert len(await second_repository.list_agent_jobs(first["id"])) == 1
        with pytest.raises(ValueError, match="idempotency_conflict"):
            await second_engine.start(
                challenge_id=challenge["id"],
                mode="assisted",
                provider="different-provider",
                budget=run_budget(),
                idempotency_key="restart-safe-start",
            )
    finally:
        await second_database.close()


@pytest.mark.asyncio
async def test_pi_session_audit_and_pending_turn_survive_repository_restart(tmp_path: Path) -> None:
    """A runner restart resumes one durable session instead of creating another."""

    database_path = tmp_path / "pi-session-restart.db"
    first_database = Database(f"sqlite+aiosqlite:///{database_path}")
    await first_database.create_schema()
    try:
        first_repository = Repository(first_database)
        challenge = await create_challenge(first_repository)
        first_engine = RunEngine(
            repository=first_repository,
            artifact_root=tmp_path / "artifacts",
        )
        run = await first_engine.start(
            challenge_id=challenge["id"],
            mode="assisted",
            provider="operator-pending",
            budget=run_budget(),
            idempotency_key="pi-session-restart",
        )
        assert await first_engine.process_next_preflight(worker_id="restart-preflight") is not None
        start = await first_repository.claim_agent_job(
            worker_id="pi-runner-stable-id",
            lease_seconds=30,
            kinds=("start_session",),
        )
        assert start is not None
        reserved = await first_repository.reserve_pi_session(
            start["id"],
            worker_id="pi-runner-stable-id",
            lease_version=start["lease_version"],
        )
        session_id = reserved["session"]["id"]
        await first_repository.activate_pi_session(
            start["id"],
            session_id=session_id,
            worker_id="pi-runner-stable-id",
            lease_version=start["lease_version"],
        )
        events_before_restart = await first_repository.list_events(run["id"])
    finally:
        await first_database.close()

    second_database = Database(f"sqlite+aiosqlite:///{database_path}")
    await second_database.create_schema()
    try:
        second_repository = Repository(second_database)
        sessions = await second_repository.list_agent_sessions(run["id"])
        assert len(sessions) == 1
        persisted_session = sessions[0]
        assert persisted_session["id"] == session_id
        assert persisted_session["state"] == "ready"
        assert persisted_session["session_store_key"] == f"pi_{session_id}"
        assert "transcript" not in persisted_session
        assert "credential" not in persisted_session
        assert await second_repository.list_events(run["id"]) == events_before_restart

        # A replacement process with the stable configured runner ID can claim
        # the queued turn and recover the same sealed durable session metadata.
        turn = await second_repository.claim_agent_job(
            worker_id="pi-runner-stable-id",
            lease_seconds=30,
            kinds=("run_turn",),
        )
        assert turn is not None
        work = await second_repository.get_pi_agent_job_work(
            turn["id"],
            worker_id="pi-runner-stable-id",
            lease_version=turn["lease_version"],
        )
        assert work["session"]["id"] == session_id
        assert work["context_manifest"]["task_id"] == persisted_session["task_id"]
        await second_repository.complete_pi_turn(
            turn["id"],
            worker_id="pi-runner-stable-id",
            lease_version=turn["lease_version"],
            result_ref="agent:inconclusive",
        )
        events_after_restart = await second_repository.list_events(run["id"])
        assert [event["sequence"] for event in events_after_restart] == list(
            range(1, len(events_after_restart) + 1)
        )
    finally:
        await second_database.close()


@pytest.mark.asyncio
async def test_budget_ledger_exhaustion_is_durable_and_idempotent(
    repository: Repository,
    tmp_path: Path,
) -> None:
    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-budget",
    )
    assert await engine.process_next_preflight(worker_id="budget-preflight") is not None

    accepted = await repository.debit_budget(
        run["id"],
        dimension="max_tool_calls",
        amount=8,
        idempotency_key="budget-full-debit",
    )
    exhausted = await repository.debit_budget(
        run["id"],
        dimension="max_tool_calls",
        amount=1,
        idempotency_key="budget-denied-debit",
    )
    repeated = await repository.debit_budget(
        run["id"],
        dimension="max_tool_calls",
        amount=1,
        idempotency_key="budget-denied-debit",
    )

    assert accepted["accepted"] is True
    assert exhausted == repeated == {"accepted": False, "remaining": 0.0, "ledger_id": None}
    assert len(await repository.list_budget_ledger(run["id"])) == 1
    persisted = await repository.get_run(run["id"])
    assert persisted is not None
    assert persisted["status"] == "budget_exhausted"


@pytest.mark.asyncio
async def test_preflight_rejects_context_evidence_that_is_not_in_its_observations(
    repository: Repository,
    tmp_path: Path,
) -> None:
    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-invalid-evidence",
    )
    job = await repository.claim_agent_job(
        worker_id="evidence-worker",
        lease_seconds=30,
        kinds=("preflight",),
    )
    assert job is not None
    now = datetime.now(UTC)
    artifact = RuntimeArtifact(
        id="artifact-real",
        run_id=run["id"],
        sha256="a" * 64,
        name="preflight/manifest.json",
        media_type="application/json",
        size_bytes=1,
        classification="internal",
        producer="preflight-worker",
        locator=f"sha256:{'a' * 64}",
        created_at=now,
    )
    observation = PreflightObservation(
        id="obs-real",
        run_id=run["id"],
        kind=PreflightObservationKind.ARCHIVE_MANIFEST,
        artifact_id=artifact.id,
        digest=artifact.sha256,
        summary="One deterministic manifest observation.",
        created_at=now,
    )
    context = ContextManifest.issue(
        id="ctx-invalid-evidence",
        run_id=run["id"],
        task_id="task-invalid-evidence",
        challenge_digest=challenge["digest"],
        role="source_auditor",
        objective="Only use evidence references that were sealed by preflight.",
        allowed_tool_ids=("finding.submit",),
        evidence_refs=(
            ContextEvidenceRef(
                observation_id="obs-missing",
                artifact_id=artifact.id,
                digest=artifact.sha256,
            ),
        ),
        hypothesis_refs=(),
        active_hint_refs=(),
        attempt_fingerprints=(),
        budget_slice=ContextBudgetSlice(tool_calls=1, input_tokens=100, output_tokens=10),
        created_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    task = RuntimeTask(
        id="task-invalid-evidence",
        run_id=run["id"],
        branch_id="branch-invalid-evidence",
        role="source_auditor",
        objective="Only use evidence references that were sealed by preflight.",
        required_evidence=("obs-missing",),
        context_manifest_id=context.id,
        lease_version=0,
        deadline_at=now + timedelta(minutes=1),
    )

    with pytest.raises(ValueError, match="context_manifest_unknown_evidence"):
        await repository.complete_preflight_job(
            job["id"],
            worker_id="evidence-worker",
            lease_version=job["lease_version"],
            branch_family="deterministic-preflight",
            artifacts=(artifact,),
            observations=(observation,),
            context_manifest=context,
            task=task,
        )


@pytest.mark.asyncio
async def test_event_rows_reject_database_update_and_delete(
    repository: Repository,
    tmp_path: Path,
) -> None:
    challenge = await create_challenge(repository)
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
        idempotency_key="run-start-append-only",
    )

    async with repository.database.sessions() as session:
        with pytest.raises(IntegrityError, match="run_events_append_only"):
            await session.execute(
                text("UPDATE run_events SET event_type = 'run.changed' WHERE run_id = :run_id"),
                {"run_id": run["id"]},
            )
        await session.rollback()
    async with repository.database.sessions() as session:
        with pytest.raises(IntegrityError, match="run_events_append_only"):
            await session.execute(
                text("DELETE FROM run_events WHERE run_id = :run_id"),
                {"run_id": run["id"]},
            )
        await session.rollback()


@pytest.mark.asyncio
async def test_verified_run_requires_an_authoritative_proof_artifact(
    repository: Repository,
) -> None:
    challenge = await create_challenge(repository)
    run = await repository.create_run(
        challenge["id"],
        mode="assisted",
        provider="operator-pending",
        budget=run_budget(),
    )
    for state in ("preparing", "running", "verifying"):
        await repository.transition_run(
            run["id"],
            state,
            actor={"kind": "system", "id": "test"},
        )

    with pytest.raises(ValueError, match="verification_proof_ref_required"):
        await repository.record_verification(
            {
                "run_id": run["id"],
                "verified": True,
                "exploit_digest": "a" * 64,
                "environment_digest": "b" * 64,
                "flag_sha256": "c" * 64,
                "masked_flag": "CTF{***masked***}",
                "replay_results": [
                    {"passed": True, "started_from_clean_reset": True, "attempt": 1},
                    {"passed": True, "started_from_clean_reset": True, "attempt": 2},
                ],
                "provenance": {"fixture": "no-proof-deny-path"},
            }
        )
