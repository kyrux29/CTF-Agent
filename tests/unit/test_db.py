from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from ctfmesh_db import Database, Repository


def manifest_data() -> dict[str, object]:
    return {
        "spec": {
            "mode": "assisted",
            "limits": {
                "wall_time_seconds": 3600,
                "max_tool_calls": 500,
                "max_http_requests": 1500,
                "max_cost_usd": 20.0,
            },
            "flag": {"replay_count": 2},
        }
    }


def run_budget() -> dict[str, int | float]:
    return {
        "wall_time_seconds": 300,
        "max_tool_calls": 30,
        "max_http_requests": 20,
        "max_cost_usd": 1.0,
    }


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[Repository]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'repository.db'}")
    await database.create_schema()
    try:
        yield Repository(database)
    finally:
        await database.close()


async def create_run(repository: Repository) -> dict[str, Any]:
    challenge = await repository.create_challenge(manifest_data(), name="audit-lab")
    return await repository.create_run(
        challenge["id"],
        mode="assisted",
        provider="fake-deterministic",
        budget=run_budget(),
    )


async def add_authoritative_proof(repository: Repository, run_id: str) -> dict[str, Any]:
    """Create the immutable proof artifact required by the verifier transition."""

    return await repository.add_artifact(
        {
            "id": f"proof-{run_id[-20:]}",
            "run_id": run_id,
            "sha256": "d" * 64,
            "name": "verification/proof.json",
            "media_type": "application/json",
            "size_bytes": 1,
            "classification": "internal",
            "producer": "independent-verifier",
            "locator": f"sha256:{'d' * 64}",
        }
    )


@pytest.mark.asyncio
async def test_create_run_and_initial_event_are_atomic(
    repository: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    challenge = await repository.create_challenge(manifest_data(), name="audit-lab")

    async def fail_append(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("simulated_event_failure")

    monkeypatch.setattr(repository, "_append_event_row", fail_append)
    with pytest.raises(RuntimeError, match="simulated_event_failure"):
        await repository.create_run(
            challenge["id"],
            mode="assisted",
            provider="fake-deterministic",
            budget=run_budget(),
        )

    assert await repository.list_runs() == []


@pytest.mark.asyncio
async def test_event_idempotency_rejects_different_payload(repository: Repository) -> None:
    run = await create_run(repository)
    await repository.append_event(
        run["id"],
        "worker.message.completed",
        {"summary": "first"},
        actor={"kind": "worker", "id": "worker-1"},
        idempotency_key="worker-command-1",
    )

    with pytest.raises(ValueError, match="idempotency_conflict"):
        await repository.append_event(
            run["id"],
            "worker.message.completed",
            {"summary": "changed"},
            actor={"kind": "worker", "id": "worker-1"},
            idempotency_key="worker-command-1",
        )

    events = await repository.list_events(run["id"])
    assert [event["sequence"] for event in events] == [1, 2]


@pytest.mark.asyncio
async def test_event_actor_must_use_a_known_kind_and_safe_identifier(
    repository: Repository,
) -> None:
    run = await create_run(repository)

    with pytest.raises(ValueError, match="invalid_event_actor"):
        await repository.append_event(
            run["id"],
            "worker.message.completed",
            {"summary": "actor validation regression"},
            actor={"kind": "untrusted", "id": "worker-1"},
            idempotency_key="invalid-actor-kind",
        )
    with pytest.raises(ValueError, match="invalid_event_actor"):
        await repository.append_event(
            run["id"],
            "worker.message.completed",
            {"summary": "actor validation regression"},
            actor={"kind": "worker", "id": "invalid id"},
            idempotency_key="invalid-actor-id",
        )


@pytest.mark.asyncio
async def test_repeated_pause_resume_cycles_each_append_an_event(repository: Repository) -> None:
    run = await create_run(repository)
    for status in ("preparing", "running", "paused", "running", "paused"):
        await repository.transition_run(
            run["id"],
            status,
            actor={"kind": "system", "id": "test"},
        )

    events = await repository.list_events(run["id"])
    assert [event["type"] for event in events].count("run.paused") == 2
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))


@pytest.mark.asyncio
async def test_triage_run_can_complete_without_bypassing_verification(
    repository: Repository,
) -> None:
    run = await create_run(repository)
    completed = run
    for status in ("preparing", "running", "completed"):
        completed = await repository.transition_run(
            run["id"], status, actor={"kind": "system", "id": "triage"}
        )
    assert completed["status"] == "completed"

    with pytest.raises(ValueError, match="solved_requires_verified_replay"):
        await repository.transition_run(
            run["id"], "solved", actor={"kind": "system", "id": "triage"}
        )


@pytest.mark.asyncio
async def test_only_independent_verifier_proof_path_can_set_solved_status(
    repository: Repository,
) -> None:
    """A spoofed verifier actor cannot bypass the sealed verification path."""

    run = await create_run(repository)
    for status in ("preparing", "running", "verifying"):
        await repository.transition_run(run["id"], status, actor={"kind": "system", "id": "test"})

    with pytest.raises(ValueError, match="solved_requires_verified_replay"):
        await repository.transition_run(
            run["id"],
            "solved",
            actor={"kind": "verifier", "id": "spoofed-verifier"},
        )
    pending_run = await repository.get_run(run["id"])
    assert pending_run is not None
    assert pending_run["status"] == "verifying"
    proof = await add_authoritative_proof(repository, run["id"])

    await repository.record_verification(
        {
            "run_id": run["id"],
            "verified": True,
            "exploit_digest": "a" * 64,
            "environment_digest": "b" * 64,
            "flag_sha256": "c" * 64,
            "masked_flag": "CTF{***masked***}",
            "verification_proof_ref": proof["id"],
            "replay_results": [
                {"passed": True, "started_from_clean_reset": True, "attempt": 1},
                {"passed": True, "started_from_clean_reset": True, "attempt": 2},
            ],
            "provenance": {"artifact_id": "artifact-1"},
        }
    )

    solved_run = await repository.get_run(run["id"])
    assert solved_run is not None
    assert solved_run["status"] == "solved"
    event = (await repository.list_events(run["id"]))[-1]
    assert event["type"] == "verification.completed"
    assert event["actor"] == {"kind": "verifier", "id": "independent-verifier"}


@pytest.mark.asyncio
async def test_power_flag_router_can_complete_only_an_active_run_with_digest_evidence(
    repository: Repository,
) -> None:
    """P2's router path persists no raw flag and stays idempotent for one proof."""

    run = await create_run(repository)
    for status in ("preparing", "running"):
        await repository.transition_run(run["id"], status, actor={"kind": "system", "id": "test"})
    flag_digest = "e" * 64
    observation_digest = "f" * 64
    accepted = await repository.complete_power_flag(
        run_id=run["id"],
        flag_sha256=flag_digest,
        masked_flag="CTF{…e}",
        observation_artifact_id=f"sha256:{observation_digest}",
        observation_sha256=observation_digest,
    )
    assert accepted is True
    solved = await repository.get_run(run["id"])
    assert solved is not None
    assert solved["status"] == "solved"
    assert solved["result"] == {
        "profile": "power",
        "verifier": "flag-router",
        "flag_sha256": flag_digest,
        "masked_flag": "CTF{…e}",
        "observation_artifact_id": f"sha256:{observation_digest}",
        "observation_sha256": observation_digest,
    }
    assert await repository.complete_power_flag(
        run_id=run["id"],
        flag_sha256=flag_digest,
        masked_flag="CTF{…e}",
        observation_artifact_id=f"sha256:{observation_digest}",
        observation_sha256=observation_digest,
    )
    event = (await repository.list_events(run["id"]))[-1]
    assert event["type"] == "power.flag.verified"
    assert event["actor"] == {"kind": "verifier", "id": "flag-router"}
    assert "raw_flag" not in event["payload"]


@pytest.mark.asyncio
async def test_concurrent_event_appends_allocate_contiguous_sequences(
    repository: Repository,
) -> None:
    run = await create_run(repository)

    await asyncio.gather(
        *(
            repository.append_event(
                run["id"],
                "worker.message.completed",
                {"index": index},
                actor={"kind": "worker", "id": "worker-1"},
                idempotency_key=f"message-{index}",
            )
            for index in range(20)
        )
    )

    events = await repository.list_events(run["id"])
    assert [event["sequence"] for event in events] == list(range(1, 22))


@pytest.mark.asyncio
async def test_completed_experiment_cannot_be_rewritten(repository: Repository) -> None:
    run = await create_run(repository)
    hypothesis = await repository.add_hypothesis(
        {
            "id": "hypothesis-1",
            "run_id": run["id"],
            "branch_id": "branch-1",
            "family": "idor",
            "statement": "Object ownership may not be checked.",
            "confidence": 0.5,
            "supporting_fact_ids": [],
            "contradicting_fact_ids": [],
            "falsifiers": ["A cross-user object request is denied."],
        }
    )
    experiment = await repository.add_experiment(
        {
            "id": "experiment-1",
            "run_id": run["id"],
            "hypothesis_id": hypothesis["id"],
            "objective": "Request another user's object.",
            "tool_name": "http.request",
            "tool_input": {"url": "http://challenge:8080/records/2"},
        }
    )
    await repository.complete_experiment(run["id"], experiment["id"], {"status_code": 200})

    with pytest.raises(ValueError, match="experiment_completion_conflict"):
        await repository.complete_experiment(run["id"], experiment["id"], {"status_code": 403})


@pytest.mark.asyncio
async def test_verified_state_requires_boolean_and_two_clean_replays(
    repository: Repository,
) -> None:
    run = await create_run(repository)
    for status in ("preparing", "running", "verifying"):
        await repository.transition_run(run["id"], status, actor={"kind": "system", "id": "test"})
    proof = await add_authoritative_proof(repository, run["id"])
    base = {
        "run_id": run["id"],
        "verified": True,
        "exploit_digest": "a" * 64,
        "environment_digest": "b" * 64,
        "flag_sha256": "c" * 64,
        "masked_flag": "CTF{***masked***}",
        "verification_proof_ref": proof["id"],
        "replay_results": [{"passed": True, "started_from_clean_reset": True, "attempt": 1}],
        "provenance": {"artifact_id": "artifact-1"},
    }
    with pytest.raises(ValueError, match="must_be_boolean"):
        await repository.record_verification({**base, "verified": "false"})
    with pytest.raises(ValueError, match="verified_replay_requirements_not_met"):
        await repository.record_verification(base)

    verified = await repository.record_verification(
        {
            **base,
            "replay_results": [
                {"passed": True, "started_from_clean_reset": True, "attempt": 1},
                {"passed": True, "started_from_clean_reset": True, "attempt": 2},
            ],
        }
    )
    assert verified["verified"] is True
    solved_run = await repository.get_run(run["id"])
    assert solved_run is not None
    assert solved_run["status"] == "solved"


@pytest.mark.asyncio
async def test_event_trace_redacts_tokens_and_raw_flags(repository: Repository) -> None:
    run = await create_run(repository)
    event = await repository.append_event(
        run["id"],
        "worker.message.completed",
        {
            "authorization": "Bearer super-secret-token",
            "summary": "Observed CTF{raw_secret_flag}",
        },
        actor={"kind": "worker", "id": "worker-1"},
        idempotency_key="sensitive-event",
    )
    encoded = str(event)
    assert "super-secret-token" not in encoded
    assert "CTF{raw_secret_flag}" not in encoded
    assert "REDACTED" in encoded


@pytest.mark.asyncio
async def test_run_budget_is_bounded_by_manifest(repository: Repository) -> None:
    challenge = await repository.create_challenge(manifest_data(), name="audit-lab")
    with pytest.raises(ValueError, match="budget_exceeds_manifest"):
        await repository.create_run(
            challenge["id"],
            mode="assisted",
            provider="fake-deterministic",
            budget={**run_budget(), "max_http_requests": 10_000},
        )


@pytest.mark.asyncio
async def test_concurrent_challenge_import_is_content_idempotent(
    repository: Repository,
) -> None:
    challenges = await asyncio.gather(
        *(repository.create_challenge(manifest_data(), name="audit-lab") for _ in range(10))
    )
    assert len({challenge["id"] for challenge in challenges}) == 1


@pytest.mark.asyncio
async def test_archive_removal_reference_projection_covers_source_and_legacy_power(
    repository: Repository,
) -> None:
    exact_intake = f"intake_{'a' * 32}"
    power_intake = f"intake_{'b' * 32}"
    unused_intake = f"intake_{'c' * 32}"
    await repository.create_challenge(
        {"spec": {"source": {"intake_id": exact_intake, "slot_id": "source-slot-1"}}},
        name="source-bound",
    )
    await repository.create_challenge(
        manifest_data(),
        name=f"power-{power_intake.removeprefix('intake_')}",
    )

    assert await repository.archive_intake_has_durable_reference(exact_intake)
    assert await repository.archive_intake_has_durable_reference(power_intake)
    assert not await repository.archive_intake_has_durable_reference(unused_intake)
    with pytest.raises(ValueError, match="archive_intake_id_invalid"):
        await repository.archive_intake_has_durable_reference("../../archive")
