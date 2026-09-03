"""A Power run must end when nothing can advance it, and honour its time cap.

Both defects were observed on a real local run: every ``power_session_start``
job completed after its in-process batch loop ended, no further job was ever
queued, and the run stayed ``running`` for hours while the console reported a
live race.  Wall time was a declared budget dimension that nothing debited, so
the operator's minute cap could not end the run either.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from ctfmesh_db import Database, Repository
from ctfmesh_db.database import PowerPiSessionSpec, _stored_utc
from ctfmesh_db.models import RunRow

WORKER = "pi-runner-1"


def _manifest() -> dict[str, object]:
    return {
        "spec": {
            "mode": "assisted",
            "limits": {
                "wall_time_seconds": 3600,
                "max_tool_calls": 500,
                "max_http_requests": 1500,
                "max_cost_usd": 20.0,
            },
            "flag": {"replay_count": 1},
        }
    }


def _budget(wall_time_seconds: int = 300) -> dict[str, int | float]:
    return {
        "wall_time_seconds": wall_time_seconds,
        "max_tool_calls": 30,
        "max_http_requests": 20,
        "max_cost_usd": 1.0,
    }


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[Repository]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'lifecycle.db'}")
    await database.create_schema()
    try:
        yield Repository(database)
    finally:
        await database.close()


async def _power_run(repository: Repository, *, wall_time_seconds: int = 300) -> str:
    challenge = await repository.create_challenge(_manifest(), name="power-lab")
    run = await repository.create_run(
        challenge["id"],
        mode="assisted",
        provider="power-swarm",
        budget=_budget(wall_time_seconds),
    )
    sessions = tuple(
        PowerPiSessionSpec(
            id=f"pses_{index}_{'0' * 24}",
            label=label,
            role=role,
            provider="openai",
            model="gpt-test",
            temperature=0.2,
            workspace_id=f"ws_{index}{'0' * 31}",
        )
        for index, (label, role) in enumerate(
            (("auto", "autoprompter"), ("A", "racer"), ("B", "racer"), ("C", "racer"))
        )
    )
    for status in ("preparing", "running"):
        await repository.transition_run(
            run["id"],
            status,
            actor={"kind": "system", "id": "test"},
            reason="test_setup",
            idempotency_key=f"test-setup:{run['id']}:{status}",
        )
    await repository.create_power_pi_sessions(
        run["id"],
        archive_digest="a" * 64,
        brief="Work only on this authorized CTF challenge through CTFMesh custom tools.",
        sessions=sessions,
        target=None,
    )
    return str(run["id"])


async def _finish_every_session(repository: Repository, run_id: str) -> int:
    """Drain every start job the way the runner does when its batches end."""

    completed = 0
    while True:
        job = await repository.claim_agent_job(
            worker_id=WORKER, kinds=("power_session_start",), run_id=run_id
        )
        if job is None:
            return completed
        await repository.get_power_pi_job_work(
            job["id"], worker_id=WORKER, lease_version=int(job["lease_version"])
        )
        await repository.complete_power_pi_start(
            job["id"], worker_id=WORKER, lease_version=int(job["lease_version"])
        )
        completed += 1


async def _status(repository: Repository, run_id: str) -> str:
    run = await repository.get_run(run_id)
    assert run is not None
    return str(run["status"])


@pytest.mark.asyncio
async def test_wall_time_debit_accumulates_against_the_declared_cap(
    repository: Repository,
) -> None:
    """Nothing debited this dimension before, so the minute cap never applied."""

    run_id = await _power_run(repository, wall_time_seconds=3_600)

    first = await repository.debit_power_wall_time(run_id)
    assert first["accepted"] is True

    # Only the seconds not yet recorded may be charged again.
    async with repository.database.sessions() as session, session.begin():
        run = await session.get(RunRow, run_id, with_for_update=True)
        assert run is not None
        run.created_at = _stored_utc(run.created_at) - timedelta(seconds=120)

    second = await repository.debit_power_wall_time(run_id)
    assert second["accepted"] is True
    assert second["remaining"] is not None
    assert 3_600 - second["remaining"] == pytest.approx(120, abs=5)


@pytest.mark.asyncio
async def test_wall_time_cap_exhausts_a_still_running_race(
    repository: Repository,
) -> None:
    """An overrunning race must reach ``budget_exhausted`` on its own."""

    run_id = await _power_run(repository, wall_time_seconds=60)
    async with repository.database.sessions() as session, session.begin():
        run = await session.get(RunRow, run_id, with_for_update=True)
        assert run is not None
        run.created_at = _stored_utc(run.created_at) - timedelta(seconds=600)

    outcome = await repository.debit_power_wall_time(run_id)

    assert outcome["accepted"] is False
    assert await _status(repository, run_id) == "budget_exhausted"


@pytest.mark.asyncio
async def test_wall_time_debit_is_inert_for_a_run_that_is_not_running(
    repository: Repository,
) -> None:
    """Deny path: a cancelled run must never be charged or transitioned again."""

    run_id = await _power_run(repository, wall_time_seconds=60)
    await _finish_every_session(repository, run_id)
    await repository.transition_run(
        run_id,
        "cancelled",
        actor={"kind": "system", "id": "test"},
        reason="operator_stop",
        idempotency_key=f"test-cancel:{run_id}",
    )
    assert await _status(repository, run_id) == "cancelled"

    async with repository.database.sessions() as session, session.begin():
        run = await session.get(RunRow, run_id, with_for_update=True)
        assert run is not None
        run.created_at = _stored_utc(run.created_at) - timedelta(seconds=600)

    outcome = await repository.debit_power_wall_time(run_id)

    assert outcome["accepted"] is True
    assert outcome["ledger_id"] is None
    assert await _status(repository, run_id) == "cancelled"


@pytest.mark.asyncio
async def test_concurrent_reporters_never_conflict_on_one_wall_time_bucket(
    repository: Repository,
) -> None:
    """Four racers report usage at once; a wall-clock delta made them collide.

    Charging "seconds since the last debit" gave every concurrent caller a
    different amount behind the same per-second idempotency key, so the ledger
    raised ``idempotency_conflict``.  ``flushPowerUsage`` does not catch that,
    so the losing racer's session died with ``power_pi_session_start_failed``
    while the run looked healthy.
    """

    run_id = await _power_run(repository, wall_time_seconds=3_600)
    async with repository.database.sessions() as session, session.begin():
        run = await session.get(RunRow, run_id, with_for_update=True)
        assert run is not None
        run.created_at = _stored_utc(run.created_at) - timedelta(seconds=37)

    outcomes = await asyncio.gather(
        *(repository.debit_power_wall_time(run_id) for _ in range(4)),
        return_exceptions=True,
    )

    assert [type(outcome) for outcome in outcomes] == [dict] * 4
    assert all(outcome["accepted"] for outcome in outcomes)  # type: ignore[index]
    ledger = [
        entry
        for entry in await repository.list_budget_ledger(run_id)
        if entry["dimension"] == "wall_time_seconds"
    ]
    # Seven whole five-second buckets of the thirty-seven elapsed seconds, each
    # charged exactly once no matter how many racers reported them.
    assert len(ledger) == 7
    assert sum(entry["debit"] for entry in ledger) == pytest.approx(35.0)


@pytest.mark.asyncio
async def test_an_idle_run_announces_itself_without_leaving_running(
    repository: Repository,
) -> None:
    """A finished batch loop queues nothing, so the console showed a live race.

    The status must stay ``running``: it is what ``queue_power_steer`` and the
    candidate gate require, and steering an idle racer is how an operator
    redirects one that has run out of ideas.
    """

    run_id = await _power_run(repository)
    await _finish_every_session(repository, run_id)

    assert await _status(repository, run_id) == "running"
    events = await repository.list_events(run_id)
    idle = [event for event in events if event["type"] == "power.sessions.idle"]
    assert len(idle) == 1
    assert idle[0]["payload"]["idle_labels"] == ["A", "B", "C", "auto"]


@pytest.mark.asyncio
async def test_no_idle_signal_while_one_session_is_still_working(
    repository: Repository,
) -> None:
    """Deny path: a single outstanding start job must not look like an idle run."""

    run_id = await _power_run(repository)
    job = await repository.claim_agent_job(
        worker_id=WORKER, kinds=("power_session_start",), run_id=run_id
    )
    assert job is not None
    await repository.get_power_pi_job_work(
        job["id"], worker_id=WORKER, lease_version=int(job["lease_version"])
    )
    await repository.complete_power_pi_start(
        job["id"], worker_id=WORKER, lease_version=int(job["lease_version"])
    )

    events = await repository.list_events(run_id)
    assert [event for event in events if event["type"] == "power.sessions.idle"] == []


@pytest.mark.asyncio
async def test_an_idle_run_can_still_be_steered(repository: Repository) -> None:
    """The point of staying ``running``: a rabbit-holed racer is recoverable."""

    run_id = await _power_run(repository)
    await _finish_every_session(repository, run_id)
    sessions = await repository.list_power_pi_sessions(run_id)
    racer = next(item for item in sessions if item["label"] == "C")

    steer = await repository.queue_power_pi_steer(
        run_id,
        session_id=racer["id"],
        message="Stop probing the disclosure; pivot to the invalid-free path.",
        idempotency_key=f"steer-idle:{run_id}",
        requested_by="local-user",
    )

    assert steer is not None


@pytest.mark.asyncio
async def test_idle_is_announced_when_the_last_racer_fails_beside_idle_siblings(
    repository: Repository,
) -> None:
    """A failing racer can be the last thing that stops.

    Observed on a real run: two racers hit a provider fault while two sessions
    sat ``ready``. Nothing could advance the run, but the idle signal fired
    only from the success path, so the console still presented a live race and
    the operator had no cue to steer the surviving racer.
    """

    run_id = await _power_run(repository)
    claimed = []
    while True:
        job = await repository.claim_agent_job(
            worker_id=WORKER, kinds=("power_session_start",), run_id=run_id
        )
        if job is None:
            break
        await repository.get_power_pi_job_work(
            job["id"], worker_id=WORKER, lease_version=int(job["lease_version"])
        )
        claimed.append(job)

    for job in claimed[:-1]:
        await repository.complete_power_pi_start(
            job["id"], worker_id=WORKER, lease_version=int(job["lease_version"])
        )
    await repository.fail_power_pi_job(
        claimed[-1]["id"],
        worker_id=WORKER,
        lease_version=int(claimed[-1]["lease_version"]),
        reason="power_pi_provider_transport_failed",
    )

    assert await _status(repository, run_id) == "running"
    events = await repository.list_events(run_id)
    idle = [event for event in events if event["type"] == "power.sessions.idle"]
    assert len(idle) == 1
