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
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from ctfmesh_db import Database, Repository
from ctfmesh_db.database import PowerPiSessionSpec, _stored_utc
from ctfmesh_db.models import AgentJobRow, RunRow
from pydantic import SecretStr

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


async def _power_run(
    repository: Repository,
    *,
    wall_time_seconds: int = 300,
    resume_sources: dict[str, str] | None = None,
) -> str:
    challenge = await repository.create_challenge(_manifest(), name="power-lab")
    run = await repository.create_run(
        challenge["id"],
        mode="assisted",
        provider="power-swarm",
        budget=_budget(wall_time_seconds),
    )
    sessions = tuple(
        PowerPiSessionSpec(
            id=f"pses_{index}_{run['id'].removeprefix('run_')}",
            label=label,
            role=role,
            provider="openai",
            model="gpt-test",
            temperature=0.2,
            workspace_id=f"ws_{index}{run['id'].removeprefix('run_')[:31]}",
            resumed_from_store_key=(None if resume_sources is None else resume_sources.get(label)),
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
async def test_terminal_power_run_never_reclaims_a_start_job(
    repository: Repository,
) -> None:
    """A solved run must fence even an expired or queued Power start job.

    Power job kinds are deliberately separate from the v0.1 Pi kinds.  The
    generic claim branch must exclude both sets; otherwise it can reclaim a
    stale Power start after verification and produce a permanent
    ``pi_job_lease_lost`` loop in the live runner.
    """

    run_id = await _power_run(repository)
    completed = await repository.complete_power_flag(
        run_id=run_id,
        flag_sha256="a" * 64,
        masked_flag="CTF{verified}",
        observation_artifact_id=f"sha256:{'a' * 64}",
        observation_sha256="a" * 64,
    )

    assert completed is True
    assert await _status(repository, run_id) == "solved"
    assert (
        await repository.claim_agent_job(
            worker_id=WORKER,
            kinds=("power_session_start",),
            run_id=run_id,
        )
        is None
    )


@pytest.mark.asyncio
async def test_transient_provider_retry_can_reclaim_the_same_live_power_start_job(
    repository: Repository,
) -> None:
    """A runner retry burst leaves its job leased instead of failing its racer.

    The next claim must retain the same Power session and increment only the
    versioned lease.  This is the durable half of Pi runner's transient
    provider recovery: it lets a later prompt reuse the existing JSONL
    transcript rather than creating a second racer or requiring an operator
    restart.
    """

    run_id = await _power_run(repository)
    first = await repository.claim_agent_job(
        worker_id=WORKER,
        lease_seconds=30,
        kinds=("power_session_start",),
        run_id=run_id,
    )
    assert first is not None
    first_work = await repository.get_power_pi_job_work(
        first["id"], worker_id=WORKER, lease_version=int(first["lease_version"])
    )

    # Model a runner that exhausted its local transient retry burst: it leaves
    # the job leased.  Do not call failure/completion, then make its short
    # lease eligible for the normal compare-and-swap claim path.
    async with repository.database.sessions() as session, session.begin():
        row = await session.get(AgentJobRow, first["id"], with_for_update=True)
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    reclaimed = await repository.claim_agent_job(
        worker_id=WORKER,
        lease_seconds=30,
        kinds=("power_session_start",),
        run_id=run_id,
    )
    assert reclaimed is not None
    assert reclaimed["id"] == first["id"]
    assert reclaimed["lease_version"] == first["lease_version"] + 1
    assert reclaimed["attempts"] == first["attempts"] + 1
    resumed_work = await repository.get_power_pi_job_work(
        reclaimed["id"], worker_id=WORKER, lease_version=int(reclaimed["lease_version"])
    )
    assert resumed_work["session"]["id"] == first_work["session"]["id"]
    assert resumed_work["session"]["state"] == "running"


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


@pytest.mark.asyncio
async def test_repeating_an_exhausted_bucket_still_ends_the_run(
    repository: Repository,
) -> None:
    """Observed live: a run sat in ``running`` with its whole cap spent.

    ``debit_budget`` moves a run to its terminal budget state only while it is
    actually rejecting a debit. Repeating a bucket whose key already recorded
    an exhausted outcome replays that result and returns early, so the racers
    kept dying on the rejection while the run still presented as live.
    """

    run_id = await _power_run(repository, wall_time_seconds=60)
    async with repository.database.sessions() as session, session.begin():
        run = await session.get(RunRow, run_id, with_for_update=True)
        assert run is not None
        run.created_at = _stored_utc(run.created_at) - timedelta(seconds=600)

    first = await repository.debit_power_wall_time(run_id)
    assert first["accepted"] is False
    assert await _status(repository, run_id) == "budget_exhausted"

    # Put the run back so the replay path is the only thing under test.
    async with repository.database.sessions() as session, session.begin():
        run = await session.get(RunRow, run_id, with_for_update=True)
        assert run is not None
        run.status = "running"

    replay = await repository.debit_power_wall_time(run_id)

    assert replay["accepted"] is False
    assert await _status(repository, run_id) == "budget_exhausted"


@pytest.mark.asyncio
async def test_a_continued_session_records_the_transcript_it_resumes_from(
    repository: Repository,
) -> None:
    """A finished run kept its transcripts, but nothing could adopt them.

    The store key stays unique per session, so two live sessions can never
    write one transcript. The successor records its predecessor's key instead
    and the runner seeds the new file from it, which is what lets a racer
    reopen with what it already established rather than repeating recon.
    """

    run_id = await _power_run(repository)
    sessions = await repository.list_power_pi_sessions(run_id)
    source = {str(item["label"]): str(item["session_store_key"]) for item in sessions}

    successor = await _power_run(repository, resume_sources=source)
    resumed = await repository.list_power_pi_sessions(successor)

    assert {str(item["label"]) for item in resumed} == {"auto", "A", "B", "C"}
    for item in resumed:
        assert item["resumed_from_store_key"] == source[str(item["label"])]
        # A successor never shares its predecessor's key.
        assert item["session_store_key"] != item["resumed_from_store_key"]


@pytest.mark.asyncio
async def test_a_fresh_run_records_no_resume_source(repository: Repository) -> None:
    """Deny path: an ordinary launch must not look like a continuation."""

    run_id = await _power_run(repository)

    for item in await repository.list_power_pi_sessions(run_id):
        assert item["resumed_from_store_key"] is None


@pytest.mark.asyncio
async def test_a_resume_source_must_look_like_a_store_key(repository: Repository) -> None:
    """Deny path: a caller cannot name an arbitrary path to open."""

    with pytest.raises(ValueError, match="power_pi_session_spec_invalid"):
        await _power_run(
            repository,
            resume_sources={
                "auto": "../../etc/passwd",
                "A": "../../etc/passwd",
                "B": "../../etc/passwd",
                "C": "../../etc/passwd",
            },
        )


async def test_settled_run_workspaces_are_listed_for_reclaim(repository: Repository) -> None:
    """A run that ends on its own must not keep its containers forever.

    Cleanup was scheduled only from an operator Stop and from a flag-router
    acceptance, both of which reach the API process while it is alive. A run
    that reached ``budget_exhausted`` or ``failed`` inside the database layer
    scheduled nothing, so twenty-four containers outlived thirteen finished
    runs on a real host. Terminal status is durable, so the leak is
    recoverable from the database alone.
    """

    run_id = await _power_run(repository)

    # A live run owns its workspaces; the sweep must never touch them.
    assert await repository.list_unreleased_power_workspaces() == []

    await repository.transition_run(
        run_id,
        "budget_exhausted",
        actor={"kind": "system", "id": "test"},
        reason="budget_exhausted:wall_time_seconds",
        idempotency_key=f"test-exhaust:{run_id}",
    )

    pending = await repository.list_unreleased_power_workspaces()
    assert {entry["workspace_id"] for entry in pending} == {
        session["workspace_id"] for session in await repository.list_power_pi_sessions(run_id)
    }

    # Marking a workspace released is what stops the sweep retrying it: the
    # column exists precisely because ``workspace_id`` cannot be cleared.
    for entry in pending:
        await repository.mark_power_workspace_released(entry["session_id"])
    assert await repository.list_unreleased_power_workspaces() == []

    # A second mark is a no-op rather than an error, because a sweep that
    # crashes mid-pass repeats the entries it already handled.
    await repository.mark_power_workspace_released(pending[0]["session_id"])
    assert await repository.list_unreleased_power_workspaces() == []


async def test_sweep_destroys_settled_workspaces_once(
    repository: Repository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sweep must free every settled workspace and then leave it alone."""

    from ctfmesh_api import power_runs
    from ctfmesh_solver_runtime.sandboxd import SandboxdClientError

    destroyed: list[str] = []

    class _FakeSandboxd:
        def __init__(self, *, base_url: str, token: str) -> None:
            self._base_url = base_url
            self._token = token

        async def destroy(self, workspace_id: str) -> None:
            destroyed.append(workspace_id)
            # sandboxd forgets a workspace whose container is already gone.
            # That is the normal case after a host restart, and it must still
            # count as reclaimed rather than being retried forever.
            if workspace_id.startswith("ws_0"):
                raise SandboxdClientError("workspace_not_found")

    monkeypatch.setattr(power_runs, "HttpSandboxdClient", _FakeSandboxd)
    controller = power_runs.PowerRunController(
        repository=repository,
        sandboxd_url="http://sandboxd:8091",
        sandboxd_token=SecretStr("s" * 32),
        credential_leases=None,
        sibling_grace_seconds=0,
    )

    run_id = await _power_run(repository)
    assert await controller.sweep_released_workspaces() == 0
    assert destroyed == []

    await repository.transition_run(
        run_id,
        "failed",
        actor={"kind": "system", "id": "test"},
        reason="all_power_racers_failed",
        idempotency_key=f"test-fail:{run_id}",
    )

    assert await controller.sweep_released_workspaces() == 4
    assert len(destroyed) == 4

    # The second pass costs sandboxd nothing: every workspace is marked.
    assert await controller.sweep_released_workspaces() == 0
    assert len(destroyed) == 4
