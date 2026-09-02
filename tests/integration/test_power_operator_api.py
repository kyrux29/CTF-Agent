"""Power API and M-PI-2 durable Pi-controller integration coverage."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_api import create_app
from ctfmesh_api.app import _power_fs_read_fingerprint, _PowerExecArguments
from ctfmesh_api.power_runs import PowerRunController, PowerRunLaunch, _power_brief
from ctfmesh_api.settings import Settings
from ctfmesh_db import Repository
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_flag_router import PowerFlagRouter
from ctfmesh_solver_runtime.runner import SandboxObservation
from ctfmesh_tools import LocalArtifactStore
from fastapi import FastAPI
from pydantic import SecretStr


def _archive() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("challenge/README.txt", "authorized Power receipt")
    return buffer.getvalue()


@dataclass
class _RecordingPowerController:
    """A public-route seam proving an operator request only creates work."""

    launches: list[tuple[str, PowerRunLaunch]] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)

    async def start(self, *, run_id: str, launch: PowerRunLaunch) -> None:
        self.launches.append((run_id, launch))

    async def cancel(self, run_id: str) -> bool:
        self.cancelled.append(run_id)
        return True

    async def aclose(self) -> None:
        return None


@pytest.fixture
async def power_api(
    tmp_path: Path,
) -> AsyncIterator[tuple[FastAPI, httpx.AsyncClient, _RecordingPowerController]]:
    app = create_app(
        Settings(
            database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'power-operator.db'}"),
            artifact_root=tmp_path / "artifacts",
            power_enabled=True,
            power_sandboxd_url="http://sandboxd:8091",
            power_sandboxd_token=SecretStr("s" * 32),
            power_flag_router_url="http://flag-router:8092",
            power_flag_router_token=SecretStr("r" * 32),
            internal_flag_router_token=SecretStr("i" * 32),
            internal_runner_token=SecretStr("p" * 32),
        )
    )
    async with LifespanManager(app):
        controller = _RecordingPowerController()
        app.state.power_runs = controller
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield app, client, controller


def _body(*, target: dict[str, object] | None = None) -> dict[str, object]:
    return {
        **({"target": target, "authorized_target": True} if target is not None else {}),
        "open_egress": False,
        "racer_count": 3,
        "contest_offline": True,
        "racers": [
            {
                "label": label,
                "provider": "openai-responses",
                "model": "gpt-5.6-sol",
                "temperature": temp,
            }
            for label, temp in (("A", 0.2), ("B", 0.5), ("C", 0.8))
        ],
        "provider_keys": {"openai-responses": "operator-key-must-not-be-durable"},
        "budget": {"wall_time_seconds": 300, "max_cost_usd": 3.0, "max_turn_cost_usd": 0.1},
    }


async def _launch(
    client: httpx.AsyncClient,
    *,
    key: str,
    target: dict[str, object] | None = None,
) -> tuple[str, dict[str, object]]:
    uploaded = await client.post(
        "/v1/archive-intakes",
        content=_archive(),
        headers={"Content-Type": "application/zip", "X-Archive-Name": "power.zip"},
    )
    assert uploaded.status_code == 201, uploaded.text
    response = await client.post(
        f"/v1/archive-intakes/{uploaded.json()['intake_id']}/power-runs",
        headers={"Idempotency-Key": key},
        json=_body(target=target),
    )
    assert response.status_code == 202, response.text
    return response.json()["run_id"], response.json()


@pytest.mark.asyncio
async def test_power_launch_uses_receipt_scope_and_keeps_key_out_of_ledger(
    power_api: tuple[FastAPI, httpx.AsyncClient, _RecordingPowerController],
) -> None:
    app, client, controller = power_api
    run_id, response = await _launch(
        client, key="power-operator-test-1", target={"host": "154.57.164.82", "port": 31337}
    )
    assert response["scope"] == {"target": "tcp"}
    assert len(controller.launches) == 1
    _, launch = controller.launches[0]
    assert launch.target == ("154.57.164.82", 31337)
    assert launch.contest_offline is True
    assert launch.brief_context.category == "unknown"
    assert launch.brief_context.files == ("challenge/README.txt",)
    brief = _power_brief(launch.target, launch.brief_context)
    assert len(brief) <= 2_000
    assert "Category: unknown." in brief
    assert "Files: challenge/README.txt." in brief
    run = await app.state.repository.get_run(run_id)
    events = await app.state.repository.list_events(run_id)
    assert run is not None and run["status"] == "running"
    assert "operator-key-must-not-be-durable" not in str(events) + str(run)


@pytest.mark.asyncio
async def test_power_launch_rejects_open_egress_and_private_target_before_controller(
    power_api: tuple[FastAPI, httpx.AsyncClient, _RecordingPowerController],
) -> None:
    _, client, controller = power_api
    uploaded = await client.post(
        "/v1/archive-intakes", content=_archive(), headers={"X-Archive-Name": "power.zip"}
    )
    intake_id = uploaded.json()["intake_id"]
    egress = await client.post(
        f"/v1/archive-intakes/{intake_id}/power-runs",
        headers={"Idempotency-Key": "power-operator-test-2"},
        json={**_body(), "open_egress": True},
    )
    assert egress.status_code == 422
    assert egress.json()["detail"]["code"] == "power_open_egress_unavailable"
    private = await client.post(
        f"/v1/archive-intakes/{intake_id}/power-runs",
        headers={"Idempotency-Key": "power-operator-test-3"},
        json=_body(target={"host": "127.0.0.1", "port": 31337}),
    )
    assert private.status_code == 422
    assert not controller.launches


@pytest.mark.asyncio
async def test_power_cancel_signals_controller_then_records_durable_cancellation(
    power_api: tuple[FastAPI, httpx.AsyncClient, _RecordingPowerController],
) -> None:
    app, client, controller = power_api
    run_id, _ = await _launch(client, key="power-operator-test-4")
    cancelled = await client.post(f"/v1/runs/{run_id}/cancel")
    assert cancelled.status_code == 200, cancelled.text
    assert controller.cancelled == [run_id]
    run = await app.state.repository.get_run(run_id)
    assert run is not None and run["status"] == "cancelled"


class _FixtureSandboxd:
    """No-key fixture: it provisions opaque workspace names only."""

    created: list[str] = []
    destroyed: list[str] = []
    received_workspaces: list[str] = []

    def __init__(self, **_kwargs: object) -> None:
        return None

    async def create(self, *, run_id: str, archive_digest: str) -> str:
        assert run_id and len(archive_digest) == 64
        workspace_id = f"ws_{len(self.created) + 1:032x}"
        self.created.append(workspace_id)
        return workspace_id

    async def destroy(self, workspace_id: str) -> None:
        self.destroyed.append(workspace_id)

    async def exec(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> SandboxObservation:
        assert command == ("ls", "/challenge")
        assert timeout_seconds == 10
        assert working_directory == "/challenge"
        self.received_workspaces.append(workspace_id)
        return SandboxObservation(
            stdout="README.txt\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            output_truncated=False,
            stdout_artifact_id=f"sha256:{'a' * 64}",
            stdout_sha256="a" * 64,
            stdout_artifact_size_bytes=11,
        )


@dataclass(frozen=True)
class _RepositoryFlagCompleter:
    """Independent-router seam used only to exercise a real artifact re-read."""

    repository: Repository

    async def complete_power_flag(
        self,
        *,
        run_id: str,
        flag: SecretStr,
        flag_sha256: str,
        masked_flag: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        return await self.repository.complete_power_flag(
            run_id=run_id,
            flag_sha256=flag_sha256,
            masked_flag=masked_flag,
            observation_artifact_id=observation_artifact_id,
            observation_sha256=observation_sha256,
        )


@pytest.mark.asyncio
async def test_power_pi_fixture_flag_solves_then_aborts_two_racer_siblings(
    power_api: tuple[FastAPI, httpx.AsyncClient, _RecordingPowerController],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One independently observed flag artifact stops the two losing racers."""

    app, client, recording = power_api
    _FixtureSandboxd.created = []
    _FixtureSandboxd.destroyed = []
    _FixtureSandboxd.received_workspaces = []
    monkeypatch.setattr("ctfmesh_api.power_runs.HttpSandboxdClient", _FixtureSandboxd)
    monkeypatch.setattr("ctfmesh_api.app.HttpSandboxdClient", _FixtureSandboxd)
    run_id, _ = await _launch(client, key="power-pi-m2-fixture")
    _, launch = recording.launches[-1]
    controller = PowerRunController(
        repository=app.state.repository,
        sandboxd_url="http://sandboxd:8091",
        sandboxd_token=SecretStr("s" * 32),
        credential_leases=None,
        sibling_grace_seconds=0,
    )
    await controller._provision(run_id=run_id, launch=launch)
    sessions = await app.state.repository.list_power_pi_sessions(run_id)
    assert {(item["label"], item["role"]) for item in sessions} == {
        ("auto", "autoprompter"),
        ("A", "racer"),
        ("B", "racer"),
        ("C", "racer"),
    }
    assert len(await app.state.repository.list_agent_jobs(run_id)) == 4

    # M-PI-4: the adapter fingerprints the normalized fs_read path, ignoring
    # a different byte cap, and the repository marks the second receipt as a
    # duplicate without ever persisting that path.
    first_path = _power_fs_read_fingerprint(
        "ctf_fs_read",
        _PowerExecArguments(
            command=["head", "-c", "512", "/challenge/README.txt"],
            timeout_seconds=30,
            working_directory="/work",
        ),
    )
    second_path = _power_fs_read_fingerprint(
        "ctf_fs_read",
        _PowerExecArguments(
            command=["head", "-c", "16384", "/challenge/README.txt"],
            timeout_seconds=30,
            working_directory="/work",
        ),
    )
    assert first_path is not None and first_path == second_path
    assert not await app.state.repository.record_power_pi_action(
        run_id,
        label="A",
        runner_id="pi-fixture",
        action="exec",
        observation_artifact_id=f"sha256:{'a' * 64}",
        observation_received=True,
        action_summary="Typed sandbox action completed.",
        recon_fingerprint=first_path,
    )
    assert await app.state.repository.record_power_pi_action(
        run_id,
        label="B",
        runner_id="pi-fixture",
        action="exec",
        observation_artifact_id=f"sha256:{'a' * 64}",
        observation_received=True,
        action_summary="Typed sandbox action completed.",
        recon_fingerprint=second_path,
    )
    duplicate_events = [
        event
        for event in await app.state.repository.list_events(run_id)
        if event["type"] == "power.recon.duplicate"
    ]
    assert len(duplicate_events) == 1
    assert "/challenge/README.txt" not in json.dumps(duplicate_events)

    # Finish one no-key startup fixture at its safe boundary and prove that
    # Power steering is a separate durable job, not an in-process model call.
    startup = await app.state.repository.claim_agent_job(
        worker_id="pi-fixture",
        lease_seconds=30,
        run_id=run_id,
        kinds=("power_session_start",),
    )
    assert startup is not None
    startup_work = await app.state.repository.get_power_pi_job_work(
        startup["id"], worker_id="pi-fixture", lease_version=startup["lease_version"]
    )
    renewed = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-start-lease-renewal",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json={"runner_id": "pi-fixture", "lease_version": startup["lease_version"]},
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["lease_version"] == startup["lease_version"]
    activity = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-activity",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json={
            "runner_id": "pi-fixture",
            "lease_version": startup["lease_version"],
            "session_id": startup_work["session"]["id"],
            "kind": "response",
            "content": "Visible plan CTF{must_not_persist} Bearer abcdefghijkl",
        },
    )
    assert activity.status_code == 200, activity.text
    activity_event = next(
        item
        for item in reversed(await app.state.repository.list_events(run_id))
        if item["type"] == "power.pi.activity"
    )
    assert activity_event["payload"]["content"] == "Visible plan [REDACTED_FLAG] Bearer [REDACTED]"

    transcript_payload = {
        "runner_id": "pi-fixture",
        "lease_version": startup["lease_version"],
        "session_id": startup_work["session"]["id"],
        "tool": "ctf_fs_read",
        "command": "head -c 99 /challenge/flag.txt token=never-persist",
        "output": "CTF{must_not_persist} Bearer abcdefghijkl",
        "exit_code": 0,
        "timed_out": False,
        "output_truncated": False,
        "idempotency_key": "tool-receipt-1",
    }
    transcript = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-tool-transcript",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json=transcript_payload,
    )
    assert transcript.status_code == 200, transcript.text
    transcript_retry = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-tool-transcript",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json=transcript_payload,
    )
    assert transcript_retry.status_code == 200, transcript_retry.text
    assert (
        len(
            [
                item
                for item in await app.state.repository.list_events(run_id)
                if item["type"] == "power.pi.tool_transcript"
            ]
        )
        == 1
    )
    transcript_event = next(
        item
        for item in reversed(await app.state.repository.list_events(run_id))
        if item["type"] == "power.pi.tool_transcript"
    )
    assert transcript_event["payload"]["tool"] == "ctf_fs_read"
    assert (
        transcript_event["payload"]["command"] == "head -c 99 /challenge/flag.txt [REDACTED_SECRET]"
    )
    assert transcript_event["payload"]["output"] == "[REDACTED_FLAG] Bearer [REDACTED]"
    assert "must_not_persist" not in json.dumps(transcript_event)
    console = await client.get(f"/v1/runs/{run_id}/console")
    assert console.status_code == 200, console.text
    projected_transcript = next(
        item
        for item in reversed(console.json()["events"])
        if item["title"] == "Power pi tool transcript"
    )
    projected_details = {
        item["label"]: item["content"]["value"] for item in projected_transcript["details"]
    }
    assert projected_details["Command"] == "head -c 99 /challenge/flag.txt [REDACTED_SECRET]"
    assert projected_details["Output"] == "[REDACTED_FLAG] Bearer [REDACTED]"

    # An operator can now steer a racer while its startup turn owns the tool
    # lease. The durable completion must preserve that running authority.
    streaming_steer = await client.post(
        f"/v1/runs/{run_id}/power-sessions/{startup_work['session']['id']}/steer",
        headers={"Idempotency-Key": "power-pi-m4-streaming-steer"},
        json={"message": "Switch to an unexplored evidence path."},
    )
    assert streaming_steer.status_code == 202, streaming_steer.text
    steer_job = await app.state.repository.claim_agent_job(
        worker_id="pi-fixture", lease_seconds=30, run_id=run_id, kinds=("power_steer",)
    )
    assert steer_job is not None
    steer_work = await app.state.repository.get_power_pi_job_work(
        steer_job["id"], worker_id="pi-fixture", lease_version=steer_job["lease_version"]
    )
    assert steer_work["session"]["state"] == "running"
    await app.state.repository.complete_power_pi_steer(
        steer_job["id"],
        worker_id="pi-fixture",
        lease_version=steer_job["lease_version"],
        delivered_while_streaming=True,
    )
    wrong_session = next(item for item in sessions if item["id"] != startup_work["session"]["id"])
    denied = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-tool-requests",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json={
            "runner_id": "pi-fixture",
            "lease_version": startup["lease_version"],
            "session_id": wrong_session["id"],
            "action": "exec",
            "arguments": {
                "command": ["ls", "/challenge"],
                "timeout_seconds": 10,
                "working_directory": "/challenge",
            },
        },
    )
    assert denied.status_code == 409
    # A session owned by a different live lease is fenced before the request
    # can reach sandboxd.  It is intentionally indistinguishable from any
    # other unavailable Power authority at this private boundary.
    assert denied.json()["detail"]["code"] == "power_pi_tool_not_authorized"
    assert _FixtureSandboxd.received_workspaces == []
    tool_result = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-tool-requests",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json={
            "runner_id": "pi-fixture",
            "lease_version": startup["lease_version"],
            "session_id": startup_work["session"]["id"],
            "action": "exec",
            "arguments": {
                "command": ["ls", "/challenge"],
                "timeout_seconds": 10,
                "working_directory": "/challenge",
            },
        },
    )
    assert tool_result.status_code == 200, tool_result.text
    assert tool_result.json()["artifact"]["id"] == f"sha256:{'a' * 64}"
    assert _FixtureSandboxd.received_workspaces == [startup_work["session"]["workspace_id"]]
    # The operator sees that a racer completed a typed action, while the
    # append-only event remains free of its command, source path, and output.
    events = await app.state.repository.list_events(run_id)
    action_event = next(
        item for item in reversed(events) if item["type"] == "power.command.observed"
    )
    assert action_event["payload"] == {
        "summary": "Racer auto: exec (running).",
        "label": "auto",
        "state": "running",
        "action_type": "exec",
        "action_summary": "Typed sandbox action completed.",
        "observation_received": True,
        "observation_artifact_id": f"sha256:{'a' * 64}",
    }
    rendered_event = json.dumps(action_event["payload"])
    assert "ls" not in rendered_event
    assert "/challenge" not in rendered_event
    usage = await client.post(
        f"/internal/agent-jobs/{startup['id']}/power-usage",
        headers={"X-CTFMesh-Runner-Token": "p" * 32},
        json={
            "runner_id": "pi-fixture",
            "lease_version": startup["lease_version"],
            "session_id": startup_work["session"]["id"],
            "input_tokens": 120,
            "output_tokens": 30,
            "cache_read_tokens": 10,
            "cache_write_tokens": 0,
            "cost_usd": 0.03125,
            "compacted": 1,
        },
    )
    assert usage.status_code == 200, usage.text
    assert usage.json() == {"accepted": True}
    usage_event = next(
        item
        for item in reversed(await app.state.repository.list_events(run_id))
        if item["type"] == "power.pi.usage"
    )
    assert usage_event["payload"] == {
        "summary": "Racer auto: Pi usage settled.",
        "label": "auto",
        "input_tokens": 120,
        "output_tokens": 30,
        "cache_read_tokens": 10,
        "cache_write_tokens": 0,
        "cost_usd": 0.03125,
        "compacted": 1,
        "budget_accepted": True,
    }
    usage_ledger = await app.state.repository.list_budget_ledger(run_id)
    assert usage_ledger[-1]["dimension"] == "max_cost_usd"
    assert usage_ledger[-1]["debit"] == 0.03125
    assert "operator-key-must-not-be-durable" not in json.dumps(usage_event)
    await app.state.repository.complete_power_pi_start(
        startup["id"], worker_id="pi-fixture", lease_version=startup["lease_version"]
    )
    steering = await client.post(
        f"/v1/runs/{run_id}/power-sessions/{startup_work['session']['id']}/steer",
        headers={"Idempotency-Key": "power-pi-m2-steer"},
        json={"message": "Review one additional observed artifact before any candidate."},
    )
    assert steering.status_code == 202, steering.text
    assert steering.json()["state"] == "queued"

    # A real router instance re-reads this immutable sandboxd-style flag file;
    # a model claim or the candidate string by itself cannot solve the run.
    flag = "CTF{power_pi_fixture}"
    artifact = await LocalArtifactStore(app.state.artifact_root).put_bytes(
        f"result: {flag}\n".encode(),
        run_id=run_id,
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )
    assert await PowerFlagRouter(
        artifact_root=app.state.artifact_root,
        completer=_RepositoryFlagCompleter(app.state.repository),
        patterns=(r"CTF\{[A-Za-z0-9_:-]+\}",),
    ).submit(
        run_id=run_id,
        candidate=flag,
        observation_artifact_id=artifact.id,
        observation_sha256=artifact.sha256,
    )
    winner = next(item for item in sessions if item["label"] == "A")
    await controller.accepted_flag(run_id=run_id, winner_session_id=winner["id"])

    # AutoPrompter and the two racer siblings are fenced through Power abort
    # jobs. The check below focuses on the acceptance criterion: B and C are
    # durably aborted while A remains the winning session.
    for _ in range(3):
        job = await app.state.repository.claim_agent_job(
            worker_id="pi-fixture", lease_seconds=30, run_id=run_id, kinds=("power_abort",)
        )
        assert job is not None
        work = await app.state.repository.get_power_pi_job_work(
            job["id"], worker_id="pi-fixture", lease_version=job["lease_version"]
        )
        await app.state.repository.complete_power_pi_abort(
            work["job"]["id"], worker_id="pi-fixture", lease_version=job["lease_version"]
        )
    refreshed = await app.state.repository.list_power_pi_sessions(run_id)
    racers = {item["label"]: item["state"] for item in refreshed if item["role"] == "racer"}
    assert racers == {"A": "starting", "B": "aborted", "C": "aborted"}
    run = await app.state.repository.get_run(run_id)
    assert run is not None and run["status"] == "solved"
    assert set(_FixtureSandboxd.destroyed) == set(_FixtureSandboxd.created)
    await controller.aclose()
