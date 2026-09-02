"""Power flag-router completion keeps its verified raw value memory-only."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_api import create_app
from ctfmesh_api.settings import Settings
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_tools import LocalArtifactStore
from fastapi import FastAPI
from pydantic import SecretStr


@pytest.fixture
async def flag_api(tmp_path: Path) -> AsyncIterator[tuple[FastAPI, httpx.AsyncClient]]:
    """Run the private route over ASGI with a separate service capability."""

    router_token = "power-router-fixture-token-123456"
    app = create_app(
        Settings(
            database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'power-flag.db'}"),
            artifact_root=tmp_path / "artifacts",
            internal_flag_router_token=SecretStr(router_token),
            power_sandboxd_url="http://sandboxd:8091",
            power_sandboxd_token=SecretStr("s" * 32),
            power_flag_router_url="http://flag-router:8092",
            power_flag_router_token=SecretStr("r" * 32),
        )
    )
    # Keep the integration fixture independent of cold-volume SQLite DDL
    # timing; this does not alter any application timeout or behavior.
    async with LifespanManager(app, startup_timeout=15):
        challenge = await app.state.repository.create_challenge(
            {
                "apiVersion": "ctfmesh.io/v1alpha1",
                "kind": "Challenge",
                "metadata": {
                    "name": "power-flag-fixture",
                    "category": "misc",
                    "tags": ["power-profile"],
                },
                "spec": {
                    "mode": "assisted",
                    "target": {"type": "artifact_bundle"},
                    "artifacts": [{"path": "archive.bin", "role": "archive"}],
                    "limits": {
                        "wall_time_seconds": 3600,
                        "max_worker_turns": 10,
                        "max_tool_calls": 100,
                        "max_http_requests": 100,
                        "max_parallel_requests": 1,
                        "max_cost_usd": 10.0,
                        "max_artifact_bytes": 64 * 1024,
                    },
                    "flag": {
                        "patterns": [
                            r"(?i)\bDH-[A-Za-z0-9_:\-]{1,512}\b",
                            r"(?i)\b(?:FLAG|HTB|CTF)\{[A-Za-z0-9_:\-]{1,512}\}",
                        ],
                        "source_policy": {
                            "allow_from_target_response": True,
                            "allow_from_target_filesystem": True,
                            "deny_from_input_artifacts": True,
                        },
                        "replay_count": 1,
                    },
                    "providers": {"preferred": "fixture", "fallbacks": []},
                    "memory": {
                        "namespace": "power-flag-fixture",
                        "cutoff": "2026-09-02T00:00:00Z",
                        "internet_search": False,
                    },
                    "tool_profile": ["files.list"],
                },
            },
            name="power-flag-fixture",
        )
        run = await app.state.repository.create_run(
            challenge["id"],
            mode="assisted",
            provider="power-swarm",
            budget={
                "wall_time_seconds": 60,
                "max_tool_calls": 10,
                "max_http_requests": 10,
                "max_cost_usd": 1.0,
            },
        )
        for state in ("preparing", "running"):
            await app.state.repository.transition_run(
                run["id"], state, actor={"kind": "system", "id": "power-test"}
            )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield app, client


@pytest.mark.asyncio
async def test_only_flag_router_capability_can_complete_with_memory_only_reveal(
    flag_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    """An unauthenticated worker cannot write a Power solve or leak its token."""

    app, client = flag_api
    run = (await app.state.repository.list_runs())[0]
    token = "power-router-fixture-token-123456"
    body = {
        "run_id": run["id"],
        "flag": "CTF{verified_memory_only}",
        "flag_sha256": "a" * 64,
        "masked_flag": "CTF{…e}",
        "observation_artifact_id": f"sha256:{'b' * 64}",
        "observation_sha256": "b" * 64,
    }
    denied = await client.post("/internal/power/flag-completions", json=body)
    assert denied.status_code == 401
    assert token not in denied.text

    accepted = await client.post(
        "/internal/power/flag-completions",
        json=body,
        headers={"X-CTFMesh-Flag-Router-Token": token},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"accepted": True}
    solved = await app.state.repository.get_run(run["id"])
    assert solved is not None
    assert solved["status"] == "solved"
    assert "raw_flag" not in solved["result"]
    assert body["flag"] not in str(solved)

    revealed = await client.post(
        f"/v1/runs/{run['id']}/flag-reveal",
        json={"confirm": True},
    )
    assert revealed.status_code == 200, revealed.text
    assert revealed.json() == {"flag": body["flag"], "one_time": True}


@pytest.mark.asyncio
async def test_runtime_candidate_reveal_returns_every_observed_shape_without_persisting_values(
    flag_api: tuple[FastAPI, httpx.AsyncClient],
) -> None:
    """The browser can explicitly review every Power candidate, including decoys."""

    app, client = flag_api
    run = (await app.state.repository.list_runs())[0]
    candidates = [f"DH{{runtime_candidate_{index}}}" for index in range(6)]
    candidates.append("DH-runtime_candidate_without_braces")
    stderr_candidate = "DH-stderr_candidate_without_braces"
    artifact = await LocalArtifactStore(app.state.artifact_root).put_bytes(
        "\n".join(candidates).encode("ascii"),
        run_id=run["id"],
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )
    stderr_artifact = await LocalArtifactStore(app.state.artifact_root).put_bytes(
        stderr_candidate.encode("ascii"),
        run_id=run["id"],
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )
    for label in ("A", "B"):
        artifact_ids = [artifact.id]
        if label == "B":
            artifact_ids.append(stderr_artifact.id)
        await app.state.repository.append_event(
            run["id"],
            "power.command.observed",
            {
                "summary": f"Racer {label}: exec (running).",
                "label": label,
                "state": "running",
                "action_type": "exec",
                "action_summary": "Typed sandbox action completed.",
                "observation_received": True,
                "observation_artifact_id": artifact.id,
                "observation_artifact_ids": artifact_ids,
            },
            actor={"kind": "service", "id": "power-test"},
            idempotency_key=f"runtime-candidate-observation-{label}",
        )

    denied = await client.post(
        f"/v1/runs/{run['id']}/candidate-flags/reveal",
        json={"confirm": False},
    )
    assert denied.status_code == 422

    revealed = await client.post(
        f"/v1/runs/{run['id']}/candidate-flags/reveal",
        json={"confirm": True},
    )
    assert revealed.status_code == 200, revealed.text
    assert revealed.headers["cache-control"] == "no-store"
    body = revealed.json()
    assert body["classification"] == "unverified_runtime_candidate"
    assert body["candidate_count"] == len(candidates) + 1
    assert body["scanned_artifact_count"] == 3
    assert body["unavailable_artifact_count"] == 0
    assert body["scan_complete"] is True
    assert [item["value"] for item in body["candidates"]] == [*candidates, stderr_candidate]
    assert body["candidates"][0]["racer_labels"] == ["A", "B"]

    events = await app.state.repository.list_events(run["id"])
    durable_text = repr(events) + repr(await app.state.repository.get_run(run["id"]))
    assert all(candidate not in durable_text for candidate in [*candidates, stderr_candidate])


@pytest.mark.asyncio
async def test_runtime_candidate_gate_requires_human_reject_or_confirmation(
    flag_api: tuple[FastAPI, httpx.AsyncClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A paused candidate queue resumes on rejection and solves only via router."""

    app, client = flag_api
    run = (await app.state.repository.list_runs())[0]
    candidate = "DH-candidate-held-for-review"
    artifact = await LocalArtifactStore(app.state.artifact_root).put_bytes(
        f"result: {candidate}\n".encode("ascii"),
        run_id=run["id"],
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )

    async def queue_gate(key: str) -> None:
        await app.state.repository.append_event(
            run["id"],
            "power.command.observed",
            {
                "summary": "Racer A: exec (running).",
                "label": "A",
                "state": "running",
                "action_type": "exec",
                "action_summary": "Typed sandbox action completed.",
                "observation_received": True,
                "observation_artifact_id": artifact.id,
            },
            actor={"kind": "service", "id": "power-test"},
            idempotency_key=f"candidate-gate-observation-{key}",
        )
        await app.state.repository.transition_run_state(
            run["id"],
            "paused",
            actor={"kind": "system", "id": "candidate-gate-test"},
            reason="power_candidate_review_required",
            idempotency_key=f"candidate-gate-paused-{key}",
        )
        await app.state.repository.append_event(
            run["id"],
            "power.candidate.review.requested",
            {
                "summary": "A runtime flag candidate requires operator review.",
                "session_id": "power-session-fixture",
                "label": "A",
                "observation_artifact_id": artifact.id,
                "candidate_count": 1,
            },
            actor={"kind": "service", "id": "candidate-gate-test"},
            idempotency_key=f"candidate-gate-requested-{key}",
        )

    await queue_gate("one")
    # The browser does not rescan the entire run or wait for a manual action:
    # once the durable pause exists it reads only the triggering evidence.
    queued = await client.get(f"/v1/runs/{run['id']}/candidate-review/queue")
    assert queued.status_code == 200, queued.text
    assert queued.headers["cache-control"] == "no-store"
    assert queued.json()["candidate_count"] == 1
    assert queued.json()["candidates"] == [{"value": candidate, "racer_labels": ["A"]}]

    rejected = await client.post(
        f"/v1/runs/{run['id']}/candidate-review/reject",
        headers={"Idempotency-Key": "candidate-gate-reject-one"},
        json={"confirm": True},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json() == {
        "accepted": True,
        "status": "running",
        "resumed_racer_count": 0,
    }
    assert (await app.state.repository.get_run(run["id"]))["status"] == "running"

    await queue_gate("two")
    received: list[str] = []

    class _IndependentRouter:
        def __init__(self, **_kwargs: object) -> None:
            return None

        async def submit(
            self,
            *,
            run_id: str,
            candidate: str,
            observation_artifact_id: str,
            observation_sha256: str,
        ) -> bool:
            received.append(candidate)
            if len(received) == 1:
                return False
            return await app.state.repository.complete_power_flag(
                run_id=run_id,
                flag_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                masked_flag="DH-…view",
                observation_artifact_id=observation_artifact_id,
                observation_sha256=observation_sha256,
            )

    monkeypatch.setattr("ctfmesh_api.app.HttpFlagRouterClient", _IndependentRouter)
    rejected_by_router = await client.post(
        f"/v1/runs/{run['id']}/candidate-review/confirm",
        headers={"Idempotency-Key": "candidate-gate-confirm-one"},
        json={"confirm": True, "candidate": candidate},
    )
    assert rejected_by_router.status_code == 200, rejected_by_router.text
    assert rejected_by_router.json() == {
        "accepted": False,
        "status": "running",
        "resumed_racer_count": 0,
    }
    assert (await app.state.repository.get_run(run["id"]))["status"] == "running"

    await queue_gate("three")
    aborted_runs: list[tuple[str, str | None]] = []

    class _AbortController:
        async def accepted_flag(self, *, run_id: str, winner_session_id: str | None) -> None:
            aborted_runs.append((run_id, winner_session_id))

        async def aclose(self) -> None:
            return None

    app.state.power_runs = _AbortController()
    confirmed = await client.post(
        f"/v1/runs/{run['id']}/candidate-review/confirm",
        headers={"Idempotency-Key": "candidate-gate-confirm-two"},
        json={"confirm": True, "candidate": candidate},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json() == {"accepted": True, "status": "solved"}
    assert received == [candidate, candidate]
    assert aborted_runs == [(run["id"], None)]
    solved = await app.state.repository.get_run(run["id"])
    assert solved is not None and solved["status"] == "solved"
    durable_text = repr(await app.state.repository.list_events(run["id"])) + repr(solved)
    assert candidate not in durable_text
