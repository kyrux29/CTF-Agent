"""Power flag-router completion keeps its verified raw value memory-only."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_api import create_app
from ctfmesh_api.settings import Settings
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
        )
    )
    async with LifespanManager(app):
        challenge = await app.state.repository.create_challenge(
            {
                "spec": {
                    "mode": "assisted",
                    "limits": {
                        "wall_time_seconds": 3600,
                        "max_tool_calls": 100,
                        "max_http_requests": 100,
                        "max_cost_usd": 10.0,
                    },
                    "flag": {"replay_count": 1},
                }
            },
            name="power-flag-fixture",
        )
        run = await app.state.repository.create_run(
            challenge["id"],
            mode="assisted",
            provider="fixture",
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
