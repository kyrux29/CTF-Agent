"""Public one-time remote flag reveal contract."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_api import create_app
from ctfmesh_api.settings import Settings
from pydantic import SecretStr


@pytest.mark.asyncio
async def test_public_flag_reveal_requires_solved_state_then_consumes_memory_lease(
    tmp_path: Path,
) -> None:
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'reveal-api.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings)
    raw_flag = "CTF{verified_lease_only}"

    async with LifespanManager(app):

        async def get_run(run_id: str) -> dict[str, str]:
            return {"id": run_id, "status": "solved"}

        app.state.repository = SimpleNamespace(get_run=get_run)
        await app.state.verified_flag_reveals.issue(
            run_id="run-verified-reveal-api",
            candidate_id="candidate-verified-reveal-api",
            flag=raw_flag,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            denied = await client.post(
                "/v1/runs/run-verified-reveal-api/flag-reveal",
                json={"confirm": False},
            )
            assert denied.status_code == 422
            assert raw_flag not in denied.text

            revealed = await client.post(
                "/v1/runs/run-verified-reveal-api/flag-reveal",
                json={"confirm": True},
            )
            assert revealed.status_code == 200
            assert revealed.headers["cache-control"] == "no-store"
            assert revealed.json() == {"flag": raw_flag, "one_time": True}

            repeated = await client.post(
                "/v1/runs/run-verified-reveal-api/flag-reveal",
                json={"confirm": True},
            )
            assert repeated.status_code == 410
            assert raw_flag not in repeated.text
