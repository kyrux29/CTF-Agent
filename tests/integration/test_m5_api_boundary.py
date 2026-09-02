"""M5 API authentication boundary checks independent from Pi Runner."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_api import create_app
from ctfmesh_api.settings import Settings
from pydantic import SecretStr


@pytest.fixture
async def m5_client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'm5-api.db'}"),
        artifact_root=tmp_path / "artifacts",
        internal_runner_token=SecretStr("runner-token-fixture-1234"),
        internal_verifier_token=SecretStr("verifier-token-fixture-1234"),
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


@pytest.mark.asyncio
async def test_verifier_queue_rejects_pi_runner_credential_and_never_echoes_either_secret(
    m5_client: httpx.AsyncClient,
) -> None:
    """A Pi Runner cannot claim verifier work even when both services use the API."""

    runner_token = "runner-token-fixture-1234"
    verifier_token = "verifier-token-fixture-1234"
    denied = await m5_client.post(
        "/internal/verification-jobs/claim",
        json={"verifier_id": "independent-verifier", "lease_seconds": 30},
        headers={"X-CTFMesh-Runner-Token": runner_token},
    )
    assert denied.status_code == 401
    assert runner_token not in denied.text
    assert verifier_token not in denied.text

    accepted = await m5_client.post(
        "/internal/verification-jobs/claim",
        json={"verifier_id": "independent-verifier", "lease_seconds": 30},
        headers={"X-CTFMesh-Verifier-Token": verifier_token},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"job": None}
