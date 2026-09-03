"""An operator must be able to read back an observation's bytes.

A pwn or reverse run produces its result as a file — an exploit script, a
patched binary, a dump. The workspace is a tmpfs that dies with its container,
sandboxd exposes no file route, and ``/v1/runs/{id}/artifacts`` lists metadata
only, so that file was previously reachable only by opening a Docker volume by
hand. These tests pin the supported path and the checks that guard it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_db import Database, Repository
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_tools import LocalArtifactStore
from pydantic import SecretStr

POC = b"#!/usr/bin/env python3\nfrom pwn import *\nio = process('./zigzag')\n"


def _manifest() -> dict[str, object]:
    return {
        "spec": {
            "mode": "assisted",
            "limits": {
                "wall_time_seconds": 600,
                "max_tool_calls": 50,
                "max_http_requests": 50,
                "max_cost_usd": 1.0,
            },
            "flag": {"replay_count": 1},
        }
    }


def _budget() -> dict[str, int | float]:
    return {
        "wall_time_seconds": 600,
        "max_tool_calls": 50,
        "max_http_requests": 50,
        "max_cost_usd": 1.0,
    }


@pytest.fixture
async def api(tmp_path: Path) -> AsyncIterator[tuple[httpx.AsyncClient, Repository, Path]]:
    from ctfmesh_api import create_app
    from ctfmesh_api.settings import Settings

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}")
    await database.create_schema()
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"),
        artifact_root=artifact_root,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as client:
            yield client, Repository(database), artifact_root
    await database.close()


async def _run_with_artifact(
    repository: Repository, artifact_root: Path, *, payload: bytes = POC
) -> tuple[str, str]:
    challenge = await repository.create_challenge(_manifest(), name="poc-lab")
    run = await repository.create_run(
        challenge["id"], mode="assisted", provider="power-swarm", budget=_budget()
    )
    reference = await LocalArtifactStore(artifact_root).put_bytes(
        payload,
        run_id=str(run["id"]),
        mime_type="text/x-python",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )
    return str(run["id"]), reference.id


@pytest.mark.asyncio
async def test_operator_can_read_back_a_stored_proof_of_concept(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    client, repository, artifact_root = api
    run_id, artifact_id = await _run_with_artifact(repository, artifact_root)

    response = await client.post(
        f"/v1/runs/{run_id}/artifacts/{artifact_id}/content", json={"confirm": True}
    )

    assert response.status_code == 200, response.text
    assert response.content == POC
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_reading_raw_bytes_requires_an_explicit_operator_act(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """Deny path: an observation can hold a raw flag, so a read is never incidental."""

    client, repository, artifact_root = api
    run_id, artifact_id = await _run_with_artifact(repository, artifact_root)

    response = await client.post(
        f"/v1/runs/{run_id}/artifacts/{artifact_id}/content", json={"confirm": False}
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "artifact_content_confirmation_required"
    assert POC not in response.content


@pytest.mark.asyncio
async def test_one_run_cannot_read_another_run_evidence(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """Deny path: provenance is re-checked rather than trusted from the path.

    The stores are content addressed, so two runs that observed identical bytes
    legitimately share one artifact. Give the second run its own distinct
    evidence, then ask it for the first run's.
    """

    client, repository, artifact_root = api
    _, artifact_id = await _run_with_artifact(repository, artifact_root)
    other_run_id, _ = await _run_with_artifact(
        repository, artifact_root, payload=b"a different observation\n"
    )

    response = await client.post(
        f"/v1/runs/{other_run_id}/artifacts/{artifact_id}/content", json={"confirm": True}
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "artifact_not_found"


@pytest.mark.asyncio
async def test_reading_content_is_recorded_in_the_append_only_ledger(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    client, repository, artifact_root = api
    run_id, artifact_id = await _run_with_artifact(repository, artifact_root)

    await client.post(f"/v1/runs/{run_id}/artifacts/{artifact_id}/content", json={"confirm": True})

    events = await repository.list_events(run_id)
    reveals = [event for event in events if event["type"] == "artifact.content.revealed"]
    assert len(reveals) == 1
    assert reveals[0]["payload"]["artifact_id"] == artifact_id
    assert reveals[0]["payload"]["size_bytes"] == len(POC)
    assert POC.decode() not in str(reveals[0]["payload"])
