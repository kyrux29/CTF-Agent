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


@pytest.mark.asyncio
async def test_the_console_lists_evidence_a_power_run_sealed_without_a_row(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """The artifact panel must show what a Power run actually produced.

    Artifact rows are written only by the v0.1-generation flows. Power seals
    straight into the content store, so every Power run's panel was empty and
    the operator had no way to learn the artifact id the content route needs -
    which made the route above reachable only by reading the store on the host.
    """

    client, repository, artifact_root = api
    run_id, artifact_id = await _run_with_artifact(repository, artifact_root)

    response = await client.get(f"/v1/runs/{run_id}/console")

    assert response.status_code == 200, response.text
    artifacts = response.json()["artifacts"]
    assert [item["id"] for item in artifacts] == [artifact_id]
    listed = artifacts[0]
    assert listed["size_bytes"] == len(POC)
    assert listed["digest"] == artifact_id
    # The id the panel shows is exactly what the content route accepts, which
    # is the whole point of listing it.
    content = await client.post(
        f"/v1/runs/{run_id}/artifacts/{listed['id']}/content", json={"confirm": True}
    )
    assert content.status_code == 200, content.text
    assert content.content == POC


@pytest.mark.asyncio
async def test_one_run_console_never_lists_another_run_evidence(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    client, repository, artifact_root = api
    run_id, _ = await _run_with_artifact(repository, artifact_root)
    other_run_id, other_artifact_id = await _run_with_artifact(
        repository, artifact_root, payload=b"a different run's evidence"
    )

    response = await client.get(f"/v1/runs/{run_id}/console")

    assert response.status_code == 200, response.text
    assert other_artifact_id not in {item["id"] for item in response.json()["artifacts"]}
    assert other_run_id != run_id


@pytest.mark.asyncio
async def test_removing_a_run_takes_its_sealed_evidence_with_it(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """A removed run must not leave bytes nothing can list or name."""

    client, repository, artifact_root = api
    run_id, artifact_id = await _run_with_artifact(repository, artifact_root)
    await repository.transition_run(
        run_id,
        "cancelled",
        actor={"kind": "system", "id": "test"},
        reason="test_setup",
        idempotency_key=f"test-cancel:{run_id}",
    )

    # Naming the wrong run is the same as not confirming at all.
    refused = await client.request(
        "DELETE", f"/v1/runs/{run_id}", headers={"x-confirm-remove": "run_something_else"}
    )
    assert refused.status_code == 422, refused.text
    assert (await client.get(f"/v1/runs/{run_id}/console")).status_code == 200

    removed = await client.request(
        "DELETE", f"/v1/runs/{run_id}", headers={"x-confirm-remove": run_id}
    )
    assert removed.status_code == 200, removed.text
    assert removed.json()["artifacts_forgotten"] == 1

    assert (await client.get(f"/v1/runs/{run_id}/console")).status_code == 404
    content = await client.post(
        f"/v1/runs/{run_id}/artifacts/{artifact_id}/content", json={"confirm": True}
    )
    assert content.status_code == 404, content.text


@pytest.mark.asyncio
async def test_a_run_still_in_flight_cannot_be_removed(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """Removing mid-flight would leave a runner leasing rows that are gone."""

    client, repository, artifact_root = api
    run_id, _ = await _run_with_artifact(repository, artifact_root)

    response = await client.request(
        "DELETE", f"/v1/runs/{run_id}", headers={"x-confirm-remove": run_id}
    )

    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "run_not_settled"
    assert (await client.get(f"/v1/runs/{run_id}/console")).status_code == 200


@pytest.mark.asyncio
async def test_bytes_shared_with_another_run_survive_a_removal(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """The store deduplicates, so one run's removal must not blind another.

    Two racers that both read the same challenge file produce one object with
    two provenance records. Removing one run because it is finished cannot take
    evidence the other run still lists.
    """

    client, repository, artifact_root = api
    doomed_id, artifact_id = await _run_with_artifact(repository, artifact_root)
    kept_id, kept_artifact_id = await _run_with_artifact(repository, artifact_root)
    assert artifact_id == kept_artifact_id  # same bytes, same digest
    await repository.transition_run(
        doomed_id,
        "cancelled",
        actor={"kind": "system", "id": "test"},
        reason="test_setup",
        idempotency_key=f"test-cancel:{doomed_id}",
    )

    removed = await client.request(
        "DELETE", f"/v1/runs/{doomed_id}", headers={"x-confirm-remove": doomed_id}
    )
    assert removed.status_code == 200, removed.text

    survivor = await client.post(
        f"/v1/runs/{kept_id}/artifacts/{artifact_id}/content", json={"confirm": True}
    )
    assert survivor.status_code == 200, survivor.text
    assert survivor.content == POC


def test_every_tool_the_runner_can_call_is_named_at_the_boundary() -> None:
    """A tool with a parser and a handler is still refused if unnamed here.

    ``ctf_artifact_read`` was added with both, but not to the action literal,
    so every call failed at request validation and a racer could never reread
    its own truncated observation - it reported the tool as broken and gave up
    on the evidence instead.
    """

    from typing import get_args

    from ctfmesh_api import app as api_app

    named = set(get_args(api_app.InternalPowerToolRequest.model_fields["action"].annotation))
    assert "artifact_read" in named

    # Every action the boundary admits must have a parser behind it. A missing
    # one raises the same generic error the missing literal did.
    for action in named:
        with pytest.raises(ValueError, match="power_tool_arguments_invalid"):
            api_app._parse_power_tool_arguments(action, {"deliberately": "invalid"})

    # And every tool the runner may name is admitted, so a tool cannot be
    # shipped that the request model silently refuses.
    tools = set(
        get_args(get_args(api_app.InternalPowerToolRequest.model_fields["tool_name"].annotation)[0])
    )
    assert "ctf_artifact_read" in tools
    assert "ctf_gdb_read" in tools


@pytest.mark.asyncio
async def test_the_console_names_the_archive_a_run_came_from(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """Continuing a run posts against its archive, so the console must say which.

    Nothing else in the projection names it, and several identical uploads can
    exist at once - an operator could not tell which produced this run.
    """

    client, repository, _ = api
    intake_id = f"intake_{'b' * 32}"
    manifest = _manifest()
    spec = manifest["spec"]
    assert isinstance(spec, dict)
    spec["source"] = {"intake_id": intake_id, "slot_id": "slot-1"}
    challenge = await repository.create_challenge(manifest, name=f"power-{'b' * 32}")
    run = await repository.create_run(
        challenge["id"], mode="assisted", provider="power-swarm", budget=_budget()
    )

    response = await client.get(f"/v1/runs/{run['id']}/console")

    assert response.status_code == 200, response.text
    assert response.json()["run"]["source_intake_id"] == intake_id


@pytest.mark.asyncio
async def test_a_run_recorded_before_power_wrote_its_source_still_resolves(
    api: tuple[httpx.AsyncClient, Repository, Path],
) -> None:
    """A generated challenge is named after its intake, so the name recovers it.

    Archive removal already relies on that correspondence; without using it
    here, every run that exists today could never be continued.
    """

    client, repository, _ = api
    suffix = "c" * 32
    challenge = await repository.create_challenge(_manifest(), name=f"power-{suffix}")
    run = await repository.create_run(
        challenge["id"], mode="assisted", provider="power-swarm", budget=_budget()
    )

    response = await client.get(f"/v1/runs/{run['id']}/console")

    assert response.status_code == 200, response.text
    assert response.json()["run"]["source_intake_id"] == f"intake_{suffix}"
