"""A run's own evidence must be findable in a content-addressed store.

Power seals every tool observation straight into the artifact store and writes
no control-plane artifact row, so the console listed nothing for any Power run
while 39 MB of that run's evidence sat in the store. A racer's working exploit
script was recoverable only by reading the store on the host as root.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_tools import LocalArtifactStore

# Seals happen in order, so the store's own clock orders them. The tests below
# never assert an absolute time, only which observation is newer.
PRODUCER = ActorRef(kind=ActorKind.TOOL, id="sandboxd")


async def _seal(store: LocalArtifactStore, run_id: str, payload: bytes) -> str:
    reference = await store.put_bytes(
        payload,
        run_id=run_id,
        producer=PRODUCER,
        mime_type="application/octet-stream",
    )
    return reference.id


@pytest.fixture
def store(tmp_path: Path) -> LocalArtifactStore:
    return LocalArtifactStore(tmp_path / "artifacts")


async def test_a_run_lists_its_own_sealed_evidence(store: LocalArtifactStore) -> None:
    first = await _seal(store, "run_mine", b"import socket")
    second = await _seal(store, "run_mine", b"0x7ffd deadbeef")
    await _seal(store, "run_other", b"another run's evidence")

    listed = await store.list_for_run("run_mine")

    # Newest first: an operator looking for what a racer just produced should
    # not have to read to the bottom of a long run.
    assert [record.id for record in listed] == [second, first]
    assert {record.run_id for record in listed} == {"run_mine"}

    assert await store.list_for_run("run_absent") == ()


async def test_one_digest_is_listed_once_however_often_it_was_produced(
    store: LocalArtifactStore,
) -> None:
    # The store deduplicates bytes but keeps a provenance sidecar per producing
    # call, so every command that printed nothing shares the empty digest.
    # Listing that object once per call buries the evidence worth looking at.
    empty = ""
    for _ in range(20):
        empty = await _seal(store, "run_noisy", b"")
    real = await _seal(store, "run_noisy", b"VAULTRIX note-cache v1.0")

    listed = await store.list_for_run("run_noisy")

    assert sorted(record.id for record in listed) == sorted({empty, real})


async def test_a_malformed_sidecar_does_not_hide_the_rest_of_a_run(
    store: LocalArtifactStore,
) -> None:
    good = await _seal(store, "run_mixed", b"readable evidence")
    broken = store.root / "metadata" / "sha256" / "aa" / "bb" / ("c" * 64)
    broken.mkdir(parents=True)
    (broken / "record.json").write_text("{ not json", encoding="utf-8")

    listed = await store.list_for_run("run_mixed")

    assert [record.id for record in listed] == [good]


async def test_the_listing_is_bounded(store: LocalArtifactStore) -> None:
    for index in range(5):
        await _seal(store, "run_big", f"evidence {index}".encode())

    assert len(await store.list_for_run("run_big", limit=2)) == 2
    with pytest.raises(ValueError, match="limit must be positive"):
        await store.list_for_run("run_big", limit=0)
