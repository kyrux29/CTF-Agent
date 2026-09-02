"""Read-only consumers must not initialize or mutate the artifact store."""

from __future__ import annotations

from pathlib import Path

import pytest
from ctfmesh_tools import ArtifactNotFoundError, LocalArtifactStore


def test_read_only_artifact_store_leaves_an_empty_existing_root_untouched(tmp_path: Path) -> None:
    """Flag-router startup works before the first observation is written."""

    root = tmp_path / "artifacts"
    root.mkdir()
    store = LocalArtifactStore(root, read_only=True)
    assert store.root == root.resolve()
    assert not (root / "objects").exists()
    with pytest.raises(ArtifactNotFoundError, match="artifact does not exist"):
        store._read_verified_blob("a" * 64)  # noqa: SLF001 - precise read-only proof.


def test_read_only_artifact_store_requires_a_prepared_volume(tmp_path: Path) -> None:
    """A typo cannot silently create a router-controlled artifact root."""

    with pytest.raises(ArtifactNotFoundError, match="artifact root does not exist"):
        LocalArtifactStore(tmp_path / "missing", read_only=True)
