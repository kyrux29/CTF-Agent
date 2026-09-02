"""Preparation of disposable, manifest-scoped artifact workspaces.

Both AI triage and the local read-only MCP facade need the same guarantee: a
tool may see only explicitly declared regular files, never the caller's whole
challenge directory.  This module performs that materialization before a
runtime receives a workspace path.
"""

from __future__ import annotations

import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from ctfmesh_domain import ChallengeManifest

MAX_READONLY_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_READONLY_ARTIFACTS = 64


class ReadonlyWorkspaceError(ValueError):
    """Stable, non-sensitive workspace-preparation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class MaterializedArtifact:
    """A declared artifact's safe workspace projection."""

    evidence_id: str
    relative_path: str
    role: str
    source_size_bytes: int
    materialized: bool


def resolve_challenge_root(challenge_root: Path) -> Path:
    """Resolve an existing local challenge directory without falling back."""

    try:
        resolved = challenge_root.resolve(strict=True)
    except OSError as exc:
        raise ReadonlyWorkspaceError("challenge_root_unavailable") from exc
    if not resolved.is_dir():
        raise ReadonlyWorkspaceError("challenge_root_not_directory")
    return resolved


def materialize_declared_artifacts(
    challenge_root: Path,
    workspace: Path,
    manifest: ChallengeManifest,
    *,
    oversize: Literal["skip", "reject"] = "skip",
) -> tuple[MaterializedArtifact, ...]:
    """Copy only declared regular files into a new disposable workspace.

    ``skip`` preserves a bounded descriptor for an oversized input so static
    triage can state that it was not inspected.  ``reject`` is used by MCP,
    where exposing a partial workspace would misrepresent the manifest scope.
    """

    try:
        workspace.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise ReadonlyWorkspaceError("readonly_workspace_unavailable") from exc
    materialized: list[MaterializedArtifact] = []
    for index, artifact in enumerate(manifest.spec.artifacts[:MAX_READONLY_ARTIFACTS], start=1):
        relative_path = artifact.path
        source, source_size = declared_regular_file(challenge_root, relative_path)
        copied = source_size <= MAX_READONLY_ARTIFACT_BYTES
        if not copied and oversize == "reject":
            raise ReadonlyWorkspaceError("declared_artifact_exceeds_readonly_limit")
        if copied:
            destination = workspace / Path(*PurePosixPath(relative_path).parts)
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            except OSError as exc:
                raise ReadonlyWorkspaceError("declared_artifact_copy_failed") from exc
        materialized.append(
            MaterializedArtifact(
                evidence_id=f"artifact-{index:02d}",
                relative_path=relative_path,
                role=artifact.role.value,
                source_size_bytes=source_size,
                materialized=copied,
            )
        )
    return tuple(materialized)


def declared_regular_file(challenge_root: Path, relative_path: str) -> tuple[Path, int]:
    """Resolve one manifest path while rejecting symlinks and special files."""

    relative = PurePosixPath(relative_path)
    current = challenge_root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ReadonlyWorkspaceError("declared_artifact_unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ReadonlyWorkspaceError("declared_artifact_symlink_denied")
    try:
        metadata = current.stat(follow_symlinks=False)
    except OSError as exc:
        raise ReadonlyWorkspaceError("declared_artifact_unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ReadonlyWorkspaceError("declared_artifact_not_regular_file")
    return current, metadata.st_size


__all__ = [
    "MAX_READONLY_ARTIFACT_BYTES",
    "MAX_READONLY_ARTIFACTS",
    "MaterializedArtifact",
    "ReadonlyWorkspaceError",
    "declared_regular_file",
    "materialize_declared_artifacts",
    "resolve_challenge_root",
]
