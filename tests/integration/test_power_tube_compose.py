"""P3 Compose proof for a scoped TCP tube without Docker-manager authority."""

from __future__ import annotations

import hashlib
import json
import os
from base64 import b64encode
from pathlib import Path

import pytest
from ctfmesh_sandboxd.contracts import (
    TubeConnectRequest,
    TubeRecvUntilRequest,
    TubeSendRequest,
    TubeTarget,
    WorkspaceCreateRequest,
)
from ctfmesh_sandboxd.engine import EngineExecResult, PtyChannel
from ctfmesh_sandboxd.intake import ArchiveIntakeLocator
from ctfmesh_sandboxd.service import WorkspaceService
from ctfmesh_tools import LocalArtifactStore


class _TubeProofEngine:
    """A lifecycle fake: this Compose proof intentionally has no Docker socket."""

    def reap_managed_workspaces(self) -> None:
        return None

    def create_workspace(self, *, workspace_id: str, run_id: str, archive_digest: str) -> str:
        del run_id, archive_digest
        return f"container-{workspace_id}"

    def copy_challenge(self, container_id: str, archive: bytes) -> None:
        del container_id, archive

    def exec(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
        output_limit_bytes: int,
    ) -> EngineExecResult:
        del container_id, command, timeout_seconds, working_directory, output_limit_bytes
        raise AssertionError("tube Compose proof must not execute a workspace command")

    def pty_start(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> PtyChannel:
        del container_id, command, timeout_seconds, working_directory
        raise AssertionError("tube Compose proof must not create a PTY")

    def destroy_workspace(self, container_id: str) -> None:
        del container_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_compose_echo_accepts_only_the_declared_tube_endpoint(tmp_path: Path) -> None:
    """Bytes cross a real internal Compose network and land in the artifact store."""

    host = os.environ.get("CTFMESH_P3_TUBE_HOST")
    if host is None:
        pytest.skip("set CTFMESH_P3_TUBE_HOST inside the P3 Compose proof")
    port = 31337
    digest = hashlib.sha256(b"p3-compose-tube").hexdigest()
    intake = tmp_path / "archive-intakes" / f"intake_{digest[:32]}"
    (intake / "workspace").mkdir(parents=True)
    (intake / "workspace" / "README").write_text("P3 tube Compose proof\n", encoding="utf-8")
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": digest}}), encoding="utf-8"
    )
    manager = WorkspaceService(
        engine=_TubeProofEngine(),
        intake_locator=ArchiveIntakeLocator(tmp_path, max_bytes=1024 * 1024),
        artifact_root=tmp_path,
        output_limit_bytes=64 * 1024,
        max_exec_timeout_seconds=120,
    )
    workspace = await manager.create(
        WorkspaceCreateRequest(
            run_id="power-p3-compose-tube",
            archive_digest=digest,
            tube_targets=(TubeTarget(host=host, port=port),),
        )
    )
    try:
        tube = await manager.tube_connect(
            workspace.workspace_id, TubeConnectRequest(host=host, port=port)
        )
        await manager.tube_send(
            workspace.workspace_id,
            tube.tube_id,
            TubeSendRequest(data_base64=b64encode(b"compose\n").decode("ascii")),
        )
        received = await manager.tube_recv_until(
            workspace.workspace_id,
            tube.tube_id,
            TubeRecvUntilRequest(delimiter_base64=b64encode(b"\n").decode("ascii")),
        )
        assert received.data == "echo:compose\n"
        assert await LocalArtifactStore(tmp_path).get_bytes(received.observation_artifact.id) == (
            b"echo:compose\n"
        )
    finally:
        await manager.destroy(workspace.workspace_id)
