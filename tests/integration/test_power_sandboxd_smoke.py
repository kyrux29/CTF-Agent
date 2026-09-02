"""Opt-in real-Docker proof for Power P1 workspace creation and cleanup."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import docker
import pytest
from ctfmesh_sandboxd.contracts import WorkspaceCreateRequest, WorkspaceExecRequest
from ctfmesh_sandboxd.engine import DockerWorkspaceEngine
from ctfmesh_sandboxd.intake import ArchiveIntakeLocator
from ctfmesh_sandboxd.service import WorkspaceService
from docker.errors import DockerException

_ROOT = Path(__file__).resolve().parents[2]
_SOCKET = Path("/var/run/docker.sock")


def _enabled() -> bool:
    return os.environ.get("CTFMESH_RUN_POWER_DOCKER_SMOKE") == "1" and _SOCKET.exists()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_power_workspace_create_exec_and_destroy_has_no_orphan(tmp_path: Path) -> None:
    """Create an actual box, observe /challenge and uid, then remove exactly it."""

    if not _enabled():
        pytest.skip("set CTFMESH_RUN_POWER_DOCKER_SMOKE=1 with a Docker socket to run P1 smoke")
    source_digest = hashlib.sha256(b"power-p1-smoke").hexdigest()
    intake = tmp_path / "archive-intakes" / f"intake_{source_digest[:32]}"
    workspace = intake / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "brief.txt").write_text("P1 smoke input\n", encoding="utf-8")
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": source_digest}}),
        encoding="utf-8",
    )

    image = f"ctfmesh-power-workspace:p1-smoke-{uuid4().hex}"
    client = docker.DockerClient(base_url=f"unix://{_SOCKET}", version="auto", timeout=135)
    manager: WorkspaceService | None = None
    receipt = None
    try:
        client.images.build(
            path=str(_ROOT),
            dockerfile="images/power-workspace/Dockerfile",
            tag=image,
            rm=True,
        )
        engine = DockerWorkspaceEngine(
            socket_path=str(_SOCKET),
            image=image,
            memory_mb=256,
            cpu_millis=250,
            pids=64,
            work_tmpfs_mb=64,
            tmp_tmpfs_mb=16,
        )
        manager = WorkspaceService(
            engine=engine,
            intake_locator=ArchiveIntakeLocator(tmp_path, max_bytes=1024 * 1024),
            artifact_root=tmp_path,
            output_limit_bytes=64 * 1024,
            max_exec_timeout_seconds=120,
        )
        receipt = await manager.create(
            WorkspaceCreateRequest(run_id="power-p1-smoke", archive_digest=source_digest)
        )
        containers = client.containers.list(
            all=True,
            filters={"label": f"ctfmesh.power.workspace_id={receipt.workspace_id}"},
        )
        assert len(containers) == 1
        attributes = containers[0].attrs
        host = attributes["HostConfig"]
        assert attributes["Config"]["User"] == "1000:1000"
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"]
        assert host["CapAdd"] == ["SYS_PTRACE"]
        # Docker presents named volumes in HostConfig.Binds too. The source is
        # a manager-generated volume name (not an absolute host path), and
        # Mounts below proves Docker did not turn it into a bind mount.
        assert host["Binds"] == [f"ctfmesh-power-challenge-{receipt.workspace_id}:/challenge:rw"]
        mounts = attributes["Mounts"]
        assert len(mounts) == 1
        challenge_mount = mounts[0]
        assert challenge_mount["Type"] == "volume"
        assert challenge_mount["Name"] == f"ctfmesh-power-challenge-{receipt.workspace_id}"
        assert challenge_mount["Destination"] == "/challenge"
        assert challenge_mount["RW"] is True

        listed = await manager.exec(
            receipt.workspace_id,
            WorkspaceExecRequest(command=("ls", "-1"), working_directory="/challenge"),
        )
        identity = await manager.exec(receipt.workspace_id, WorkspaceExecRequest(command=("id",)))
        assert listed.stdout == "brief.txt\n"
        assert "uid=1000(ctf)" in identity.stdout
    except DockerException as exc:
        pytest.fail(f"Power P1 Docker smoke could not run: {type(exc).__name__}")
    finally:
        if manager is not None and receipt is not None:
            await manager.destroy(receipt.workspace_id)
            assert not client.containers.list(
                all=True,
                filters={"label": f"ctfmesh.power.workspace_id={receipt.workspace_id}"},
            )
            assert not client.volumes.list(
                filters={"name": f"ctfmesh-power-challenge-{receipt.workspace_id}"},
            )
        try:
            client.images.remove(image, force=True)
        except DockerException:
            pass
        client.close()
