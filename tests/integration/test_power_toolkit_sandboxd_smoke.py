"""Opt-in P5 proof: the deployed toolkit is usable through sandboxd's boundary."""

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
async def test_power_toolkit_commands_run_in_a_non_networked_workspace(tmp_path: Path) -> None:
    """The solver-facing service executes real pinned tools, not host binaries."""

    if not _enabled():
        pytest.skip("set CTFMESH_RUN_POWER_DOCKER_SMOKE=1 with a Docker socket to run P5 smoke")
    source_digest = hashlib.sha256(b"power-p5-toolkit").hexdigest()
    intake = tmp_path / "archive-intakes" / f"intake_{source_digest[:32]}"
    (intake / "workspace").mkdir(parents=True)
    (intake / "workspace" / "README").write_text("P5 toolkit fixture\n", encoding="utf-8")
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": source_digest}}), encoding="utf-8"
    )

    image = f"ctfmesh-ctf-toolkit:p5-smoke-{uuid4().hex}"
    client = docker.DockerClient(base_url=f"unix://{_SOCKET}", version="auto", timeout=180)
    manager: WorkspaceService | None = None
    workspace_id: str | None = None
    try:
        client.images.build(
            path=str(_ROOT), dockerfile="images/ctf-toolkit/Dockerfile", tag=image, rm=True
        )
        manager = WorkspaceService(
            engine=DockerWorkspaceEngine(
                socket_path=str(_SOCKET),
                image=image,
                memory_mb=512,
                cpu_millis=500,
                pids=128,
                work_tmpfs_mb=64,
                tmp_tmpfs_mb=32,
            ),
            intake_locator=ArchiveIntakeLocator(tmp_path, max_bytes=1024 * 1024),
            artifact_root=tmp_path,
            output_limit_bytes=64 * 1024,
            max_exec_timeout_seconds=120,
        )
        receipt = await manager.create(
            WorkspaceCreateRequest(run_id="power-p5-smoke", archive_digest=source_digest)
        )
        workspace_id = receipt.workspace_id

        gdb = await manager.exec(workspace_id, WorkspaceExecRequest(command=("gdb", "--version")))
        python = await manager.exec(
            workspace_id,
            WorkspaceExecRequest(command=("python3", "-c", "import gmpy2; import pwn")),
        )
        scratch = await manager.exec(
            workspace_id,
            WorkspaceExecRequest(
                command=(
                    "python3",
                    "-c",
                    "from pathlib import Path; "
                    "Path('/work/p5-proof').write_text('ok'); print('scratch-ok')",
                ),
            ),
        )
        radare = await manager.exec(workspace_id, WorkspaceExecRequest(command=("r2", "-v")))

        assert gdb.exit_code == 0
        assert "GNU gdb (GDB) 15.2" in gdb.stdout
        assert python.exit_code == 0
        assert python.stderr == ""
        assert scratch.exit_code == 0
        assert scratch.stdout == "scratch-ok\n"
        assert radare.exit_code == 0
        assert "radare2 5.9.8" in radare.stdout
        await manager.destroy(workspace_id)
        workspace_id = None
        assert not client.containers.list(
            all=True,
            filters={"label": "ctfmesh.power.run_id=power-p5-smoke"},
        )
    except DockerException as exc:
        pytest.fail(f"Power P5 Docker smoke could not run: {type(exc).__name__}")
    finally:
        if manager is not None and workspace_id is not None:
            await manager.destroy(workspace_id)
        try:
            client.images.remove(image, force=True)
        except DockerException:
            pass
        client.close()
