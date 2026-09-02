"""Opt-in P2 end-to-end proof: real archive → workspace → flag-router win."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import docker
import pytest
from ctfmesh_aci import FlagSubmitAction, FsReadAction
from ctfmesh_flag_router import PowerFlagRouter
from ctfmesh_sandboxd.contracts import WorkspaceCreateRequest, WorkspaceExecRequest
from ctfmesh_sandboxd.engine import DockerWorkspaceEngine
from ctfmesh_sandboxd.intake import ArchiveIntakeLocator
from ctfmesh_sandboxd.service import WorkspaceService
from ctfmesh_solver_runtime import ReActSolver, SandboxObservation, SolverContext, SolverTurn
from docker.errors import DockerException
from pydantic import SecretStr

_ROOT = Path(__file__).resolve().parents[2]
_SOCKET = Path("/var/run/docker.sock")


def _enabled() -> bool:
    return os.environ.get("CTFMESH_RUN_POWER_DOCKER_SMOKE") == "1" and _SOCKET.exists()


@dataclass
class _Completion:
    received: dict[str, str] | None = None

    async def complete_power_flag(
        self,
        *,
        run_id: str,
        flag: SecretStr,
        flag_sha256: str,
        masked_flag: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        assert flag.get_secret_value().startswith("CTF{")
        self.received = {
            "run_id": run_id,
            "flag_sha256": flag_sha256,
            "masked_flag": masked_flag,
            "observation_artifact_id": observation_artifact_id,
            "observation_sha256": observation_sha256,
        }
        return True


class _WorkspaceServiceAdapter:
    """Keep the fixture solver on its public P1 RPC-shaped boundary."""

    def __init__(self, service: WorkspaceService) -> None:
        self._service = service

    async def create(self, *, run_id: str, archive_digest: str) -> str:
        receipt = await self._service.create(
            WorkspaceCreateRequest(run_id=run_id, archive_digest=archive_digest)
        )
        return receipt.workspace_id

    async def exec(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> SandboxObservation:
        receipt = await self._service.exec(
            workspace_id,
            WorkspaceExecRequest(
                command=command,
                timeout_seconds=timeout_seconds,
                working_directory=working_directory,
            ),
        )
        return SandboxObservation(
            stdout=receipt.stdout,
            stderr=receipt.stderr,
            exit_code=receipt.exit_code,
            timed_out=receipt.timed_out,
            output_truncated=receipt.output_truncated,
            stdout_artifact_id=receipt.stdout_artifact.id,
            stdout_sha256=receipt.stdout_artifact.sha256,
        )

    async def pty_start(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 smoke must not start an interactive session")

    async def pty_send_read(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 smoke must not use an interactive session")

    async def pty_close(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P2 smoke must not close an interactive session")

    async def tube_connect(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 smoke must not open a tube")

    async def tube_send(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P2 smoke must not send to a tube")

    async def tube_recv_until(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 smoke must not receive from a tube")

    async def tube_close(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P2 smoke must not close a tube")

    async def destroy(self, workspace_id: str) -> None:
        await self._service.destroy(workspace_id)


class _ObservedFlagModel:
    def __init__(self, flag: str) -> None:
        self._flag = flag

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        if not context.observations:
            return SolverTurn(action=FsReadAction(path="/challenge/flag.txt"))
        observation = context.observations[-1]
        assert self._flag in observation.stdout
        return SolverTurn(
            action=FlagSubmitAction(
                candidate=SecretStr(self._flag),
                observation_artifact_id=observation.artifact_id,
                observation_sha256=observation.sha256,
            )
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_power_react_reads_fixture_archive_and_submits_observed_flag(tmp_path: Path) -> None:
    """A no-provider fixture crosses the real P1 workspace and P2 router boundary."""

    if not _enabled():
        pytest.skip("set CTFMESH_RUN_POWER_DOCKER_SMOKE=1 with a Docker socket to run P2 smoke")
    run_id = "power-p2-smoke"
    flag = "CTF{power_p2_real_workspace}"
    source_digest = hashlib.sha256(b"power-p2-real-archive").hexdigest()
    intake = tmp_path / "archive-intakes" / f"intake_{source_digest[:32]}"
    workspace = intake / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "flag.txt").write_text(f"{flag}\n", encoding="utf-8")
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": source_digest}}), encoding="utf-8"
    )

    image = f"ctfmesh-power-workspace:p2-smoke-{uuid4().hex}"
    docker_client = docker.DockerClient(base_url=f"unix://{_SOCKET}", version="auto", timeout=135)
    manager: WorkspaceService | None = None
    try:
        docker_client.images.build(
            path=str(_ROOT), dockerfile="images/power-workspace/Dockerfile", tag=image, rm=True
        )
        manager = WorkspaceService(
            engine=DockerWorkspaceEngine(
                socket_path=str(_SOCKET),
                image=image,
                memory_mb=256,
                cpu_millis=250,
                pids=64,
                work_tmpfs_mb=64,
                tmp_tmpfs_mb=16,
            ),
            intake_locator=ArchiveIntakeLocator(tmp_path, max_bytes=1024 * 1024),
            artifact_root=tmp_path,
            output_limit_bytes=64 * 1024,
            max_exec_timeout_seconds=120,
        )
        completion = _Completion()
        result = await ReActSolver(
            sandbox=_WorkspaceServiceAdapter(manager),
            flag_router=PowerFlagRouter(
                artifact_root=tmp_path,
                completer=completion,
                patterns=(r"CTF\{[A-Za-z0-9_:-]+\}",),
            ),
        ).solve(run_id=run_id, archive_digest=source_digest, backend=_ObservedFlagModel(flag))
        assert result.status == "solved"
        assert completion.received is not None
        assert completion.received["flag_sha256"] != flag
        assert not docker_client.containers.list(
            all=True,
            filters={"label": f"ctfmesh.power.run_id={run_id}"},
        )
    except DockerException as exc:
        pytest.fail(f"Power P2 Docker smoke could not run: {type(exc).__name__}")
    finally:
        if manager is not None:
            for workspace_id in tuple(manager._workspaces):  # noqa: SLF001 - exceptional cleanup proof.
                await manager.destroy(workspace_id)
        try:
            docker_client.images.remove(image, force=True)
        except DockerException:
            pass
        docker_client.close()
