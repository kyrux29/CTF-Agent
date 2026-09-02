"""P4 Docker proof: one verified racer wins and two private workspaces stop."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import uuid4

import docker
import pytest
from ctfmesh_aci import FlagSubmitAction, FsListAction, FsReadAction, ShellExecAction
from ctfmesh_flag_router import PowerFlagRouter
from ctfmesh_orchestrator import (
    PowerRacerSpec,
    PowerRacerState,
    PowerSwarmCoordinator,
    PowerSwarmState,
)
from ctfmesh_sandboxd.contracts import WorkspaceCreateRequest, WorkspaceExecRequest
from ctfmesh_sandboxd.engine import DockerWorkspaceEngine
from ctfmesh_sandboxd.intake import ArchiveIntakeLocator
from ctfmesh_sandboxd.service import WorkspaceService
from ctfmesh_solver_runtime import (
    Sandbox,
    SandboxObservation,
    SolverContext,
    SolverTurn,
)
from docker.errors import DockerException
from pydantic import SecretStr

_ROOT = Path(__file__).resolve().parents[2]
_SOCKET = Path("/var/run/docker.sock")


def _enabled() -> bool:
    return os.environ.get("CTFMESH_RUN_POWER_DOCKER_SMOKE") == "1" and _SOCKET.exists()


@dataclass
class _Completion:
    calls: int = 0

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
        self.calls += 1
        assert run_id == "power-p4-smoke"
        assert len(flag_sha256) == 64
        assert masked_flag.endswith("}")
        assert observation_artifact_id == f"sha256:{observation_sha256}"
        return True


class _WorkspaceServiceAdapter:
    """Use only the public RPC-shaped sandboxd methods needed by this smoke."""

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

    async def destroy(self, workspace_id: str) -> None:
        await self._service.destroy(workspace_id)


class _AutoListModel:
    def __init__(self) -> None:
        self.turn = 0

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        self.turn += 1
        if self.turn == 1:
            return SolverTurn(action=FsListAction(path="/challenge"))
        return SolverTurn(action=None)


class _ObservedFlagModel:
    async def next_turn(self, context: SolverContext) -> SolverTurn:
        if not context.observations:
            return SolverTurn(action=FsReadAction(path="/challenge/flag.txt"))
        observation = context.observations[-1]
        flag = observation.stdout.strip()
        return SolverTurn(
            action=FlagSubmitAction(
                candidate=SecretStr(flag),
                observation_artifact_id=observation.artifact_id,
                observation_sha256=observation.sha256,
            )
        )


class _SlowProbeModel:
    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        # The P4 coordinator cancels the racer after a different workspace
        # has produced an independently verified candidate.
        await asyncio.sleep(0.1)
        return SolverTurn(action=ShellExecAction(command=("true",)))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_power_swarm_runs_three_docker_workspaces_and_cancels_siblings(
    tmp_path: Path,
) -> None:
    """Exercise real P1/P2 boundaries; no provider call and no external target."""

    if not _enabled():
        pytest.skip("set CTFMESH_RUN_POWER_DOCKER_SMOKE=1 with a Docker socket to run P4 smoke")
    run_id = "power-p4-smoke"
    flag = "CTF{power_p4_real_workspace}"
    source_digest = hashlib.sha256(b"power-p4-real-archive").hexdigest()
    intake = tmp_path / "archive-intakes" / f"intake_{source_digest[:32]}"
    workspace = intake / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "flag.txt").write_text(f"{flag}\n", encoding="utf-8")
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": source_digest}}), encoding="utf-8"
    )

    image = f"ctfmesh-power-workspace:p4-smoke-{uuid4().hex}"
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

        def sandbox_factory() -> Sandbox:
            return cast(Sandbox, _WorkspaceServiceAdapter(manager))

        completion = _Completion()
        result = await asyncio.wait_for(
            PowerSwarmCoordinator(
                sandbox_factory=sandbox_factory,
                flag_router=PowerFlagRouter(
                    artifact_root=tmp_path,
                    completer=completion,
                    patterns=(r"CTF\{[A-Za-z0-9_:-]+\}",),
                ),
            ).run(
                run_id=run_id,
                archive_digest=source_digest,
                autoprompter_backend=_AutoListModel(),
                racers=(
                    PowerRacerSpec(racer_id="racer-a", label="A", backend=_ObservedFlagModel()),
                    PowerRacerSpec(racer_id="racer-b", label="B", backend=_SlowProbeModel()),
                    PowerRacerSpec(racer_id="racer-c", label="C", backend=_SlowProbeModel()),
                ),
            ),
            timeout=20,
        )

        assert result.state is PowerSwarmState.SOLVED
        assert result.winner_racer_id == "racer-a"
        assert completion.calls == 1
        assert {racer.state for racer in result.racers} == {
            PowerRacerState.SOLVED,
            PowerRacerState.CANCELLED,
        }
        assert not docker_client.containers.list(
            all=True,
            filters={"label": f"ctfmesh.power.run_id={run_id}"},
        )
    except DockerException as exc:
        pytest.fail(f"Power P4 Docker smoke could not run: {type(exc).__name__}")
    finally:
        if manager is not None:
            for workspace_id in tuple(manager._workspaces):  # noqa: SLF001 - cleanup proof.
                await manager.destroy(workspace_id)
        try:
            docker_client.images.remove(image, force=True)
        except DockerException:
            pass
        docker_client.close()
