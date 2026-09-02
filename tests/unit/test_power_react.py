"""P2 fixture proof: observed file content can win; model prose cannot."""

from __future__ import annotations

import hashlib
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path

import pytest
from ctfmesh_aci import (
    FlagSubmitAction,
    FsReadAction,
    GdbCmdAction,
    GdbStartAction,
    TubeConnectAction,
    TubeRecvUntilAction,
    TubeSendAction,
)
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_flag_router import PowerFlagRouter
from ctfmesh_solver_runtime import (
    ReActSolver,
    SandboxObservation,
    SolverContext,
    SolverTurn,
    SolverTurnTelemetry,
)
from ctfmesh_tools import LocalArtifactStore
from pydantic import SecretStr


@dataclass
class _Completion:
    solved: bool = False
    calls: int = 0
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
        self.calls += 1
        self.solved = True
        self.received = {
            "run_id": run_id,
            "flag_sha256": flag_sha256,
            "masked_flag": masked_flag,
            "observation_artifact_id": observation_artifact_id,
            "observation_sha256": observation_sha256,
        }
        return True


class _Sandbox:
    def __init__(self, root: Path, *, flag: str) -> None:
        self._store = LocalArtifactStore(root, max_artifact_bytes=64 * 1024)
        self._flag = flag
        self.destroyed: list[str] = []

    async def create(self, *, run_id: str, archive_digest: str) -> str:
        assert run_id == "run-power-p2"
        assert len(archive_digest) == 64
        return "ws_0123456789abcdef0123456789abcdef"

    async def exec(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> SandboxObservation:
        assert workspace_id.startswith("ws_")
        assert command[:3] == ("head", "-c", "16384")
        assert command[-1] == "/challenge/flag.txt"
        assert timeout_seconds == 30
        assert working_directory == "/work"
        output = f"{self._flag}\n".encode()
        artifact = await self._store.put_bytes(
            output,
            run_id="run-power-p2",
            mime_type="application/octet-stream",
            producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
            classification="secret",
        )
        return SandboxObservation(
            stdout=output.decode(),
            stderr="",
            exit_code=0,
            timed_out=False,
            output_truncated=False,
            stdout_artifact_id=artifact.id,
            stdout_sha256=artifact.sha256,
        )

    async def pty_start(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 fixture must not start an interactive session")

    async def pty_send_read(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 fixture must not use an interactive session")

    async def pty_close(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P2 fixture must not close an interactive session")

    async def tube_connect(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 fixture must not open a tube")

    async def tube_send(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P2 fixture must not send to a tube")

    async def tube_recv_until(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P2 fixture must not receive from a tube")

    async def tube_close(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P2 fixture must not close a tube")

    async def destroy(self, workspace_id: str) -> None:
        self.destroyed.append(workspace_id)


class _ObservedFlagModel:
    def __init__(self, flag: str) -> None:
        self._flag = flag
        self.calls = 0

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self.calls += 1
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


class _ProseOnlyModel:
    async def next_turn(self, context: SolverContext) -> SolverTurn:
        assert not context.observations
        return SolverTurn(action=None, thought="The flag is CTF{fabricated_claim}.")


class _IatSandbox:
    """Minimal typed boundary proving IAT sessions stay separated by kind."""

    destroyed: list[str]

    def __init__(self) -> None:
        self.destroyed = []
        self.gdb_id = "pty_" + "a" * 32
        self.tube_id = "tube_" + "b" * 32

    async def create(self, *, run_id: str, archive_digest: str) -> str:
        del run_id, archive_digest
        return "ws_0123456789abcdef0123456789abcdef"

    async def exec(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("IAT fixture does not use shell.exec")

    async def pty_start(self, *args: object, kind: str, **kwargs: object) -> SandboxObservation:
        assert kind == "gdb"
        return _iat_observation("GNU gdb ready\n", self.gdb_id, "gdb")

    async def pty_send_read(
        self, *args: object, pty_id: str, data: str, kind: str, **kwargs: object
    ) -> SandboxObservation:
        assert pty_id == self.gdb_id
        assert kind == "gdb"
        assert data == "break main\n"
        return _iat_observation("Breakpoint 1 at main\n", self.gdb_id, "gdb")

    async def pty_close(self, *args: object, **kwargs: object) -> None:
        return None

    async def tube_connect(
        self, *args: object, host: str, port: int, **kwargs: object
    ) -> SandboxObservation:
        assert (host, port) == ("challenge.test", 31337)
        return _iat_observation("connected challenge.test:31337\n", self.tube_id, "tube")

    async def tube_send(
        self, *args: object, tube_id: str, data_base64: str, **kwargs: object
    ) -> None:
        assert tube_id == self.tube_id
        assert data_base64 == b64encode(b"ping\n").decode("ascii")

    async def tube_recv_until(
        self, *args: object, tube_id: str, **kwargs: object
    ) -> SandboxObservation:
        assert tube_id == self.tube_id
        return _iat_observation("pong\n", self.tube_id, "tube")

    async def tube_close(self, *args: object, **kwargs: object) -> None:
        return None

    async def destroy(self, workspace_id: str) -> None:
        self.destroyed.append(workspace_id)


def _iat_observation(value: str, identifier: str, kind: str) -> SandboxObservation:
    digest = hashlib.sha256(value.encode()).hexdigest()
    return SandboxObservation(
        stdout=value,
        stderr="",
        exit_code=None,
        timed_out=False,
        output_truncated=False,
        stdout_artifact_id=f"sha256:{digest}",
        stdout_sha256=digest,
        interactive_id=identifier,
        interactive_kind=kind,
    )


class _IatModel:
    def __init__(self) -> None:
        self._turn = 0

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self._turn += 1
        if self._turn == 1:
            return SolverTurn(action=GdbStartAction(path="/challenge/hello"))
        if self._turn == 2:
            return SolverTurn(
                action=GdbCmdAction(
                    gdb_id=context.observations[-1].interactive_id or "", command="break main"
                )
            )
        if self._turn == 3:
            return SolverTurn(action=TubeConnectAction(host="challenge.test", port=31337))
        if self._turn == 4:
            return SolverTurn(
                action=TubeSendAction(
                    tube_id=context.observations[-1].interactive_id or "",
                    data_base64=b64encode(b"ping\n").decode("ascii"),
                )
            )
        if self._turn == 5:
            return SolverTurn(
                action=TubeRecvUntilAction(
                    tube_id=context.observations[-1].interactive_id or "",
                    delimiter_base64=b64encode(b"\n").decode("ascii"),
                )
            )
        return SolverTurn(action=None)


@pytest.mark.asyncio
async def test_fixture_solver_reads_an_observed_flag_then_router_solves(tmp_path: Path) -> None:
    """The fixture only wins after flag-router re-reads the sandbox artifact."""

    flag = "CTF{power_p2_fixture}"
    completion = _Completion()
    sandbox = _Sandbox(tmp_path, flag=flag)
    telemetry: list[SolverTurnTelemetry] = []

    async def record_turn(receipt: SolverTurnTelemetry) -> None:
        telemetry.append(receipt)

    router = PowerFlagRouter(
        artifact_root=tmp_path,
        completer=completion,
        patterns=(r"CTF\{[A-Za-z0-9_:-]+\}",),
    )
    result = await ReActSolver(
        sandbox=sandbox,
        flag_router=router,
        on_turn_telemetry=record_turn,
    ).solve(
        run_id="run-power-p2",
        archive_digest="a" * 64,
        backend=_ObservedFlagModel(flag),
    )
    assert result.status == "solved"
    assert len(result.observations) == 1
    assert completion.solved is True
    assert completion.received is not None
    assert completion.received["flag_sha256"] != flag
    assert sandbox.destroyed == ["ws_0123456789abcdef0123456789abcdef"]
    assert telemetry[0].action_summary == "Reading one challenge file."
    assert telemetry[0].observation_artifact_id is not None
    assert (
        telemetry[-1].action_summary
        == "Submitting an observed candidate for independent verification."
    )
    assert telemetry[-1].observation_artifact_id is None
    assert flag not in repr(telemetry)
    assert "flag.txt" not in repr(telemetry)


@pytest.mark.asyncio
async def test_model_prose_cannot_claim_a_flag_or_transition_a_run(tmp_path: Path) -> None:
    """A flag-shaped thought has no action/evidence and is deliberately inert."""

    completion = _Completion()
    sandbox = _Sandbox(tmp_path, flag="CTF{not_read}")
    result = await ReActSolver(
        sandbox=sandbox,
        flag_router=PowerFlagRouter(artifact_root=tmp_path, completer=completion),
    ).solve(
        run_id="run-power-p2",
        archive_digest="b" * 64,
        backend=_ProseOnlyModel(),
    )
    assert result.status == "stopped"
    assert result.reason == "model_stopped_without_action"
    assert completion.calls == 0
    assert completion.solved is False


@pytest.mark.asyncio
async def test_iat_actions_keep_gdb_and_tube_sessions_as_observed_evidence(tmp_path: Path) -> None:
    """P3's action runner exposes live session IDs only from sandbox observations."""

    sandbox = _IatSandbox()
    result = await ReActSolver(
        sandbox=sandbox,
        flag_router=PowerFlagRouter(artifact_root=tmp_path, completer=_Completion()),
    ).solve(run_id="run-power-p3", archive_digest="c" * 64, backend=_IatModel())
    assert result.status == "stopped"
    assert [observation.interactive_kind for observation in result.observations] == [
        "gdb",
        "gdb",
        "tube",
        "tube",
    ]
    assert result.observations[-1].stdout == "pong\n"
    assert sandbox.destroyed == ["ws_0123456789abcdef0123456789abcdef"]


@pytest.mark.asyncio
async def test_router_rejects_candidate_not_present_in_the_observed_artifact(
    tmp_path: Path,
) -> None:
    """Submitting a plausible string without matching CAS bytes cannot solve."""

    completion = _Completion()
    store = LocalArtifactStore(tmp_path)
    artifact = await store.put_bytes(
        b"nothing flag-shaped here\n",
        run_id="run-power-p2",
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )
    accepted = await PowerFlagRouter(artifact_root=tmp_path, completer=completion).submit(
        run_id="run-power-p2",
        candidate="CTF{fabricated_claim}",
        observation_artifact_id=artifact.id,
        observation_sha256=artifact.sha256,
    )
    assert accepted is False
    assert completion.calls == 0
