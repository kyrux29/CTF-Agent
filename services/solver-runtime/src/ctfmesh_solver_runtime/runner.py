"""Evidence-only, one-action-per-turn solver loop for Power P2.

The model produces one typed action.  The runner obtains every observation
from `sandboxd`; it never accepts model-provided output.  A flag action is
forwarded to a separate router which is responsible for reading the immutable
artifact again and deciding whether a run may become solved.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from ctfmesh_aci import (
    FlagSubmitAction,
    FsListAction,
    FsReadAction,
    FsWriteAction,
    GdbCloseAction,
    GdbCmdAction,
    GdbStartAction,
    PtyCloseAction,
    PtyReadAction,
    PtySendAction,
    PtyStartAction,
    ShellExecAction,
    TubeCloseAction,
    TubeConnectAction,
    TubeRecvUntilAction,
    TubeSendAction,
)
from ctfmesh_aci.contracts import SolverAction

_MAX_BRIEF_CHARS = 8_000
_MAX_SUMMARY_CHARS = 4_000
_MAX_COORDINATOR_HINT_CHARS = 2_000


@dataclass(frozen=True, slots=True)
class SandboxObservation:
    """A secret-bearing payload that exists only in the active solver turn."""

    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    output_truncated: bool
    stdout_artifact_id: str
    stdout_sha256: str
    # Artifact metadata is evidence-bound and lets a downstream custom-tool
    # contract refer to the raw CAS object without copying the raw output.
    stdout_artifact_size_bytes: int = 0
    interactive_id: str | None = None
    interactive_kind: str | None = None
    # ``sandboxd`` keeps stderr in a separate immutable artifact for normal
    # exec calls.  Keep only its reference here so consumers can preserve the
    # complete observed result without copying raw output into the ledger.
    stderr_artifact_id: str | None = None
    stderr_sha256: str | None = None
    stderr_artifact_size_bytes: int = 0


@dataclass(frozen=True, slots=True)
class SolverObservation:
    """Safe context supplied to the next turn; raw output remains bounded."""

    sequence: int
    action_type: str
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    output_truncated: bool
    artifact_id: str
    sha256: str
    interactive_id: str | None = None
    interactive_kind: str | None = None


@dataclass(frozen=True, slots=True)
class SolverContext:
    """Bounded evidence context for one model turn, never a durable record."""

    initial_brief: str
    observation_summary: str
    observations: tuple[SolverObservation, ...]
    # This is an ephemeral nudge from P4's local coordinator. It must never
    # replace observations as evidence and is deliberately not persisted.
    coordinator_hint: str = ""


@dataclass(frozen=True, slots=True)
class SolverTurn:
    """A model's private thought is never put into the ledger or result."""

    action: SolverAction | None
    thought: str = ""


@dataclass(frozen=True, slots=True)
class SolverResult:
    status: str
    observations: tuple[SolverObservation, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class SolverTurnTelemetry:
    """Secret-free fact emitted after one solver action has completed.

    The coordinator only needs to schedule racers; it does not need command
    text or tool output. A SHA-256 command fingerprint permits duplicate-work
    detection without putting a potentially sensitive command into a ledger
    or UI read model.
    """

    sequence: int
    action_type: str
    command_fingerprint: str | None
    observation_received: bool
    # A reviewed, fixed-vocabulary activity label gives the operator useful
    # live context without persisting model thoughts, command arguments,
    # challenge paths, request payloads, or a flag candidate.
    action_summary: str = ""
    # This immutable reference proves that an observation exists without
    # copying its potentially secret-bearing content into the event ledger.
    observation_artifact_id: str | None = None


TurnTelemetryListener = Callable[[SolverTurnTelemetry], Awaitable[None]]
CoordinatorHintProvider = Callable[[], str]


class ModelBackend(Protocol):
    """Provider adapter seam; P2's CI uses a deterministic fixture backend."""

    async def next_turn(self, context: SolverContext) -> SolverTurn: ...


class Sandbox(Protocol):
    """The solver knows only typed P1 methods, never a Docker client/socket."""

    async def create(self, *, run_id: str, archive_digest: str) -> str: ...

    async def exec(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> SandboxObservation: ...

    async def pty_start(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
        kind: str,
    ) -> SandboxObservation: ...

    async def pty_send_read(
        self,
        workspace_id: str,
        *,
        pty_id: str,
        data: str,
        max_bytes: int,
        wait_ms: int,
        kind: str,
    ) -> SandboxObservation: ...

    async def pty_close(self, workspace_id: str, *, pty_id: str) -> None: ...

    async def tube_connect(
        self,
        workspace_id: str,
        *,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> SandboxObservation: ...

    async def tube_send(
        self,
        workspace_id: str,
        *,
        tube_id: str,
        data_base64: str,
    ) -> None: ...

    async def tube_recv_until(
        self,
        workspace_id: str,
        *,
        tube_id: str,
        delimiter_base64: str,
        max_bytes: int,
        timeout_seconds: int,
    ) -> SandboxObservation: ...

    async def tube_close(self, workspace_id: str, *, tube_id: str) -> None: ...

    async def destroy(self, workspace_id: str) -> None: ...


class FlagRouter(Protocol):
    """Independent boundary that alone can accept an observed candidate."""

    async def submit(
        self,
        *,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool: ...


class ReActSolver:
    """Drive exactly one action per turn until independent flag verification."""

    def __init__(
        self,
        *,
        sandbox: Sandbox,
        flag_router: FlagRouter,
        max_turns: int = 32,
        context_observation_limit: int = 8,
        initial_brief: str = "",
        allow_flag_submission: bool = True,
        cancellation: asyncio.Event | None = None,
        coordinator_hint_provider: CoordinatorHintProvider | None = None,
        on_turn_telemetry: TurnTelemetryListener | None = None,
    ) -> None:
        if not 1 <= max_turns <= 512:
            raise ValueError("solver_max_turns_invalid")
        if not 1 <= context_observation_limit <= 64:
            raise ValueError("solver_context_observation_limit_invalid")
        if len(initial_brief) > _MAX_BRIEF_CHARS:
            raise ValueError("solver_initial_brief_too_large")
        if not isinstance(allow_flag_submission, bool):
            raise ValueError("solver_allow_flag_submission_invalid")
        self._sandbox = sandbox
        self._flag_router = flag_router
        self._max_turns = max_turns
        self._context_observation_limit = context_observation_limit
        self._initial_brief = initial_brief
        # AutoPrompter has exactly the same typed action surface as a racer,
        # but has no completion authority. This guard keeps a reconnaissance
        # pass from accidentally consuming the only accepted flag submission.
        self._allow_flag_submission = allow_flag_submission
        self._cancellation = cancellation
        self._coordinator_hint_provider = coordinator_hint_provider
        self._on_turn_telemetry = on_turn_telemetry

    async def solve(
        self,
        *,
        run_id: str,
        archive_digest: str,
        backend: ModelBackend,
    ) -> SolverResult:
        """Create a private workspace, execute typed actions, then always clean up."""

        workspace_id = await self._sandbox.create(run_id=run_id, archive_digest=archive_digest)
        observations: list[SolverObservation] = []
        sessions: dict[str, str] = {}
        try:
            for sequence in range(1, self._max_turns + 1):
                if self._is_cancelled():
                    return SolverResult("cancelled", tuple(observations), "coordinator_cancelled")
                context = self._context(observations)
                try:
                    turn = await backend.next_turn(context)
                except Exception as exc:
                    # A provider can return a malformed action after useful
                    # observations. Preserve that partial receipt-only result
                    # so the coordinator can still launch independent racers.
                    # Other failures (sandbox, budget, cancellation) retain
                    # their existing authority and continue to propagate.
                    if getattr(exc, "code", None) == "solver_model_action_invalid":
                        return SolverResult(
                            "stopped", tuple(observations), "solver_model_action_invalid"
                        )
                    raise
                if self._is_cancelled():
                    return SolverResult("cancelled", tuple(observations), "coordinator_cancelled")
                if turn.action is None:
                    # Assistant prose, including text that looks like a flag,
                    # has no execution or completion authority.
                    return SolverResult(
                        "stopped", tuple(observations), "model_stopped_without_action"
                    )
                action = turn.action
                if isinstance(action, FlagSubmitAction):
                    await self._emit_telemetry(
                        SolverTurnTelemetry(
                            sequence=sequence,
                            action_type=action.type,
                            command_fingerprint=None,
                            observation_received=False,
                            action_summary=_safe_action_summary(action),
                        )
                    )
                    if not self._allow_flag_submission:
                        return SolverResult(
                            "stopped", tuple(observations), "flag_submission_disabled"
                        )
                    accepted = await self._flag_router.submit(
                        run_id=run_id,
                        candidate=action.candidate.get_secret_value(),
                        observation_artifact_id=action.observation_artifact_id,
                        observation_sha256=action.observation_sha256,
                    )
                    # Remove the short-lived plaintext candidate as soon as the
                    # router call returns; it never enters SolverResult.
                    candidate = ""
                    del candidate
                    if accepted:
                        return SolverResult("solved", tuple(observations), "flag_router_verified")
                    return SolverResult("stopped", tuple(observations), "flag_router_rejected")
                observation = await self._execute_action(workspace_id, action, sessions)
                if observation is not None:
                    observations.append(self._observation(sequence, action.type, observation))
                await self._emit_telemetry(
                    SolverTurnTelemetry(
                        sequence=sequence,
                        action_type=action.type,
                        command_fingerprint=_command_fingerprint(action),
                        observation_received=observation is not None,
                        action_summary=_safe_action_summary(action),
                        observation_artifact_id=(
                            observation.stdout_artifact_id if observation is not None else None
                        ),
                    )
                )
                if self._is_cancelled():
                    return SolverResult("cancelled", tuple(observations), "coordinator_cancelled")
        finally:
            await self._sandbox.destroy(workspace_id)
        return SolverResult("stopped", tuple(observations), "turn_limit_reached")

    async def _execute_action(
        self,
        workspace_id: str,
        action: SolverAction,
        sessions: dict[str, str],
    ) -> SandboxObservation | None:
        if isinstance(action, ShellExecAction):
            return await self._sandbox.exec(
                workspace_id,
                command=action.command,
                timeout_seconds=action.timeout_seconds,
                working_directory=action.working_directory,
            )
        if isinstance(action, FsListAction):
            return await self._sandbox.exec(
                workspace_id,
                command=(
                    "find",
                    action.path,
                    "-maxdepth",
                    "1",
                    "-mindepth",
                    "1",
                    "-printf",
                    "%f\\n",
                ),
                timeout_seconds=30,
                working_directory="/work",
            )
        if isinstance(action, FsReadAction):
            return await self._sandbox.exec(
                workspace_id,
                command=("head", "-c", str(action.max_bytes), action.path),
                timeout_seconds=30,
                working_directory="/work",
            )
        if isinstance(action, PtyStartAction):
            observation = await self._sandbox.pty_start(
                workspace_id,
                command=action.command,
                timeout_seconds=action.timeout_seconds,
                working_directory=action.working_directory,
                kind="pty",
            )
            if observation.interactive_id is None:
                raise RuntimeError("sandboxd_pty_protocol_invalid")
            sessions[observation.interactive_id] = "pty"
            return observation
        if isinstance(action, PtySendAction):
            self._require_session(sessions, action.pty_id, "pty")
            return await self._sandbox.pty_send_read(
                workspace_id,
                pty_id=action.pty_id,
                data=action.data,
                max_bytes=16 * 1024,
                wait_ms=500,
                kind="pty",
            )
        if isinstance(action, PtyReadAction):
            self._require_session(sessions, action.pty_id, "pty")
            return await self._sandbox.pty_send_read(
                workspace_id,
                pty_id=action.pty_id,
                data="",
                max_bytes=action.max_bytes,
                wait_ms=action.wait_ms,
                kind="pty",
            )
        if isinstance(action, PtyCloseAction):
            self._require_session(sessions, action.pty_id, "pty")
            await self._sandbox.pty_close(workspace_id, pty_id=action.pty_id)
            sessions.pop(action.pty_id, None)
            return None
        if isinstance(action, GdbStartAction):
            observation = await self._sandbox.pty_start(
                workspace_id,
                command=("gdb", "--quiet", "--nx", action.path),
                timeout_seconds=action.timeout_seconds,
                working_directory="/challenge",
                kind="gdb",
            )
            if observation.interactive_id is None:
                raise RuntimeError("sandboxd_gdb_protocol_invalid")
            sessions[observation.interactive_id] = "gdb"
            return observation
        if isinstance(action, GdbCmdAction):
            self._require_session(sessions, action.gdb_id, "gdb")
            return await self._sandbox.pty_send_read(
                workspace_id,
                pty_id=action.gdb_id,
                data=f"{action.command}\n",
                max_bytes=16 * 1024,
                wait_ms=1_000,
                kind="gdb",
            )
        if isinstance(action, GdbCloseAction):
            self._require_session(sessions, action.gdb_id, "gdb")
            await self._sandbox.pty_close(workspace_id, pty_id=action.gdb_id)
            sessions.pop(action.gdb_id, None)
            return None
        if isinstance(action, TubeConnectAction):
            observation = await self._sandbox.tube_connect(
                workspace_id,
                host=action.host,
                port=action.port,
                timeout_seconds=action.timeout_seconds,
            )
            if observation.interactive_id is None:
                raise RuntimeError("sandboxd_tube_protocol_invalid")
            sessions[observation.interactive_id] = "tube"
            return observation
        if isinstance(action, TubeSendAction):
            self._require_session(sessions, action.tube_id, "tube")
            await self._sandbox.tube_send(
                workspace_id, tube_id=action.tube_id, data_base64=action.data_base64
            )
            return None
        if isinstance(action, TubeRecvUntilAction):
            self._require_session(sessions, action.tube_id, "tube")
            return await self._sandbox.tube_recv_until(
                workspace_id,
                tube_id=action.tube_id,
                delimiter_base64=action.delimiter_base64,
                max_bytes=action.max_bytes,
                timeout_seconds=action.timeout_seconds,
            )
        if isinstance(action, TubeCloseAction):
            self._require_session(sessions, action.tube_id, "tube")
            await self._sandbox.tube_close(workspace_id, tube_id=action.tube_id)
            sessions.pop(action.tube_id, None)
            return None
        if isinstance(action, FsWriteAction):
            # A file write is passed as argv stdin-free data, so no command
            # shell re-parses model content. The workspace path was validated
            # by the ACI contract before reaching this fixed command template.
            return await self._sandbox.exec(
                workspace_id,
                command=(
                    "sh",
                    "-c",
                    'printf %s "$1" > "$2"',
                    "ctfmesh",
                    action.content,
                    action.path,
                ),
                timeout_seconds=30,
                working_directory="/work",
            )
        raise RuntimeError("solver_action_not_executable")

    @staticmethod
    def _require_session(sessions: dict[str, str], identifier: str, expected: str) -> None:
        """Do not let a model reuse an identifier across interactive tool kinds."""

        if sessions.get(identifier) != expected:
            raise RuntimeError("interactive_session_not_owned")

    @staticmethod
    def _observation(
        sequence: int,
        action_type: str,
        observed: SandboxObservation,
    ) -> SolverObservation:
        # The router independently re-reads the raw CAS bytes before a flag
        # can be accepted. This loop deliberately does not recreate a digest
        # from decoded text: a valid command observation may be binary.
        return SolverObservation(
            sequence=sequence,
            action_type=action_type,
            stdout=observed.stdout,
            stderr=observed.stderr,
            exit_code=observed.exit_code,
            timed_out=observed.timed_out,
            output_truncated=observed.output_truncated,
            artifact_id=observed.stdout_artifact_id,
            sha256=observed.stdout_sha256,
            interactive_id=observed.interactive_id,
            interactive_kind=observed.interactive_kind,
        )

    def _context(self, observations: list[SolverObservation]) -> SolverContext:
        """Keep recent evidence verbatim-ish and compress only older output.

        The summary is a deterministic compression of tool evidence, not a
        model inference. It therefore cannot invent an observation while still
        giving a long-running solver useful prior command state.
        """

        split_at = max(0, len(observations) - self._context_observation_limit)
        older = observations[:split_at]
        recent = tuple(observations[split_at:])
        return SolverContext(
            initial_brief=self._initial_brief,
            observation_summary=_summarize_observations(older),
            observations=recent,
            coordinator_hint=self._coordinator_hint(),
        )

    def _is_cancelled(self) -> bool:
        """Check the optional P4 cooperative cancellation signal."""

        return self._cancellation is not None and self._cancellation.is_set()

    def _coordinator_hint(self) -> str:
        """Get a small, transient scheduling hint without trusting it as evidence."""

        if self._coordinator_hint_provider is None:
            return ""
        hint = self._coordinator_hint_provider()
        if not isinstance(hint, str) or len(hint) > _MAX_COORDINATOR_HINT_CHARS:
            raise RuntimeError("solver_coordinator_hint_invalid")
        return hint

    async def _emit_telemetry(self, telemetry: SolverTurnTelemetry) -> None:
        """Notify the in-process coordinator after an action has taken effect."""

        if self._on_turn_telemetry is not None:
            await self._on_turn_telemetry(telemetry)


def _summarize_observations(observations: list[SolverObservation]) -> str:
    """Render only bounded, observed output from context that has aged out."""

    if not observations:
        return ""
    lines: list[str] = []
    remaining = _MAX_SUMMARY_CHARS
    for observation in observations:
        header = (
            f"#{observation.sequence} {observation.action_type} "
            f"exit={observation.exit_code!s} timeout={observation.timed_out} "
            f"artifact={observation.artifact_id}"
        )
        detail = _summarize_iat_output(observation, max_chars=512)
        item = f"{header}\n{detail}" if detail else header
        if len(item) > remaining:
            lines.append(item[:remaining])
            break
        lines.append(item)
        remaining -= len(item) + 1
        if remaining <= 0:
            break
    return "\n".join(lines)


def _command_fingerprint(action: SolverAction) -> str | None:
    """Return an in-memory fingerprint for shell diversity, never the command itself."""

    if not isinstance(action, ShellExecAction):
        return None
    encoded = "\x00".join(action.command).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_action_summary(action: SolverAction) -> str:
    """Describe a typed action without serializing untrusted action content.

    The model controls command arguments, file names, interactive input and
    candidate values. A fixed label tells an authorized operator which class
    of work is active while preserving the trace's no-secret/no-transcript
    contract.
    """

    if isinstance(action, FsListAction):
        return "Mapping workspace files."
    if isinstance(action, FsReadAction):
        return "Reading one challenge file."
    if isinstance(action, FsWriteAction):
        return "Saving a derived work file."
    if isinstance(action, ShellExecAction):
        return "Running a bounded analysis command."
    if isinstance(action, PtyStartAction):
        return "Opening an interactive analysis tool."
    if isinstance(action, PtySendAction):
        return "Sending bounded input to an analysis tool."
    if isinstance(action, PtyReadAction):
        return "Reading an interactive analysis result."
    if isinstance(action, PtyCloseAction):
        return "Closing an interactive analysis tool."
    if isinstance(action, GdbStartAction):
        return "Starting a debugger for the challenge binary."
    if isinstance(action, GdbCmdAction):
        return "Inspecting the binary in the debugger."
    if isinstance(action, GdbCloseAction):
        return "Closing the debugger session."
    if isinstance(action, TubeConnectAction):
        return "Connecting to the declared target."
    if isinstance(action, TubeSendAction):
        return "Sending scoped input to the declared target."
    if isinstance(action, TubeRecvUntilAction):
        return "Reading a scoped target response."
    if isinstance(action, TubeCloseAction):
        return "Closing the target connection."
    if isinstance(action, FlagSubmitAction):
        return "Submitting an observed candidate for independent verification."
    raise AssertionError("solver_action_summary_unknown")


def _bounded_text(value: str, *, max_chars: int) -> str:
    """Retain both ends of a command output without pretending it is complete."""

    if len(value) <= max_chars:
        return value
    head_length = max_chars // 2
    tail_length = max_chars - head_length
    return f"{value[:head_length]}\n…[output truncated for context]…\n{value[-tail_length:]}"


def _summarize_iat_output(observation: SolverObservation, *, max_chars: int) -> str:
    """Keep evidence, but avoid letting a long GDB backtrace crowd out all context."""

    value = observation.stdout + observation.stderr
    if observation.interactive_kind != "gdb":
        return _bounded_text(value, max_chars=max_chars)
    frames = [line for line in value.splitlines() if line.lstrip().startswith("#")]
    if len(frames) > 12:
        value = "\n".join([*frames[:6], "…[backtrace frames omitted]…", *frames[-6:]])
    return _bounded_text(value, max_chars=max_chars)


__all__ = [
    "FlagRouter",
    "ModelBackend",
    "ReActSolver",
    "Sandbox",
    "SandboxObservation",
    "SolverContext",
    "SolverObservation",
    "SolverResult",
    "SolverTurnTelemetry",
    "SolverTurn",
    "CoordinatorHintProvider",
    "TurnTelemetryListener",
]
