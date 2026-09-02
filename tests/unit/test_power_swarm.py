"""P4 fixture proofs for bounded briefing, three-racer coordination, and bumps."""

from __future__ import annotations

import asyncio
import hashlib
from base64 import b64encode

import pytest
from ctfmesh_aci import (
    FlagSubmitAction,
    FsReadAction,
    ShellExecAction,
    TubeConnectAction,
    TubeSendAction,
)
from ctfmesh_knowledge import KnowledgeExcerpt, KnowledgeRetrieval, KnowledgeRetrievalMode
from ctfmesh_orchestrator import (
    AUTOPROMPTER_MAX_TURNS,
    AutoPrompter,
    PowerModelAssignment,
    PowerRaceProvider,
    PowerRacerAssignment,
    PowerRacerSpec,
    PowerRacerState,
    PowerRunBudget,
    PowerSwarmCoordinator,
    PowerSwarmState,
)
from ctfmesh_solver_runtime import SandboxObservation, SolverContext, SolverModelError, SolverTurn
from pydantic import SecretStr

_ARCHIVE_DIGEST = hashlib.sha256(b"power-p4-fixture").hexdigest()
_FLAG = "CTF{power_p4_verified_fixture}"
_TUBE_ID = "tube_" + "a" * 32


def _observation(value: str, *, interactive_id: str | None = None) -> SandboxObservation:
    """Create a fake sandbox receipt without putting output in coordinator state."""

    digest = hashlib.sha256(value.encode()).hexdigest()
    return SandboxObservation(
        stdout=value,
        stderr="",
        exit_code=0,
        timed_out=False,
        output_truncated=False,
        stdout_artifact_id=f"sha256:{digest}",
        stdout_sha256=digest,
        interactive_id=interactive_id,
        interactive_kind="tube" if interactive_id is not None else None,
    )


class _Sandbox:
    """Typed fixture sandbox; each factory result represents one workspace."""

    def __init__(self, *, ordinal: int, flag: str = _FLAG) -> None:
        self.workspace_id = f"ws_{ordinal:032x}"
        self.flag = flag
        self.destroyed = False

    async def create(self, *, run_id: str, archive_digest: str) -> str:
        assert run_id == "run-power-p4"
        assert archive_digest == _ARCHIVE_DIGEST
        return self.workspace_id

    async def exec(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> SandboxObservation:
        assert workspace_id == self.workspace_id
        assert timeout_seconds >= 1
        assert working_directory in {"/challenge", "/work"}
        if command[:3] == ("head", "-c", "16384"):
            assert command[-1] == "/challenge/flag.txt"
            return _observation(f"{self.flag}\n")
        return _observation("fixture command observed\n")

    async def pty_start(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P4 fixture does not use PTY")

    async def pty_send_read(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P4 fixture does not use PTY")

    async def pty_close(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P4 fixture does not use PTY")

    async def tube_connect(
        self, workspace_id: str, *, host: str, port: int, timeout_seconds: int
    ) -> SandboxObservation:
        assert workspace_id == self.workspace_id
        assert (host, port, timeout_seconds) == ("challenge.test", 31337, 10)
        return _observation("fixture tube connected\n", interactive_id=_TUBE_ID)

    async def tube_send(self, workspace_id: str, *, tube_id: str, data_base64: str) -> None:
        assert workspace_id == self.workspace_id
        assert tube_id == _TUBE_ID
        assert data_base64 == b64encode(b"probe\n").decode("ascii")

    async def tube_recv_until(self, *args: object, **kwargs: object) -> SandboxObservation:
        raise AssertionError("P4 stall fixture does not receive from tube")

    async def tube_close(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("P4 stall fixture does not close tube")

    async def destroy(self, workspace_id: str) -> None:
        assert workspace_id == self.workspace_id
        self.destroyed = True


class _SandboxFactory:
    def __init__(self) -> None:
        self.workspaces: list[_Sandbox] = []

    def __call__(self) -> _Sandbox:
        workspace = _Sandbox(ordinal=len(self.workspaces) + 1)
        self.workspaces.append(workspace)
        return workspace


class _FixtureFlagRouter:
    """Independent fixture check; it accepts only an observed expected candidate."""

    def __init__(self, expected_flag: str = _FLAG) -> None:
        self._expected_flag = expected_flag
        self.calls = 0

    async def submit(
        self,
        *,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        self.calls += 1
        assert run_id == "run-power-p4"
        assert observation_artifact_id == f"sha256:{observation_sha256}"
        return candidate == self._expected_flag


class _StopModel:
    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        return SolverTurn(action=None)


class _InvalidAfterOneModel:
    """Produce one useful receipt, then emulate a malformed provider action."""

    def __init__(self) -> None:
        self.calls = 0

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        self.calls += 1
        if self.calls == 1:
            return SolverTurn(action=FsReadAction(path="/challenge/flag.txt"))
        raise SolverModelError("solver_model_action_invalid")


class _AlwaysInvalidModel:
    """Emulate a provider that never returns a typed action."""

    def __init__(self) -> None:
        self.calls = 0

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        self.calls += 1
        raise SolverModelError("solver_model_action_invalid")


class _RecordingStopModel(_StopModel):
    """Retain private fixture context only to prove P7 recipient isolation."""

    def __init__(self) -> None:
        self.contexts: list[SolverContext] = []

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self.contexts.append(context)
        return await super().next_turn(context)


class _KnowledgeRetriever:
    """Fixture local-retrieval seam; it has no filesystem or provider access."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def retrieve(self, *, query: str, top_k: int) -> KnowledgeRetrieval:
        self.calls.append((query, top_k))
        return KnowledgeRetrieval(
            mode=KnowledgeRetrievalMode.RETRIEVED,
            corpus_pin=None,
            excerpts=(
                KnowledgeExcerpt(
                    document_id="padding-oracle.md",
                    document_sha256="e" * 64,
                    chunk_index=0,
                    score=20,
                    text="Use an oracle response only as an advisory technique reference.",
                ),
            ),
        )


class _AutoReadModel:
    def __init__(self) -> None:
        self.contexts: list[SolverContext] = []

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self.contexts.append(context)
        if len(self.contexts) == 1:
            return SolverTurn(action=FsReadAction(path="/challenge/flag.txt"))
        return SolverTurn(action=None)


class _ObservedFlagModel:
    def __init__(self) -> None:
        self.contexts: list[SolverContext] = []

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self.contexts.append(context)
        if not context.observations:
            return SolverTurn(action=FsReadAction(path="/challenge/flag.txt"))
        observation = context.observations[-1]
        return SolverTurn(
            action=FlagSubmitAction(
                candidate=SecretStr(_FLAG),
                observation_artifact_id=observation.artifact_id,
                observation_sha256=observation.sha256,
            )
        )


class _SlowModel:
    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        # This simulates a provider currently thinking. The solver checks the
        # coordinator event before it executes this returned action.
        await asyncio.sleep(0.05)
        return SolverTurn(action=ShellExecAction(command=("echo", "sibling")))


class _EndlessShellModel:
    def __init__(self, *, command: tuple[str, ...] = ("echo", "same")) -> None:
        self.command = command
        self.contexts: list[SolverContext] = []

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self.contexts.append(context)
        return SolverTurn(action=ShellExecAction(command=self.command))


class _StalledTubeModel:
    def __init__(self) -> None:
        self.contexts: list[SolverContext] = []

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        self.contexts.append(context)
        turn = len(self.contexts)
        if turn == 1:
            return SolverTurn(action=TubeConnectAction(host="challenge.test", port=31337))
        if 2 <= turn <= 6:
            return SolverTurn(
                action=TubeSendAction(
                    tube_id=context.observations[-1].interactive_id or "",
                    data_base64=b64encode(b"probe\n").decode("ascii"),
                )
            )
        return SolverTurn(action=None)


@pytest.mark.asyncio
async def test_autoprompter_is_limited_to_ten_turns_and_never_submits_flag() -> None:
    factory = _SandboxFactory()
    router = _FixtureFlagRouter()
    brief = await AutoPrompter(sandbox_factory=factory, flag_router=router).prepare(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        backend=_EndlessShellModel(command=("echo", "recon")),
    )

    assert brief.turn_count == AUTOPROMPTER_MAX_TURNS
    assert brief.action_types == ("shell.exec",) * AUTOPROMPTER_MAX_TURNS
    assert brief.finish_reason == "turn_limit_reached"
    assert router.calls == 0
    assert len(factory.workspaces) == 1
    assert factory.workspaces[0].destroyed


@pytest.mark.asyncio
async def test_partial_autoprompter_receipt_still_starts_all_racers() -> None:
    """A late malformed briefing reply cannot leave A/B/C in the queue."""

    factory = _SandboxFactory()
    router = _FixtureFlagRouter()
    briefing = _InvalidAfterOneModel()
    result = await PowerSwarmCoordinator(
        sandbox_factory=factory,
        flag_router=router,
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=briefing,
        racers=(
            PowerRacerSpec(racer_id="racer-a", label="A", backend=_ObservedFlagModel()),
            PowerRacerSpec(racer_id="racer-b", label="B", backend=_SlowModel()),
            PowerRacerSpec(racer_id="racer-c", label="C", backend=_SlowModel()),
        ),
    )

    assert result.state is PowerSwarmState.SOLVED
    assert result.winner_racer_id == "racer-a"
    assert briefing.calls == 4  # first action plus three bounded retry attempts
    assert result.brief.turn_count == 1
    assert len(result.brief.observation_artifact_ids) == 1
    assert "invalid action response" in result.brief.text
    assert len(factory.workspaces) == 4  # AutoPrompter plus all three racers
    states = {racer.racer_id: racer.state for racer in result.racers}
    assert states["racer-a"] is PowerRacerState.SOLVED
    assert states["racer-b"] is PowerRacerState.CANCELLED
    assert states["racer-c"] is PowerRacerState.CANCELLED


@pytest.mark.asyncio
async def test_invalid_racer_actions_are_isolated_and_do_not_remain_queued() -> None:
    """Each malformed racer response is terminal only for that racer."""

    factory = _SandboxFactory()
    models = tuple(_AlwaysInvalidModel() for _ in range(3))
    result = await PowerSwarmCoordinator(
        sandbox_factory=factory,
        flag_router=_FixtureFlagRouter(),
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=_StopModel(),
        racers=tuple(
            PowerRacerSpec(racer_id=f"racer-{label.lower()}", label=label, backend=model)
            for label, model in zip(("A", "B", "C"), models, strict=True)
        ),
    )

    assert result.state is PowerSwarmState.EXHAUSTED
    assert len(factory.workspaces) == 4
    assert all(model.calls == 3 for model in models)
    assert all(
        racer.state is PowerRacerState.STOPPED and racer.reason == "solver_model_action_invalid"
        for racer in result.racers
    )


@pytest.mark.asyncio
async def test_three_racers_cancel_siblings_after_first_verified_flag() -> None:
    factory = _SandboxFactory()
    router = _FixtureFlagRouter()
    autoprompter = _AutoReadModel()
    winner = _ObservedFlagModel()
    coordinator = PowerSwarmCoordinator(sandbox_factory=factory, flag_router=router)
    snapshots = []

    async def record_progress(snapshot: object) -> None:
        # The controller receives only the coordinator's secret-free view.
        assert _FLAG not in repr(snapshot)
        snapshots.append(snapshot)

    result = await asyncio.wait_for(
        coordinator.run(
            run_id="run-power-p4",
            archive_digest=_ARCHIVE_DIGEST,
            autoprompter_backend=autoprompter,
            racers=(
                PowerRacerSpec(racer_id="racer-a", label="A", backend=winner),
                PowerRacerSpec(racer_id="racer-b", label="B", backend=_SlowModel()),
                PowerRacerSpec(racer_id="racer-c", label="C", backend=_SlowModel()),
            ),
            progress_listener=record_progress,
        ),
        timeout=1.0,
    )

    assert result.state is PowerSwarmState.SOLVED
    assert result.winner_racer_id == "racer-a"
    assert router.calls == 1
    assert result.brief.turn_count == 1
    assert _FLAG not in result.brief.text
    states = {racer.racer_id: racer.state for racer in result.racers}
    assert states == {
        "racer-a": PowerRacerState.SOLVED,
        "racer-b": PowerRacerState.CANCELLED,
        "racer-c": PowerRacerState.CANCELLED,
    }
    # One AutoPrompter workspace and one private workspace for each racer.
    assert len(factory.workspaces) == 4
    assert len({workspace.workspace_id for workspace in factory.workspaces}) == 4
    assert all(workspace.destroyed for workspace in factory.workspaces)
    assert result.category_pack.id.value == "web.v1"
    assert all(context.initial_brief.startswith(result.brief.text) for context in winner.contexts)
    assert len(snapshots) >= 3
    assert all(
        "Reviewed category pack (web.v1)" in context.initial_brief for context in winner.contexts
    )
    snapshot = coordinator.snapshot()
    assert snapshot.state is PowerSwarmState.SOLVED
    assert "power_p4_verified_fixture" not in repr(snapshot)


@pytest.mark.asyncio
async def test_duplicate_command_bumps_later_racer_without_command_text_in_snapshot() -> None:
    factory = _SandboxFactory()
    first = _EndlessShellModel()
    duplicate = _EndlessShellModel()
    result = await PowerSwarmCoordinator(
        sandbox_factory=factory,
        flag_router=_FixtureFlagRouter(),
        solver_max_turns=3,
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=_StopModel(),
        racers=(
            PowerRacerSpec(racer_id="racer-a", label="A", backend=first),
            PowerRacerSpec(racer_id="racer-b", label="B", backend=duplicate),
            PowerRacerSpec(racer_id="racer-c", label="C", backend=_StopModel()),
        ),
    )

    racer_b = next(racer for racer in result.racers if racer.racer_id == "racer-b")
    assert result.state is PowerSwarmState.EXHAUSTED
    assert racer_b.state is PowerRacerState.STOPPED
    assert racer_b.bump_count == 1
    assert racer_b.last_command_fingerprint_prefix is not None
    assert "same" not in repr(racer_b)
    assert any(
        "equivalent shell command" in context.coordinator_hint for context in duplicate.contexts
    )


@pytest.mark.asyncio
async def test_five_turn_observation_stall_bumps_racer() -> None:
    factory = _SandboxFactory()
    stalled = _StalledTubeModel()
    result = await PowerSwarmCoordinator(
        sandbox_factory=factory,
        flag_router=_FixtureFlagRouter(),
        solver_max_turns=8,
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=_StopModel(),
        racers=(
            PowerRacerSpec(racer_id="racer-a", label="A", backend=stalled),
            PowerRacerSpec(racer_id="racer-b", label="B", backend=_StopModel()),
            PowerRacerSpec(racer_id="racer-c", label="C", backend=_StopModel()),
        ),
    )

    racer_a = next(racer for racer in result.racers if racer.racer_id == "racer-a")
    assert racer_a.bump_count == 1
    assert racer_a.reason == "model_stopped_without_action"
    assert any(
        "five actions produced no observation" in context.coordinator_hint
        for context in stalled.contexts
    )


@pytest.mark.asyncio
async def test_shared_power_budget_stops_racers_and_keeps_a_per_racer_cost_ledger() -> None:
    """P6 charges AutoPrompter and A/B/C before model I/O under one cap."""

    def assignment(label: str) -> PowerRacerAssignment:
        return PowerRacerAssignment(
            racer_id=f"racer-{label.lower()}",
            label=label,
            model_assignment=PowerModelAssignment(
                provider=PowerRaceProvider.OPENAI_RESPONSES,
                model="gpt-5.6-terra",
                temperature=0.2,
                max_turn_cost_microusd=100,
            ),
        )

    racer_assignments = tuple(assignment(label) for label in ("A", "B", "C"))
    autoprompter_assignment = PowerModelAssignment(
        provider=PowerRaceProvider.OPENAI_RESPONSES,
        model="gpt-5.6-terra",
        temperature=0.2,
        max_turn_cost_microusd=100,
    )
    result = await PowerSwarmCoordinator(
        sandbox_factory=_SandboxFactory(),
        flag_router=_FixtureFlagRouter(),
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=_StopModel(),
        racers=tuple(
            PowerRacerSpec(
                racer_id=racer.racer_id,
                label=racer.label,
                backend=_StopModel(),
                assignment=racer,
            )
            for racer in racer_assignments
        ),
        budget=PowerRunBudget(max_cost_microusd=200, max_wall_time_seconds=60),
        autoprompter_assignment=autoprompter_assignment,
    )

    assert result.state is PowerSwarmState.BUDGET_EXHAUSTED
    assert result.budget is not None
    assert result.budget.spent_cost_microusd == 200
    assert result.budget.exhausted_reason == "power_budget_cost_exhausted"
    assert result.budget.entries[0].subject_id == "autoprompter"
    assert [entry.subject_id for entry in result.budget.entries[1:]] == [
        "racer-a",
        "racer-b",
        "racer-c",
    ]
    subtotals = [
        (total.subject_id, total.reserved_cost_microusd) for total in result.budget.subtotals
    ]
    assert subtotals == [
        ("autoprompter", 100),
        ("racer-a", 100),
    ]
    assert all("fixture-provider" not in repr(item) for item in result.budget.entries)


@pytest.mark.asyncio
async def test_knowledge_is_retrieved_after_brief_and_injected_only_into_selected_racer() -> None:
    """P7 never shares local writeup text with AutoPrompter or sibling racers."""

    retriever = _KnowledgeRetriever()
    racer_a, racer_b, racer_c = _RecordingStopModel(), _RecordingStopModel(), _RecordingStopModel()
    result = await PowerSwarmCoordinator(
        sandbox_factory=_SandboxFactory(),
        flag_router=_FixtureFlagRouter(),
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=_StopModel(),
        racers=(
            PowerRacerSpec(racer_id="racer-a", label="A", backend=racer_a),
            PowerRacerSpec(racer_id="racer-b", label="B", backend=racer_b),
            PowerRacerSpec(racer_id="racer-c", label="C", backend=racer_c),
        ),
        knowledge_retriever=retriever,
        knowledge_recipient_racer_id="racer-b",
    )

    assert retriever.calls == [("web", 3)]
    assert result.knowledge is not None
    assert result.knowledge.mode is KnowledgeRetrievalMode.RETRIEVED
    assert result.knowledge.recipient_racer_id == "racer-b"
    assert result.knowledge.excerpt_count == 1
    assert "padding-oracle" not in repr(result.knowledge)
    assert "Local knowledge references" not in racer_a.contexts[0].initial_brief
    assert "Local knowledge references" in racer_b.contexts[0].initial_brief
    assert "Local knowledge references" not in racer_c.contexts[0].initial_brief
    assert "Local knowledge references" not in repr(result)


@pytest.mark.asyncio
async def test_contest_offline_does_not_call_retriever_or_inject_knowledge() -> None:
    """P7's contest gate has precedence even when a retriever was configured."""

    retriever = _KnowledgeRetriever()
    racer_a, racer_b, racer_c = _RecordingStopModel(), _RecordingStopModel(), _RecordingStopModel()
    result = await PowerSwarmCoordinator(
        sandbox_factory=_SandboxFactory(),
        flag_router=_FixtureFlagRouter(),
    ).run(
        run_id="run-power-p4",
        archive_digest=_ARCHIVE_DIGEST,
        autoprompter_backend=_StopModel(),
        racers=(
            PowerRacerSpec(racer_id="racer-a", label="A", backend=racer_a),
            PowerRacerSpec(racer_id="racer-b", label="B", backend=racer_b),
            PowerRacerSpec(racer_id="racer-c", label="C", backend=racer_c),
        ),
        knowledge_retriever=retriever,
        knowledge_recipient_racer_id="racer-a",
        contest_offline=True,
    )

    assert retriever.calls == []
    assert result.knowledge is not None
    assert result.knowledge.mode is KnowledgeRetrievalMode.CONTEST_OFFLINE
    assert result.knowledge.excerpt_count == 0
    assert all(
        "Local knowledge references" not in racer.contexts[0].initial_brief
        for racer in (
            racer_a,
            racer_b,
            racer_c,
        )
    )
