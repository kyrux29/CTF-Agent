"""P4 coordination for three isolated Power ReAct racers.

This module deliberately owns scheduling only.  It cannot call Docker, open a
target connection, read an artifact, or transition a durable run to ``solved``.
Those powers remain with sandboxd and flag-router.  Its in-memory snapshots are
safe for a later UI because they omit model thought, command text, tool output,
credentials, and flags.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum

from ctfmesh_knowledge import (
    KnowledgeRetrieval,
    KnowledgeRetrievalMode,
    KnowledgeRetriever,
    render_knowledge_context,
)
from ctfmesh_solver_runtime import (
    FlagRouter,
    ModelBackend,
    ReActSolver,
    Sandbox,
    SolverContext,
    SolverModelError,
    SolverResult,
    SolverTurn,
    SolverTurnTelemetry,
)

from .category_packs import (
    CategoryPack,
    CategoryPackId,
    category_signals_from_observations,
    select_category_pack,
)
from .power_budget import (
    BudgetedModelBackend,
    PowerBudgetError,
    PowerBudgetLedger,
    PowerBudgetSnapshot,
    PowerRunBudget,
)
from .power_race import PowerModelAssignment, PowerRacerAssignment

AUTOPROMPTER_MAX_TURNS = 10
POWER_RACER_COUNT = 3
POWER_RACER_GRACE_SECONDS = 5.0
POWER_KNOWLEDGE_TOP_K = 3
POWER_MODEL_PROTOCOL_RETRIES = 2
_BRIEF_MAX_ARTIFACTS = 10
_FINGERPRINT_PREVIEW_CHARS = 12
_MAX_RETRY_HINT_CHARS = 2_000
_MODEL_RETRY_HINT = (
    "The previous response did not match the action schema. Return exactly one JSON action "
    "object; do not include markdown, prose, or private reasoning in the final content."
)

# The control plane may persist this already-sanitized snapshot as an
# append-only activity record.  It is deliberately a snapshot callback rather
# than a transcript hook: model thought, command arguments, tool output,
# credentials and flags never cross this boundary.
PowerProgressListener = Callable[["PowerSwarmSnapshot"], Awaitable[None]]


class PowerRacerState(StrEnum):
    """The current lifecycle of one P4 racer, suitable for a progress pane."""

    QUEUED = "queued"
    RUNNING = "running"
    BUMPED = "bumped"
    CANCELLED = "cancelled"
    SOLVED = "solved"
    STOPPED = "stopped"
    FAILED = "failed"


class PowerSwarmState(StrEnum):
    """High-level coordinator state exposed by the secret-free read model."""

    IDLE = "idle"
    BRIEFING = "briefing"
    RACING = "racing"
    SOLVED = "solved"
    EXHAUSTED = "exhausted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PowerKnowledgeProgress:
    """Safe retrieval metadata; local writeup text never enters this read model."""

    mode: KnowledgeRetrievalMode
    recipient_racer_id: str
    corpus_sha256: str | None
    excerpt_count: int


@dataclass(frozen=True, slots=True)
class PowerRacerSpec:
    """One reviewed model adapter assigned to a visible A/B/C racer slot."""

    racer_id: str
    label: str
    backend: ModelBackend
    # This mapping contains reviewed provider/model metadata and an upper
    # cost bound only.  In particular, a provider key is never part of a spec.
    assignment: PowerRacerAssignment | None = None


@dataclass(frozen=True, slots=True)
class AutoPromptBrief:
    """Safe reconnaissance hand-off shared with every independently-run racer."""

    text: str
    action_types: tuple[str, ...]
    observation_artifact_ids: tuple[str, ...]
    turn_count: int
    finish_reason: str
    # Signals are fixed category labels derived in memory. They never contain
    # the raw observation that led to the classification.
    category_signals: tuple[CategoryPackId, ...] = ()


@dataclass(frozen=True, slots=True)
class PowerRacerProgress:
    """Secret-free current state for one racer; no transcript is retained here."""

    racer_id: str
    label: str
    provider: str | None
    model: str | None
    temperature: float | None
    state: PowerRacerState
    last_action_type: str | None
    last_command_fingerprint_prefix: str | None
    turn_count: int
    observation_count: int
    bump_count: int
    reason: str | None
    last_action_summary: str | None = None
    last_observation_received: bool | None = None
    last_observation_artifact_id: str | None = None


@dataclass(frozen=True, slots=True)
class PowerSwarmSnapshot:
    """Immutable UI/read-model projection for the three active racer boxes."""

    state: PowerSwarmState
    brief: AutoPromptBrief | None
    category_pack: CategoryPack | None
    winner_racer_id: str | None
    racers: tuple[PowerRacerProgress, ...]
    budget: PowerBudgetSnapshot | None
    knowledge: PowerKnowledgeProgress | None


@dataclass(frozen=True, slots=True)
class PowerSwarmResult:
    """Terminal coordinator outcome; flag material is intentionally absent."""

    state: PowerSwarmState
    winner_racer_id: str | None
    brief: AutoPromptBrief
    category_pack: CategoryPack
    racers: tuple[PowerRacerProgress, ...]
    budget: PowerBudgetSnapshot | None
    knowledge: PowerKnowledgeProgress | None


@dataclass(slots=True)
class _RacerControl:
    """Private mutable state owned by the coordinator event loop."""

    spec: PowerRacerSpec
    state: PowerRacerState = PowerRacerState.QUEUED
    last_action_type: str | None = None
    last_action_summary: str | None = None
    last_command_fingerprint: str | None = None
    last_observation_received: bool | None = None
    last_observation_artifact_id: str | None = None
    turn_count: int = 0
    observation_count: int = 0
    consecutive_unobserved_turns: int = 0
    bump_count: int = 0
    reason: str | None = None
    _hints: dict[str, str] = field(default_factory=dict)

    def coordinator_hint(self) -> str:
        """Return bounded operational directions without converting them to evidence."""

        return "\n".join(self._hints.values())

    def snapshot(self) -> PowerRacerProgress:
        """Project only values safe enough for the future UI progress view."""

        fingerprint = self.last_command_fingerprint
        return PowerRacerProgress(
            racer_id=self.spec.racer_id,
            label=self.spec.label,
            provider=(
                self.spec.assignment.model_assignment.provider.value
                if self.spec.assignment is not None
                else None
            ),
            model=(
                self.spec.assignment.model_assignment.model
                if self.spec.assignment is not None
                else None
            ),
            temperature=(
                self.spec.assignment.model_assignment.temperature
                if self.spec.assignment is not None
                else None
            ),
            state=self.state,
            last_action_type=self.last_action_type,
            last_command_fingerprint_prefix=(
                fingerprint[:_FINGERPRINT_PREVIEW_CHARS] if fingerprint is not None else None
            ),
            turn_count=self.turn_count,
            observation_count=self.observation_count,
            bump_count=self.bump_count,
            reason=self.reason,
            last_action_summary=self.last_action_summary,
            last_observation_received=self.last_observation_received,
            last_observation_artifact_id=self.last_observation_artifact_id,
        )


class AutoPrompter:
    """Perform at most ten evidence-only reconnaissance turns before a race."""

    def __init__(
        self,
        *,
        sandbox_factory: Callable[[], Sandbox],
        flag_router: FlagRouter,
        max_turns: int = AUTOPROMPTER_MAX_TURNS,
    ) -> None:
        if not 1 <= max_turns <= AUTOPROMPTER_MAX_TURNS:
            raise ValueError("autoprompter_max_turns_invalid")
        self._sandbox_factory = sandbox_factory
        self._flag_router = flag_router
        self._max_turns = max_turns

    async def prepare(
        self,
        *,
        run_id: str,
        archive_digest: str,
        backend: ModelBackend,
    ) -> AutoPromptBrief:
        """Run a bounded discovery pass and render a receipt-only shared brief."""

        action_types: list[str] = []

        async def record_turn(telemetry: SolverTurnTelemetry) -> None:
            action_types.append(telemetry.action_type)

        result = await ReActSolver(
            sandbox=self._sandbox_factory(),
            flag_router=self._flag_router,
            max_turns=self._max_turns,
            initial_brief=(
                "Perform a short reconnaissance pass for an authorized CTF archive. "
                "Use typed actions only. Do not submit a flag; later racers must "
                "independently reproduce all evidence."
            ),
            allow_flag_submission=False,
            on_turn_telemetry=record_turn,
        ).solve(run_id=run_id, archive_digest=archive_digest, backend=backend)
        return _receipt_only_brief(result, tuple(action_types))


class PowerSwarmCoordinator:
    """Coordinate exactly three independent ReAct racers from one safe brief."""

    def __init__(
        self,
        *,
        sandbox_factory: Callable[[], Sandbox],
        flag_router: FlagRouter,
        solver_max_turns: int = 32,
        sibling_grace_seconds: float = POWER_RACER_GRACE_SECONDS,
    ) -> None:
        if not 1 <= solver_max_turns <= 512:
            raise ValueError("power_swarm_solver_max_turns_invalid")
        if not 0 < sibling_grace_seconds <= POWER_RACER_GRACE_SECONDS:
            raise ValueError("power_swarm_sibling_grace_invalid")
        self._sandbox_factory = sandbox_factory
        self._flag_router = flag_router
        self._solver_max_turns = solver_max_turns
        # The production default is the plan's five-second ledger flush. Tests
        # can use a smaller bounded value only to prove the forced-cancel path.
        self._sibling_grace_seconds = sibling_grace_seconds
        self._state = PowerSwarmState.IDLE
        self._brief: AutoPromptBrief | None = None
        self._category_pack: CategoryPack | None = None
        self._winner_racer_id: str | None = None
        self._controls: dict[str, _RacerControl] = {}
        self._first_command_owner: dict[str, str] = {}
        self._budget_ledger: PowerBudgetLedger | None = None
        self._knowledge_retriever: KnowledgeRetriever | None = None
        self._knowledge_recipient_racer_id: str | None = None
        self._knowledge_context = ""
        self._knowledge_progress: PowerKnowledgeProgress | None = None
        self._contest_offline = False
        self._knowledge_top_k = POWER_KNOWLEDGE_TOP_K
        self._progress_listener: PowerProgressListener | None = None

    def snapshot(self) -> PowerSwarmSnapshot:
        """Return a stable, secret-free projection without waiting on model I/O."""

        return PowerSwarmSnapshot(
            state=self._state,
            brief=self._brief,
            category_pack=self._category_pack,
            winner_racer_id=self._winner_racer_id,
            racers=tuple(control.snapshot() for control in self._controls.values()),
            budget=self._budget_ledger.snapshot() if self._budget_ledger is not None else None,
            knowledge=self._knowledge_progress,
        )

    async def run(
        self,
        *,
        run_id: str,
        archive_digest: str,
        autoprompter_backend: ModelBackend,
        racers: tuple[PowerRacerSpec, ...],
        budget: PowerRunBudget | None = None,
        autoprompter_assignment: PowerModelAssignment | None = None,
        knowledge_retriever: KnowledgeRetriever | None = None,
        knowledge_recipient_racer_id: str | None = None,
        contest_offline: bool = False,
        knowledge_top_k: int = POWER_KNOWLEDGE_TOP_K,
        progress_listener: PowerProgressListener | None = None,
    ) -> PowerSwarmResult:
        """Prepare one receipt-only brief then race three isolated workspaces."""

        if self._state in {PowerSwarmState.BRIEFING, PowerSwarmState.RACING}:
            raise RuntimeError("power_swarm_run_already_active")
        self._prepare_run(
            racers,
            budget=budget,
            autoprompter_assignment=autoprompter_assignment,
            knowledge_retriever=knowledge_retriever,
            knowledge_recipient_racer_id=knowledge_recipient_racer_id,
            contest_offline=contest_offline,
            knowledge_top_k=knowledge_top_k,
            progress_listener=progress_listener,
        )
        self._state = PowerSwarmState.BRIEFING
        await self._publish_progress()
        try:
            self._brief = await AutoPrompter(
                sandbox_factory=self._sandbox_factory,
                flag_router=self._flag_router,
            ).prepare(
                run_id=run_id,
                archive_digest=archive_digest,
                backend=_RetryingModelBackend(
                    self._budgeted_autoprompter_backend(
                        autoprompter_backend,
                        autoprompter_assignment,
                    )
                ),
            )
            # This happens only after the bounded reconnaissance pass. The
            # selected pack is trusted local guidance, not a model decision
            # and not a substitute for sandbox observations.
            self._category_pack = select_category_pack(
                action_types=self._brief.action_types,
                category_signals=self._brief.category_signals,
            )
            await self._prepare_knowledge()
            await self._publish_progress()
        except PowerBudgetError as exc:
            # A failed preflight model call is not a solver failure.  It has no
            # evidence to share, so retain an empty receipt-only brief and a
            # distinct terminal state rather than inventing a category.
            self._brief = _budget_exhausted_brief(exc.code)
            self._category_pack = select_category_pack(action_types=(), category_signals=())
            self._mark_queued_racers_stopped(exc.code)
            self._state = PowerSwarmState.BUDGET_EXHAUSTED
            await self._publish_progress()
            return self._result()
        except Exception:
            self._state = PowerSwarmState.FAILED
            raise

        cancellation = asyncio.Event()
        winner_gate = _FirstVerifiedFlagGate(
            delegate=self._flag_router,
            cancellation=cancellation,
        )
        self._state = PowerSwarmState.RACING
        await self._publish_progress()
        tasks = {
            asyncio.create_task(
                self._run_racer(
                    run_id=run_id,
                    archive_digest=archive_digest,
                    control=control,
                    flag_router=_RacerFlagRouter(
                        racer_id=racer_id,
                        winner_gate=winner_gate,
                    ),
                    cancellation=cancellation,
                ),
                name=f"ctfmesh-power-{racer_id}",
            ): racer_id
            for racer_id, control in self._controls.items()
        }
        pending = set(tasks)
        try:
            while pending:
                complete, pending = await asyncio.wait(
                    pending,
                    timeout=(
                        self._budget_ledger.remaining_wall_time_seconds()
                        if self._budget_ledger is not None
                        else None
                    ),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not complete:
                    self._mark_queued_racers_stopped("power_budget_wall_time_exhausted")
                    self._state = PowerSwarmState.BUDGET_EXHAUSTED
                    break
                for task in complete:
                    self._record_terminal(tasks[task], task)
                    await self._publish_progress()
                if winner_gate.winner_racer_id is not None:
                    self._winner_racer_id = winner_gate.winner_racer_id
                    await self._flush_and_cancel_siblings(pending, tasks, cancellation)
                    pending.clear()
                    self._state = PowerSwarmState.SOLVED
                    await self._publish_progress()
                    break
            if self._state is PowerSwarmState.RACING:
                all_failed = all(
                    control.state is PowerRacerState.FAILED for control in self._controls.values()
                )
                budget_snapshot = (
                    self._budget_ledger.snapshot() if self._budget_ledger is not None else None
                )
                if budget_snapshot is not None and budget_snapshot.exhausted_reason is not None:
                    self._state = PowerSwarmState.BUDGET_EXHAUSTED
                else:
                    self._state = (
                        PowerSwarmState.FAILED if all_failed else PowerSwarmState.EXHAUSTED
                    )
        finally:
            if pending:
                await self._flush_and_cancel_siblings(pending, tasks, cancellation)

        await self._publish_progress()

        return self._result()

    def _result(self) -> PowerSwarmResult:
        """Build the total terminal read model after any controlled stop path."""

        if self._brief is None:
            # ``prepare`` assigns the brief before racer tasks exist. This is
            # defensive only, and keeps the public result total for typing.
            raise RuntimeError("power_swarm_brief_missing")
        if self._category_pack is None:
            raise RuntimeError("power_swarm_category_pack_missing")
        return PowerSwarmResult(
            state=self._state,
            winner_racer_id=self._winner_racer_id,
            brief=self._brief,
            category_pack=self._category_pack,
            racers=self.snapshot().racers,
            budget=self.snapshot().budget,
            knowledge=self.snapshot().knowledge,
        )

    def _prepare_run(
        self,
        racers: tuple[PowerRacerSpec, ...],
        *,
        budget: PowerRunBudget | None,
        autoprompter_assignment: PowerModelAssignment | None,
        knowledge_retriever: KnowledgeRetriever | None,
        knowledge_recipient_racer_id: str | None,
        contest_offline: bool,
        knowledge_top_k: int,
        progress_listener: PowerProgressListener | None,
    ) -> None:
        """Reset mutable state and enforce the fixed, visible A/B/C topology."""

        if len(racers) != POWER_RACER_COUNT:
            raise ValueError("power_swarm_racer_count_invalid")
        racer_ids = tuple(spec.racer_id for spec in racers)
        labels = tuple(spec.label for spec in racers)
        if (
            any(not racer_id or len(racer_id) > 128 for racer_id in racer_ids)
            or len(set(racer_ids)) != POWER_RACER_COUNT
            or set(labels) != {"A", "B", "C"}
        ):
            raise ValueError("power_swarm_racer_spec_invalid")
        if budget is None and autoprompter_assignment is not None:
            raise ValueError("power_swarm_budget_assignment_without_budget")
        if budget is not None and (
            autoprompter_assignment is None or any(spec.assignment is None for spec in racers)
        ):
            raise ValueError("power_swarm_budget_assignment_missing")
        if not isinstance(contest_offline, bool):
            raise ValueError("power_swarm_contest_offline_invalid")
        if knowledge_retriever is None and knowledge_recipient_racer_id is not None:
            raise ValueError("power_swarm_knowledge_recipient_without_retriever")
        if knowledge_retriever is not None and knowledge_recipient_racer_id is None:
            raise ValueError("power_swarm_knowledge_recipient_missing")
        if (
            knowledge_recipient_racer_id is not None
            and knowledge_recipient_racer_id not in racer_ids
        ):
            raise ValueError("power_swarm_knowledge_recipient_invalid")
        if (
            isinstance(knowledge_top_k, bool)
            or not isinstance(knowledge_top_k, int)
            or not 1 <= knowledge_top_k <= 5
        ):
            raise ValueError("power_swarm_knowledge_top_k_invalid")
        if progress_listener is not None and not callable(progress_listener):
            raise ValueError("power_swarm_progress_listener_invalid")
        self._state = PowerSwarmState.IDLE
        self._brief = None
        self._category_pack = None
        self._winner_racer_id = None
        self._controls = {spec.racer_id: _RacerControl(spec=spec) for spec in racers}
        self._first_command_owner = {}
        self._budget_ledger = PowerBudgetLedger(budget) if budget is not None else None
        self._knowledge_retriever = knowledge_retriever
        self._knowledge_recipient_racer_id = knowledge_recipient_racer_id
        self._knowledge_context = ""
        self._knowledge_progress = None
        self._contest_offline = contest_offline
        self._knowledge_top_k = knowledge_top_k
        self._progress_listener = progress_listener

    async def _publish_progress(self) -> None:
        """Publish the safe read model without allowing UI storage to steer work."""

        if self._progress_listener is not None:
            await self._progress_listener(self.snapshot())

    async def _prepare_knowledge(self) -> None:
        """Retrieve advisory local technique text after, never during, AutoPrompter.

        The shared brief and the selected pack produce a compact query. The
        query deliberately excludes raw observations and archive paths. Only
        the configured recipient receives rendered excerpts; the coordinator
        snapshot retains just metadata for audit.
        """

        retriever = self._knowledge_retriever
        recipient = self._knowledge_recipient_racer_id
        if retriever is None or recipient is None:
            return
        if self._contest_offline:
            self._knowledge_progress = PowerKnowledgeProgress(
                mode=KnowledgeRetrievalMode.CONTEST_OFFLINE,
                recipient_racer_id=recipient,
                corpus_sha256=None,
                excerpt_count=0,
            )
            return
        if self._brief is None or self._category_pack is None:
            raise RuntimeError("power_swarm_brief_missing")
        try:
            retrieval = await retriever.retrieve(
                query=_knowledge_query(self._brief, self._category_pack),
                top_k=self._knowledge_top_k,
            )
            if not isinstance(retrieval, KnowledgeRetrieval):
                raise TypeError("knowledge_retrieval_invalid")
            context = render_knowledge_context(retrieval)
        except Exception:
            # Local knowledge is optional. Treat a changed/corrupt corpus as
            # unavailable rather than silently falling back to unbounded files
            # or failing the independently-verifiable solve path.
            self._knowledge_progress = PowerKnowledgeProgress(
                mode=KnowledgeRetrievalMode.UNAVAILABLE,
                recipient_racer_id=recipient,
                corpus_sha256=None,
                excerpt_count=0,
            )
            return
        self._knowledge_context = context
        self._knowledge_progress = PowerKnowledgeProgress(
            mode=retrieval.mode,
            recipient_racer_id=recipient,
            corpus_sha256=retrieval.corpus_pin.sha256 if retrieval.corpus_pin is not None else None,
            excerpt_count=len(retrieval.excerpts),
        )

    def _budgeted_autoprompter_backend(
        self,
        backend: ModelBackend,
        assignment: PowerModelAssignment | None,
    ) -> ModelBackend:
        """Charge the bounded reconnaissance pass before every provider call."""

        if self._budget_ledger is None:
            return backend
        if assignment is None:  # Defended by ``_prepare_run`` for future callers.
            raise RuntimeError("power_swarm_budget_assignment_missing")
        return BudgetedModelBackend(
            delegate=backend,
            ledger=self._budget_ledger,
            subject=assignment.cost_subject(subject_id="autoprompter", label="AutoPrompter"),
        )

    def _budgeted_racer_backend(self, control: _RacerControl) -> ModelBackend:
        """Use one shared cap while keeping each racer model call independent."""

        if self._budget_ledger is None:
            return control.spec.backend
        if control.spec.assignment is None:  # Defended by ``_prepare_run``.
            raise RuntimeError("power_swarm_budget_assignment_missing")
        return BudgetedModelBackend(
            delegate=control.spec.backend,
            ledger=self._budget_ledger,
            subject=control.spec.assignment.cost_subject(),
        )

    def _mark_queued_racers_stopped(self, reason: str) -> None:
        """Give never-started racer slots an explicit, operator-visible outcome."""

        for control in self._controls.values():
            if control.state is PowerRacerState.QUEUED:
                control.state = PowerRacerState.STOPPED
                control.reason = reason

    async def _run_racer(
        self,
        *,
        run_id: str,
        archive_digest: str,
        control: _RacerControl,
        flag_router: FlagRouter,
        cancellation: asyncio.Event,
    ) -> SolverResult:
        """Run one model in its own sandbox, sharing only the receipt-only brief."""

        if self._brief is None or self._category_pack is None:
            raise RuntimeError("power_swarm_brief_missing")
        control.state = PowerRacerState.RUNNING
        # Publish ownership before the first provider request so the operator
        # can distinguish a racer that is thinking from one still queued.
        await self._publish_progress()

        async def record_turn(telemetry: SolverTurnTelemetry) -> None:
            self._record_turn(control, telemetry)
            await self._publish_progress()

        try:
            return await ReActSolver(
                sandbox=self._sandbox_factory(),
                flag_router=flag_router,
                max_turns=self._solver_max_turns,
                initial_brief=_racer_brief(
                    self._brief,
                    self._category_pack,
                    self._knowledge_context
                    if control.spec.racer_id == self._knowledge_recipient_racer_id
                    else "",
                ),
                cancellation=cancellation,
                coordinator_hint_provider=control.coordinator_hint,
                on_turn_telemetry=record_turn,
            ).solve(
                run_id=run_id,
                archive_digest=archive_digest,
                backend=_RetryingModelBackend(self._budgeted_racer_backend(control)),
            )
        except PowerBudgetError as exc:
            # ReActSolver always cleans the allocated workspace in ``finally``
            # before this controlled, non-solve outcome reaches the scheduler.
            return SolverResult(status="stopped", observations=(), reason=exc.code)

    def _record_turn(self, control: _RacerControl, telemetry: SolverTurnTelemetry) -> None:
        """Update scheduling facts and nudge a racer away from duplicate work."""

        if control.state is PowerRacerState.BUMPED:
            control.state = PowerRacerState.RUNNING
        control.turn_count = telemetry.sequence
        control.last_action_type = telemetry.action_type
        control.last_action_summary = telemetry.action_summary
        control.last_command_fingerprint = telemetry.command_fingerprint
        control.last_observation_received = telemetry.observation_received
        control.last_observation_artifact_id = telemetry.observation_artifact_id
        if telemetry.observation_received:
            control.observation_count += 1
            control.consecutive_unobserved_turns = 0
        elif telemetry.action_type != "flag.submit":
            control.consecutive_unobserved_turns += 1

        fingerprint = telemetry.command_fingerprint
        if fingerprint is not None:
            owner = self._first_command_owner.setdefault(fingerprint, control.spec.racer_id)
            if owner != control.spec.racer_id:
                self._bump(
                    control,
                    code="duplicate_command",
                    hint=(
                        "Coordinator bump: another racer already issued an equivalent "
                        "shell command. Take a different evidence-gathering approach."
                    ),
                )
        if control.consecutive_unobserved_turns >= 5:
            control.consecutive_unobserved_turns = 0
            self._bump(
                control,
                code="observation_stall",
                hint=(
                    "Coordinator bump: five actions produced no observation. Request a "
                    "new observable result before continuing."
                ),
            )

    @staticmethod
    def _bump(control: _RacerControl, *, code: str, hint: str) -> None:
        """Mark a bounded scheduling nudge; it never changes tool authority."""

        if code not in control._hints:
            control.bump_count += 1
            control._hints[code] = hint
        control.state = PowerRacerState.BUMPED
        control.reason = code

    def _record_terminal(self, racer_id: str, task: asyncio.Task[SolverResult]) -> None:
        """Map a solver task outcome to a safe racer state without re-raising it."""

        control = self._controls[racer_id]
        if task.cancelled():
            control.state = PowerRacerState.CANCELLED
            control.reason = "coordinator_cancelled"
            return
        try:
            result = task.result()
        except SolverModelError as exc:
            # Keep a reviewed provider code on the racer; do not collapse it
            # into an opaque generic exception or stop sibling racers.
            control.state = PowerRacerState.FAILED
            control.reason = exc.code
            return
        except Exception:
            control.state = PowerRacerState.FAILED
            control.reason = "solver_failed"
            return
        control.reason = result.reason
        if result.status == "solved":
            control.state = PowerRacerState.SOLVED
        elif result.status == "cancelled":
            control.state = PowerRacerState.CANCELLED
        else:
            control.state = PowerRacerState.STOPPED

    async def _flush_and_cancel_siblings(
        self,
        pending: set[asyncio.Task[SolverResult]],
        tasks: dict[asyncio.Task[SolverResult], str],
        cancellation: asyncio.Event,
    ) -> None:
        """Give racers five seconds to flush, then cancel only still-pending work."""

        if not pending:
            return
        cancellation.set()
        done, remaining = await asyncio.wait(
            pending,
            timeout=self._sibling_grace_seconds,
            return_when=asyncio.ALL_COMPLETED,
        )
        for task in done:
            self._record_terminal(tasks[task], task)
        for task in remaining:
            task.cancel()
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)
            for task in remaining:
                self._record_terminal(tasks[task], task)


class _RetryingModelBackend(ModelBackend):
    """Retry only schema-invalid replies while charging every provider call."""

    def __init__(
        self,
        delegate: ModelBackend,
        *,
        max_retries: int = POWER_MODEL_PROTOCOL_RETRIES,
    ) -> None:
        if not 0 <= max_retries <= POWER_MODEL_PROTOCOL_RETRIES:
            raise ValueError("power_model_protocol_retries_invalid")
        self._delegate = delegate
        self._max_retries = max_retries

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        """Ask for one clean typed action without reflecting provider output."""

        retry_context = context
        for attempt in range(self._max_retries + 1):
            try:
                return await self._delegate.next_turn(retry_context)
            except SolverModelError as exc:
                if exc.code != "solver_model_action_invalid" or attempt >= self._max_retries:
                    raise
                retry_context = replace(
                    context,
                    coordinator_hint=_merge_retry_hint(context.coordinator_hint),
                )
        raise AssertionError("power_model_retry_loop_unreachable")


def _merge_retry_hint(existing: str) -> str:
    """Append one bounded protocol correction without exposing provider text."""

    if not existing:
        return _MODEL_RETRY_HINT
    return f"{existing}\n{_MODEL_RETRY_HINT}"[:_MAX_RETRY_HINT_CHARS]


class _FirstVerifiedFlagGate:
    """Serialize router access so only one racer can be the first valid winner."""

    def __init__(self, *, delegate: FlagRouter, cancellation: asyncio.Event) -> None:
        self._delegate = delegate
        self._cancellation = cancellation
        self._lock = asyncio.Lock()
        self.winner_racer_id: str | None = None

    async def submit(
        self,
        *,
        racer_id: str,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        """Forward one candidate to the independent router at most until a win."""

        async with self._lock:
            if self.winner_racer_id is not None:
                return False
            accepted = await self._delegate.submit(
                run_id=run_id,
                candidate=candidate,
                observation_artifact_id=observation_artifact_id,
                observation_sha256=observation_sha256,
            )
            if accepted:
                self.winner_racer_id = racer_id
                self._cancellation.set()
            return accepted


class _RacerFlagRouter:
    """Bind a solver's flag submission to the shared first-winner gate."""

    def __init__(self, *, racer_id: str, winner_gate: _FirstVerifiedFlagGate) -> None:
        self._racer_id = racer_id
        self._winner_gate = winner_gate

    async def submit(
        self,
        *,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        """Keep raw candidate handling limited to the existing flag-router call."""

        return await self._winner_gate.submit(
            racer_id=self._racer_id,
            run_id=run_id,
            candidate=candidate,
            observation_artifact_id=observation_artifact_id,
            observation_sha256=observation_sha256,
        )


def _receipt_only_brief(result: SolverResult, action_types: tuple[str, ...]) -> AutoPromptBrief:
    """Render a shared prompt with receipts, never the raw observations themselves."""

    artifacts = tuple(
        observation.artifact_id for observation in result.observations[:_BRIEF_MAX_ARTIFACTS]
    )
    signals = category_signals_from_observations(
        observation.stdout + observation.stderr for observation in result.observations
    )
    action_summary = ", ".join(action_types) if action_types else "none"
    artifact_summary = ", ".join(artifacts) if artifacts else "none"
    heading = (
        "AutoPrompter stopped after an invalid action response. Preserve and independently "
        "reproduce the receipts below; this brief is not evidence."
        if result.reason == "solver_model_action_invalid"
        else "AutoPrompter reconnaissance completed. Independently reproduce every claim "
        "from your own sandbox observations; this brief is not evidence."
    )
    text = (
        f"{heading}\n"
        f"Observed action types: {action_summary}.\n"
        f"Category signals: {', '.join(signal.value for signal in signals) or 'none'}.\n"
        f"Evidence receipt IDs: {artifact_summary}.\n"
        "Prefer a distinct next command when the coordinator supplies a bump."
    )
    return AutoPromptBrief(
        text=text,
        action_types=action_types,
        observation_artifact_ids=artifacts,
        turn_count=len(action_types),
        finish_reason=result.reason,
        category_signals=signals,
    )


def _budget_exhausted_brief(reason: str) -> AutoPromptBrief:
    """Represent a pre-race budget stop without fabricating reconnaissance facts."""

    return AutoPromptBrief(
        text=(
            "AutoPrompter did not produce a reconnaissance receipt because the shared "
            "Power budget was exhausted. No category or evidence claim was made."
        ),
        action_types=(),
        observation_artifact_ids=(),
        turn_count=0,
        finish_reason=reason,
        category_signals=(),
    )


def _racer_brief(brief: AutoPromptBrief, pack: CategoryPack, knowledge_context: str = "") -> str:
    """Append reviewed pack and one optional advisory excerpt set to a racer context."""

    base = f"{brief.text}\n\nReviewed category pack ({pack.id}):\n{pack.text}"
    return f"{base}\n\n{knowledge_context}" if knowledge_context else base


def _knowledge_query(brief: AutoPromptBrief, pack: CategoryPack) -> str:
    """Build a bounded retrieval query only from receipt/category metadata."""

    category_terms = [pack.id.value.split(".", maxsplit=1)[0]]
    category_terms.extend(
        signal.value.split(".", maxsplit=1)[0] for signal in brief.category_signals
    )
    action_terms = (action.replace(".", " ") for action in brief.action_types)
    return " ".join((*category_terms, *action_terms))[:512]


__all__ = [
    "AUTOPROMPTER_MAX_TURNS",
    "POWER_RACER_COUNT",
    "POWER_RACER_GRACE_SECONDS",
    "POWER_KNOWLEDGE_TOP_K",
    "POWER_MODEL_PROTOCOL_RETRIES",
    "AutoPromptBrief",
    "AutoPrompter",
    "PowerRacerProgress",
    "PowerKnowledgeProgress",
    "PowerRacerSpec",
    "PowerRacerState",
    "PowerSwarmCoordinator",
    "PowerSwarmResult",
    "PowerSwarmSnapshot",
    "PowerSwarmState",
]
