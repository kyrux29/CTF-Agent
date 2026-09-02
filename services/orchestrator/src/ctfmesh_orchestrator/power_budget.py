"""Secret-free, conservative budget accounting for one Power race.

The coordinator uses this module before each provider call.  It reserves the
declared worst-case cost rather than trusting a provider to report usage after
the request.  This means the cap cannot be exceeded by concurrent racers.  The
ledger deliberately contains only reviewed model metadata and integer money
units; it cannot contain credentials, prompts, observations, commands, or
flag candidates.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from ctfmesh_solver_runtime import ModelBackend, SolverContext, SolverTurn

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_MAX_WALL_TIME_SECONDS = 86_400
_MAX_COST_MICROUSD = 1_000_000_000


class PowerBudgetError(RuntimeError):
    """A stable stop reason which never includes provider or model output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PowerRunBudget:
    """One conservative cap shared by AutoPrompter and all three racers."""

    max_cost_microusd: int
    max_wall_time_seconds: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_cost_microusd, bool)
            or not isinstance(self.max_cost_microusd, int)
            or not 1 <= self.max_cost_microusd <= _MAX_COST_MICROUSD
        ):
            raise ValueError("power_budget_cost_invalid")
        if (
            isinstance(self.max_wall_time_seconds, bool)
            or not isinstance(self.max_wall_time_seconds, int)
            or not 1 <= self.max_wall_time_seconds <= _MAX_WALL_TIME_SECONDS
        ):
            raise ValueError("power_budget_wall_time_invalid")


@dataclass(frozen=True, slots=True)
class PowerCostSubject:
    """Reviewed identity of the single model call being charged."""

    subject_id: str
    label: str
    provider: str
    model: str
    max_turn_cost_microusd: int

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, str) or _IDENTIFIER.fullmatch(self.subject_id) is None:
            raise ValueError("power_budget_subject_invalid")
        if not isinstance(self.label, str) or not self.label or len(self.label) > 32:
            raise ValueError("power_budget_label_invalid")
        if not isinstance(self.provider, str) or not self.provider or len(self.provider) > 64:
            raise ValueError("power_budget_provider_invalid")
        if not isinstance(self.model, str) or _MODEL_NAME.fullmatch(self.model) is None:
            raise ValueError("power_budget_model_invalid")
        if (
            isinstance(self.max_turn_cost_microusd, bool)
            or not isinstance(self.max_turn_cost_microusd, int)
            or not 1 <= self.max_turn_cost_microusd <= _MAX_COST_MICROUSD
        ):
            raise ValueError("power_budget_turn_cost_invalid")


@dataclass(frozen=True, slots=True)
class PowerCostLedgerEntry:
    """One immutable reservation decision in the Power run's cost ledger."""

    sequence: int
    subject_id: str
    label: str
    provider: str
    model: str
    reserved_cost_microusd: int
    accepted: bool
    reason: str | None


@dataclass(frozen=True, slots=True)
class PowerCostSubtotal:
    """Cost total for a visible racer or the bounded AutoPrompter pass."""

    subject_id: str
    label: str
    reserved_cost_microusd: int


@dataclass(frozen=True, slots=True)
class PowerBudgetSnapshot:
    """Secret-free, append-only projection exposed to the coordinator UI."""

    max_cost_microusd: int
    spent_cost_microusd: int
    remaining_cost_microusd: int
    max_wall_time_seconds: int
    elapsed_wall_time_seconds: float
    remaining_wall_time_seconds: float
    exhausted_reason: str | None
    subtotals: tuple[PowerCostSubtotal, ...]
    entries: tuple[PowerCostLedgerEntry, ...]


@dataclass(frozen=True, slots=True)
class PowerCostReservation:
    """Result of atomically reserving a maximum-cost provider call."""

    accepted: bool
    reason: str | None


class PowerBudgetLedger:
    """Serialize conservative reservations so concurrent racers share one cap."""

    def __init__(
        self,
        budget: PowerRunBudget,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._budget = budget
        self._clock = monotonic_clock
        self._started_at = monotonic_clock()
        self._lock = asyncio.Lock()
        self._spent_cost_microusd = 0
        self._entries: list[PowerCostLedgerEntry] = []
        self._subtotals: dict[str, PowerCostSubtotal] = {}
        self._exhausted_reason: str | None = None

    def remaining_wall_time_seconds(self) -> float:
        """Return the shared monotonic deadline without leaking wall-clock time."""

        return max(0.0, self._budget.max_wall_time_seconds - self._elapsed_seconds())

    def snapshot(self) -> PowerBudgetSnapshot:
        """Project immutable accounting data suitable for a future run console."""

        elapsed = self._elapsed_seconds()
        return PowerBudgetSnapshot(
            max_cost_microusd=self._budget.max_cost_microusd,
            spent_cost_microusd=self._spent_cost_microusd,
            remaining_cost_microusd=self._budget.max_cost_microusd - self._spent_cost_microusd,
            max_wall_time_seconds=self._budget.max_wall_time_seconds,
            elapsed_wall_time_seconds=elapsed,
            remaining_wall_time_seconds=max(0.0, self._budget.max_wall_time_seconds - elapsed),
            exhausted_reason=self._exhausted_reason,
            subtotals=tuple(self._subtotals.values()),
            entries=tuple(self._entries),
        )

    async def reserve(self, subject: PowerCostSubject) -> PowerCostReservation:
        """Reserve a maximum call cost before provider I/O, never after it."""

        async with self._lock:
            reason: str | None = None
            if self.remaining_wall_time_seconds() <= 0:
                reason = "power_budget_wall_time_exhausted"
            elif (
                self._spent_cost_microusd + subject.max_turn_cost_microusd
                > self._budget.max_cost_microusd
            ):
                reason = "power_budget_cost_exhausted"

            accepted = reason is None
            if accepted:
                self._spent_cost_microusd += subject.max_turn_cost_microusd
                prior = self._subtotals.get(subject.subject_id)
                self._subtotals[subject.subject_id] = PowerCostSubtotal(
                    subject_id=subject.subject_id,
                    label=subject.label,
                    reserved_cost_microusd=(prior.reserved_cost_microusd if prior else 0)
                    + subject.max_turn_cost_microusd,
                )
            else:
                # The first terminal cause remains stable even if late racers
                # observe another exhausted dimension after cancellation.
                self._exhausted_reason = self._exhausted_reason or reason

            self._entries.append(
                PowerCostLedgerEntry(
                    sequence=len(self._entries) + 1,
                    subject_id=subject.subject_id,
                    label=subject.label,
                    provider=subject.provider,
                    model=subject.model,
                    reserved_cost_microusd=subject.max_turn_cost_microusd if accepted else 0,
                    accepted=accepted,
                    reason=reason,
                )
            )
            return PowerCostReservation(accepted=accepted, reason=reason)

    def _elapsed_seconds(self) -> float:
        """Clamp a test clock anomaly so a budget can never gain time."""

        return max(0.0, self._clock() - self._started_at)


class BudgetedModelBackend(ModelBackend):
    """Gate one reviewed model backend behind the shared Power budget ledger."""

    def __init__(
        self,
        *,
        delegate: ModelBackend,
        ledger: PowerBudgetLedger,
        subject: PowerCostSubject,
    ) -> None:
        self._delegate = delegate
        self._ledger = ledger
        self._subject = subject

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        """Reserve then bound the call by the run deadline before it leaves process."""

        reservation = await self._ledger.reserve(self._subject)
        if not reservation.accepted:
            raise PowerBudgetError(reservation.reason or "power_budget_exhausted")
        remaining = self._ledger.remaining_wall_time_seconds()
        if remaining <= 0:
            raise PowerBudgetError("power_budget_wall_time_exhausted")
        try:
            async with asyncio.timeout(remaining):
                return await self._delegate.next_turn(context)
        except TimeoutError:
            raise PowerBudgetError("power_budget_wall_time_exhausted") from None


__all__ = [
    "BudgetedModelBackend",
    "PowerBudgetError",
    "PowerBudgetLedger",
    "PowerBudgetSnapshot",
    "PowerCostLedgerEntry",
    "PowerCostReservation",
    "PowerCostSubject",
    "PowerCostSubtotal",
    "PowerRunBudget",
]
