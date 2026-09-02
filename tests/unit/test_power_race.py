"""P6 proofs for non-secret provider composition and conservative cost ledger."""

from __future__ import annotations

from math import nan

import pytest
from ctfmesh_orchestrator import (
    BudgetedModelBackend,
    PowerBudgetError,
    PowerBudgetLedger,
    PowerModelAssignment,
    PowerRaceConfiguration,
    PowerRaceConfigurationError,
    PowerRaceProvider,
    PowerRacerAssignment,
    PowerRunBudget,
    compose_power_race,
    same_model_racer_assignments,
)
from ctfmesh_solver_runtime import SolverContext, SolverTurn
from pydantic import SecretStr


class _StopBackend:
    """Local model seam proving P6 composition cannot make a network request."""

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        del context
        return SolverTurn(action=None)


def _assignment(
    provider: PowerRaceProvider,
    model: str,
    *,
    temperature: float = 0.2,
    cost: int = 100_000,
) -> PowerModelAssignment:
    return PowerModelAssignment(
        provider=provider,
        model=model,
        temperature=temperature,
        max_turn_cost_microusd=cost,
    )


def test_composition_maps_three_reviewed_providers_without_serializing_keys() -> None:
    """Each racer receives its reviewed mapping while key material stays ephemeral."""

    openai_key = SecretStr("fixture-openai-key-123456")
    gemini_key = SecretStr("fixture-gemini-key-123456")
    deepseek_key = SecretStr("fixture-deepseek-key-123456")
    openai_racers = same_model_racer_assignments(
        provider=PowerRaceProvider.OPENAI_RESPONSES,
        model="gpt-5.6-sol",
        max_turn_cost_microusd=120_000,
    )
    # The tuple is intentionally heterogeneous: P6 permits a real
    # multi-provider race when the operator has the three credentials.
    configuration = PowerRaceConfiguration(
        autoprompter=_assignment(PowerRaceProvider.OPENAI_RESPONSES, "gpt-5.6-terra"),
        racers=(
            openai_racers[0],
            same_model_racer_assignments(
                provider=PowerRaceProvider.GEMINI_OPENAI_COMPAT,
                model="gemini-3.7-flash",
                max_turn_cost_microusd=90_000,
            )[1],
            same_model_racer_assignments(
                provider=PowerRaceProvider.DEEPSEEK_CHAT,
                model="deepseek-v4-pro",
                max_turn_cost_microusd=80_000,
            )[2],
        ),
        budget=PowerRunBudget(max_cost_microusd=2_000_000, max_wall_time_seconds=600),
    )
    calls: list[tuple[PowerRaceProvider, str, float, SecretStr]] = []

    def factory(assignment: PowerModelAssignment, key: SecretStr) -> _StopBackend:
        calls.append((assignment.provider, assignment.model, assignment.temperature, key))
        return _StopBackend()

    composed = compose_power_race(
        configuration,
        provider_keys={
            PowerRaceProvider.OPENAI_RESPONSES: openai_key,
            PowerRaceProvider.GEMINI_OPENAI_COMPAT: gemini_key,
            PowerRaceProvider.DEEPSEEK_CHAT: deepseek_key,
        },
        backend_factory=factory,
    )

    mapping = [
        (racer.label, assignment.model_assignment.provider)
        for racer in composed.racers
        if (assignment := racer.assignment) is not None
    ]
    assert mapping == [
        ("A", PowerRaceProvider.OPENAI_RESPONSES),
        ("B", PowerRaceProvider.GEMINI_OPENAI_COMPAT),
        ("C", PowerRaceProvider.DEEPSEEK_CHAT),
    ]
    assert [call[3] for call in calls] == [openai_key, openai_key, gemini_key, deepseek_key]
    assert "fixture-openai-key" not in repr(configuration)
    assert "fixture-gemini-key" not in repr(composed)


def test_one_credential_can_compose_three_same_model_racers_with_diverse_temperature() -> None:
    """Three backends share only the caller-owned key, never a serialized copy."""

    racer_assignments = same_model_racer_assignments(
        provider=PowerRaceProvider.DEEPSEEK_CHAT,
        model="deepseek-v4-pro",
        max_turn_cost_microusd=75_000,
    )
    key = SecretStr("fixture-deepseek-key-123456")
    seen_keys: list[SecretStr] = []

    def factory(assignment: PowerModelAssignment, credential: SecretStr) -> _StopBackend:
        del assignment
        seen_keys.append(credential)
        return _StopBackend()

    composed = compose_power_race(
        PowerRaceConfiguration(
            autoprompter=racer_assignments[0].model_assignment,
            racers=racer_assignments,
            budget=PowerRunBudget(max_cost_microusd=1_000_000, max_wall_time_seconds=600),
        ),
        provider_keys={PowerRaceProvider.DEEPSEEK_CHAT: key},
        backend_factory=factory,
    )

    configured_racers = [
        assignment for racer in composed.racers if (assignment := racer.assignment) is not None
    ]
    assert [racer.model_assignment.model for racer in configured_racers] == [
        "deepseek-v4-pro",
        "deepseek-v4-pro",
        "deepseek-v4-pro",
    ]
    assert [racer.model_assignment.temperature for racer in configured_racers] == [
        0.2,
        0.5,
        0.8,
    ]
    assert seen_keys == [key, key, key, key]


def test_power_composition_rejects_missing_provider_key() -> None:
    """The coordinator cannot silently substitute credentials across providers."""

    racers = same_model_racer_assignments(
        provider=PowerRaceProvider.OPENAI_RESPONSES,
        model="gpt-5.6-terra",
        max_turn_cost_microusd=100_000,
    )
    with pytest.raises(PowerRaceConfigurationError, match="power_race_provider_key_missing"):
        compose_power_race(
            PowerRaceConfiguration(
                autoprompter=racers[0].model_assignment,
                racers=racers,
                budget=PowerRunBudget(max_cost_microusd=1_000_000, max_wall_time_seconds=600),
            ),
            provider_keys={},
            backend_factory=lambda _assignment, _key: _StopBackend(),
        )


def test_identical_model_race_requires_distinct_sampling_temperatures() -> None:
    """A manual configuration cannot accidentally make three identical attempts."""

    repeated_assignment = _assignment(PowerRaceProvider.OPENAI_RESPONSES, "gpt-5.6-terra")
    with pytest.raises(
        PowerRaceConfigurationError,
        match="power_race_temperature_diversity_invalid",
    ):
        PowerRaceConfiguration(
            autoprompter=repeated_assignment,
            racers=tuple(
                PowerRacerAssignment(
                    racer_id=racer.racer_id,
                    label=racer.label,
                    model_assignment=repeated_assignment,
                )
                for racer in same_model_racer_assignments(
                    provider=PowerRaceProvider.OPENAI_RESPONSES,
                    model="gpt-5.6-terra",
                    max_turn_cost_microusd=100_000,
                )
            ),
            budget=PowerRunBudget(max_cost_microusd=1_000_000, max_wall_time_seconds=600),
        )


def test_power_configuration_rejects_non_finite_sampling_and_boolean_budget_values() -> None:
    """Malformed internal composition inputs cannot turn into permissive limits."""

    with pytest.raises(PowerRaceConfigurationError, match="power_race_temperature_invalid"):
        _assignment(PowerRaceProvider.OPENAI_RESPONSES, "gpt-5.6-terra", temperature=nan)
    with pytest.raises(ValueError, match="power_budget_cost_invalid"):
        PowerRunBudget(max_cost_microusd=True, max_wall_time_seconds=60)


@pytest.mark.asyncio
async def test_cost_ledger_is_append_only_and_stops_before_shared_cap_is_exceeded() -> None:
    """Concurrent callers cannot spend more than the declared race envelope."""

    clock = [10.0]
    ledger = PowerBudgetLedger(
        PowerRunBudget(max_cost_microusd=150, max_wall_time_seconds=60),
        monotonic_clock=lambda: clock[0],
    )
    first = _assignment(PowerRaceProvider.OPENAI_RESPONSES, "gpt-5.6-terra", cost=100).cost_subject(
        subject_id="racer-a",
        label="A",
    )
    second = _assignment(
        PowerRaceProvider.GEMINI_OPENAI_COMPAT,
        "gemini-3.7-flash",
        cost=100,
    ).cost_subject(
        subject_id="racer-b",
        label="B",
    )

    accepted, rejected = await ledger.reserve(first), await ledger.reserve(second)
    snapshot = ledger.snapshot()

    assert accepted.accepted
    assert not rejected.accepted
    assert rejected.reason == "power_budget_cost_exhausted"
    assert snapshot.spent_cost_microusd == 100
    assert snapshot.remaining_cost_microusd == 50
    assert [(entry.subject_id, entry.accepted) for entry in snapshot.entries] == [
        ("racer-a", True),
        ("racer-b", False),
    ]
    assert [(total.subject_id, total.reserved_cost_microusd) for total in snapshot.subtotals] == [
        ("racer-a", 100),
    ]


@pytest.mark.asyncio
async def test_budgeted_backend_refuses_provider_call_after_cost_reservation_is_denied() -> None:
    """The deny path happens before the wrapped backend can make I/O."""

    class _UnexpectedBackend:
        async def next_turn(self, context: SolverContext) -> SolverTurn:
            del context
            raise AssertionError("provider call must not start after a denied reservation")

    ledger = PowerBudgetLedger(PowerRunBudget(max_cost_microusd=50, max_wall_time_seconds=60))
    backend = BudgetedModelBackend(
        delegate=_UnexpectedBackend(),
        ledger=ledger,
        subject=_assignment(
            PowerRaceProvider.OPENAI_RESPONSES,
            "gpt-5.6-terra",
            cost=100,
        ).cost_subject(
            subject_id="racer-a",
            label="A",
        ),
    )

    with pytest.raises(PowerBudgetError, match="power_budget_cost_exhausted"):
        await backend.next_turn(SolverContext("", "", ()))
