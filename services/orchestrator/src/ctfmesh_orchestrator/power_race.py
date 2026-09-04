"""Reviewed, non-secret composition for the P6 three-model Power race.

This module maps a visible racer only to a provider ID, model ID, sampling
temperature and conservative per-turn maximum.  It deliberately has no
database serialization, target URL, sandbox capability, or credential store.
The caller provides short-lived ``SecretStr`` values only when composing live
provider backends.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING

from pydantic import SecretStr

from .power_budget import PowerCostSubject, PowerRunBudget

if TYPE_CHECKING:
    from ctfmesh_solver_runtime import ModelBackend, OpenAICompatibleSolverBackend

    from .power_swarm import PowerRacerSpec

_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_RACER_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_RACER_LABELS = ("A", "B", "C")
_SAME_MODEL_TEMPERATURES = (0.2, 0.5, 0.8)


class PowerRaceProvider(StrEnum):
    """The model backends the Power profile can be pointed at.

    Every value except ``CUSTOM_OPENAI`` names a provider the Pi SDK already
    ships with its own endpoint and model catalog, so choosing one adds no new
    egress shape - only a host the operator must also allow on the provider
    proxy. ``CUSTOM_OPENAI`` is the escape hatch for anything else that speaks
    the OpenAI chat API, including a model server on the operator's own
    machine, and it is the only value that carries a base URL.
    """

    OPENAI_RESPONSES = "openai-responses"
    GEMINI_OPENAI_COMPAT = "gemini-openai-compat"
    DEEPSEEK_CHAT = "deepseek-chat"
    ANTHROPIC = "anthropic"
    OPENROUTER = "openrouter"
    GROQ = "groq"
    TOGETHER = "together"
    MISTRAL = "mistral"
    XAI = "xai"
    CEREBRAS = "cerebras"
    FIREWORKS = "fireworks"
    CUSTOM_OPENAI = "custom-openai"


#: Where each provider's traffic goes, so a deployment can allow exactly the
#: hosts it actually uses. ``CUSTOM_OPENAI`` is absent: its host comes from the
#: operator's own base URL and cannot be known here.
POWER_PROVIDER_HOSTS: dict[PowerRaceProvider, str] = {
    PowerRaceProvider.OPENAI_RESPONSES: "api.openai.com",
    PowerRaceProvider.GEMINI_OPENAI_COMPAT: "generativelanguage.googleapis.com",
    PowerRaceProvider.DEEPSEEK_CHAT: "api.deepseek.com",
    PowerRaceProvider.ANTHROPIC: "api.anthropic.com",
    PowerRaceProvider.OPENROUTER: "openrouter.ai",
    PowerRaceProvider.GROQ: "api.groq.com",
    PowerRaceProvider.TOGETHER: "api.together.ai",
    PowerRaceProvider.MISTRAL: "api.mistral.ai",
    PowerRaceProvider.XAI: "api.x.ai",
    PowerRaceProvider.CEREBRAS: "api.cerebras.ai",
    PowerRaceProvider.FIREWORKS: "api.fireworks.ai",
}


class PowerRaceConfigurationError(ValueError):
    """A stable composition failure with no credential or provider detail."""


@dataclass(frozen=True, slots=True)
class PowerModelAssignment:
    """Non-secret configuration for AutoPrompter or a single racer backend."""

    provider: PowerRaceProvider
    model: str
    temperature: float
    max_turn_cost_microusd: int

    def __post_init__(self) -> None:
        if not isinstance(self.provider, PowerRaceProvider):
            raise PowerRaceConfigurationError("power_race_provider_invalid")
        if not isinstance(self.model, str) or _MODEL_NAME.fullmatch(self.model) is None:
            raise PowerRaceConfigurationError("power_race_model_invalid")
        if (
            isinstance(self.temperature, bool)
            or not isinstance(self.temperature, int | float)
            or not isfinite(self.temperature)
            or not 0 <= self.temperature <= 2
        ):
            raise PowerRaceConfigurationError("power_race_temperature_invalid")
        if (
            isinstance(self.max_turn_cost_microusd, bool)
            or not isinstance(self.max_turn_cost_microusd, int)
            or not 1 <= self.max_turn_cost_microusd <= 1_000_000_000
        ):
            raise PowerRaceConfigurationError("power_race_turn_cost_invalid")

    def cost_subject(self, *, subject_id: str, label: str) -> PowerCostSubject:
        """Translate the secret-free assignment into one ledger charge identity."""

        return PowerCostSubject(
            subject_id=subject_id,
            label=label,
            provider=self.provider.value,
            model=self.model,
            max_turn_cost_microusd=self.max_turn_cost_microusd,
        )


@dataclass(frozen=True, slots=True)
class PowerRacerAssignment:
    """One visible A/B/C mapping, including its deliberate sampling diversity."""

    racer_id: str
    label: str
    model_assignment: PowerModelAssignment

    def __post_init__(self) -> None:
        if _RACER_ID.fullmatch(self.racer_id) is None:
            raise PowerRaceConfigurationError("power_race_racer_id_invalid")
        if self.label not in _RACER_LABELS:
            raise PowerRaceConfigurationError("power_race_racer_label_invalid")
        if not isinstance(self.model_assignment, PowerModelAssignment):
            raise PowerRaceConfigurationError("power_race_model_assignment_invalid")

    def cost_subject(self) -> PowerCostSubject:
        """Attribute each conservative reservation to the visible racer slot."""

        return self.model_assignment.cost_subject(subject_id=self.racer_id, label=self.label)


@dataclass(frozen=True, slots=True)
class PowerRaceConfiguration:
    """Complete P6 configuration, with three racers and one shared budget."""

    autoprompter: PowerModelAssignment
    racers: tuple[PowerRacerAssignment, ...]
    budget: PowerRunBudget

    def __post_init__(self) -> None:
        if not isinstance(self.autoprompter, PowerModelAssignment):
            raise PowerRaceConfigurationError("power_race_autoprompter_invalid")
        if not isinstance(self.budget, PowerRunBudget):
            raise PowerRaceConfigurationError("power_race_budget_invalid")
        if len(self.racers) != len(_RACER_LABELS):
            raise PowerRaceConfigurationError("power_race_racer_count_invalid")
        if any(not isinstance(racer, PowerRacerAssignment) for racer in self.racers):
            raise PowerRaceConfigurationError("power_race_racer_mapping_invalid")
        racer_ids = tuple(racer.racer_id for racer in self.racers)
        labels = tuple(racer.label for racer in self.racers)
        if len(set(racer_ids)) != len(_RACER_LABELS) or set(labels) != set(_RACER_LABELS):
            raise PowerRaceConfigurationError("power_race_racer_mapping_invalid")
        assignments = tuple(racer.model_assignment for racer in self.racers)
        same_model = all(
            assignment.provider is assignments[0].provider
            and assignment.model == assignments[0].model
            for assignment in assignments
        )
        if same_model and len({assignment.temperature for assignment in assignments}) != len(
            _RACER_LABELS
        ):
            raise PowerRaceConfigurationError("power_race_temperature_diversity_invalid")


PowerBackendFactory = Callable[[PowerModelAssignment, SecretStr], "ModelBackend"]


@dataclass(frozen=True, slots=True)
class ComposedPowerRace:
    """Ephemeral live backend objects paired with their safe P6 configuration."""

    autoprompter_backend: ModelBackend
    racers: tuple[PowerRacerSpec, ...]
    autoprompter_assignment: PowerModelAssignment
    budget: PowerRunBudget


_SOLVER_PROVIDER_VALUE_BY_RACE_PROVIDER = {
    PowerRaceProvider.OPENAI_RESPONSES: "openai-chat",
    PowerRaceProvider.GEMINI_OPENAI_COMPAT: "gemini-openai-compat",
    PowerRaceProvider.DEEPSEEK_CHAT: "deepseek-chat",
}


def same_model_racer_assignments(
    *,
    provider: PowerRaceProvider,
    model: str,
    max_turn_cost_microusd: int,
    temperatures: tuple[float, float, float] = _SAME_MODEL_TEMPERATURES,
) -> tuple[PowerRacerAssignment, ...]:
    """Make three independent samplers when the operator has only one key."""

    if len(temperatures) != len(_RACER_LABELS) or len(set(temperatures)) != len(_RACER_LABELS):
        raise PowerRaceConfigurationError("power_race_temperature_diversity_invalid")
    return tuple(
        PowerRacerAssignment(
            racer_id=f"racer-{label.lower()}",
            label=label,
            model_assignment=PowerModelAssignment(
                provider=provider,
                model=model,
                temperature=temperature,
                max_turn_cost_microusd=max_turn_cost_microusd,
            ),
        )
        for label, temperature in zip(_RACER_LABELS, temperatures, strict=True)
    )


def compose_power_race(
    configuration: PowerRaceConfiguration,
    *,
    provider_keys: Mapping[PowerRaceProvider, SecretStr],
    backend_factory: PowerBackendFactory | None = None,
) -> ComposedPowerRace:
    """Create short-lived backends without serializing or retaining the key map.

    The default factory pins outbound routes to the existing provider proxy.
    Tests can supply a local fake factory; neither path grants the coordinator
    a direct HTTP, sandbox, or target capability.
    """

    factory = backend_factory or _default_backend_factory
    autoprompter_backend = factory(
        configuration.autoprompter,
        _key_for(configuration.autoprompter, provider_keys),
    )
    # Local import avoids a module cycle: PowerSwarm owns scheduling while this
    # module owns only reviewed provider/model composition.
    from .power_swarm import PowerRacerSpec

    racers = tuple(
        PowerRacerSpec(
            racer_id=racer.racer_id,
            label=racer.label,
            backend=factory(
                racer.model_assignment,
                _key_for(racer.model_assignment, provider_keys),
            ),
            assignment=racer,
        )
        for racer in configuration.racers
    )
    return ComposedPowerRace(
        autoprompter_backend=autoprompter_backend,
        racers=racers,
        autoprompter_assignment=configuration.autoprompter,
        budget=configuration.budget,
    )


def _key_for(
    assignment: PowerModelAssignment,
    provider_keys: Mapping[PowerRaceProvider, SecretStr],
) -> SecretStr:
    """Read one ephemeral key without admitting it into configuration objects."""

    key = provider_keys.get(assignment.provider)
    if not isinstance(key, SecretStr) or not key.get_secret_value():
        raise PowerRaceConfigurationError("power_race_provider_key_missing")
    return key


def _default_backend_factory(
    assignment: PowerModelAssignment,
    api_key: SecretStr,
) -> OpenAICompatibleSolverBackend:
    """Use fixed reviewed routes; a model mapping cannot supply an endpoint."""

    # Legacy fixture composition is intentionally lazy.  M-PI-2's Power
    # production path imports only the non-provider configuration above.
    from ctfmesh_solver_runtime.model import OpenAICompatibleSolverBackend, SolverProvider

    return OpenAICompatibleSolverBackend(
        provider=SolverProvider(_SOLVER_PROVIDER_VALUE_BY_RACE_PROVIDER[assignment.provider]),
        model=assignment.model,
        api_key=api_key,
        proxy_url="http://provider-proxy:3128",
        temperature=assignment.temperature,
    )


__all__ = [
    "ComposedPowerRace",
    "PowerModelAssignment",
    "PowerRaceConfiguration",
    "PowerRaceConfigurationError",
    "PowerRaceProvider",
    "PowerRacerAssignment",
    "compose_power_race",
    "same_model_racer_assignments",
]
