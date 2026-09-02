"""Read-only triage, deterministic preflight, and control-plane helpers."""

from typing import Any

from .candidates import CandidateArtifactService
from .category_packs import (
    CategoryPack,
    CategoryPackId,
    category_signals_from_observations,
    reviewed_category_pack,
    reviewed_category_packs,
    select_category_pack,
)
from .console import build_console_snapshot
from .preflight import (
    DeterministicPreflight,
    PreflightError,
    PreflightPayload,
    canonical_preflight_bytes,
)
from .readonly_workspace import (
    MAX_READONLY_ARTIFACT_BYTES,
    MaterializedArtifact,
    ReadonlyWorkspaceError,
    materialize_declared_artifacts,
    resolve_challenge_root,
)
from .run_engine import FakeRunHarness, RunEngine, RunEngineError
from .scheduler import (
    MAX_ACTIVE_WORKER_BRANCHES,
    SCHEDULER_POLICY_VERSION,
    STALL_TURN_THRESHOLD,
    branch_score,
    deterministic_fallback_role,
    hint_template,
    hint_templates,
    prompt_skill_pack_ids,
    rank_branches,
    role_prompt_contracts,
    task_template_for_hint,
)
from .triage import (
    TriageBackend,
    TriageConfigurationError,
    TriageOrchestrator,
    TriageProposalError,
    TriageRunError,
    TriageRunResult,
)
from .worker import (
    PreflightWorkerConfig,
    PreflightWorkerConfigurationError,
    load_preflight_worker_config,
)

_LEGACY_POWER_EXPORTS = frozenset(
    {
        "AUTOPROMPTER_MAX_TURNS",
        "POWER_RACER_COUNT",
        "POWER_RACER_GRACE_SECONDS",
        "POWER_KNOWLEDGE_TOP_K",
        "POWER_MODEL_PROTOCOL_RETRIES",
        "AutoPromptBrief",
        "AutoPrompter",
        "BudgetedModelBackend",
        "ComposedPowerRace",
        "PowerBudgetError",
        "PowerBudgetLedger",
        "PowerBudgetSnapshot",
        "PowerCostLedgerEntry",
        "PowerCostReservation",
        "PowerCostSubject",
        "PowerCostSubtotal",
        "PowerKnowledgeProgress",
        "PowerModelAssignment",
        "PowerProgressListener",
        "PowerRacerAssignment",
        "PowerRacerProgress",
        "PowerRacerSpec",
        "PowerRacerState",
        "PowerRaceConfiguration",
        "PowerRaceConfigurationError",
        "PowerRaceProvider",
        "PowerRunBudget",
        "PowerSwarmCoordinator",
        "PowerSwarmResult",
        "PowerSwarmSnapshot",
        "PowerSwarmState",
        "compose_power_race",
        "same_model_racer_assignments",
    }
)


def __getattr__(name: str) -> Any:
    """Keep legacy Power fixture imports lazy outside the Compose runtime."""

    if name not in _LEGACY_POWER_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    if name in {
        "BudgetedModelBackend",
        "PowerBudgetError",
        "PowerBudgetLedger",
        "PowerBudgetSnapshot",
        "PowerCostLedgerEntry",
        "PowerCostReservation",
        "PowerCostSubject",
        "PowerCostSubtotal",
        "PowerRunBudget",
    }:
        from . import power_budget

        return getattr(power_budget, name)
    if name in {
        "ComposedPowerRace",
        "PowerModelAssignment",
        "PowerRaceConfiguration",
        "PowerRaceConfigurationError",
        "PowerRaceProvider",
        "PowerRacerAssignment",
        "compose_power_race",
        "same_model_racer_assignments",
    }:
        from . import power_race

        return getattr(power_race, name)
    from . import power_swarm

    return getattr(power_swarm, name)


__all__ = [
    "MAX_READONLY_ARTIFACT_BYTES",
    "CandidateArtifactService",
    "CategoryPack",
    "CategoryPackId",
    "MAX_ACTIVE_WORKER_BRANCHES",
    "DeterministicPreflight",
    "FakeRunHarness",
    "MaterializedArtifact",
    "PreflightError",
    "PreflightPayload",
    "PreflightWorkerConfig",
    "PreflightWorkerConfigurationError",
    "ReadonlyWorkspaceError",
    "TriageBackend",
    "TriageConfigurationError",
    "TriageOrchestrator",
    "TriageProposalError",
    "TriageRunError",
    "TriageRunResult",
    "RunEngine",
    "RunEngineError",
    "SCHEDULER_POLICY_VERSION",
    "STALL_TURN_THRESHOLD",
    "branch_score",
    "build_console_snapshot",
    "canonical_preflight_bytes",
    "category_signals_from_observations",
    "deterministic_fallback_role",
    "hint_template",
    "hint_templates",
    "materialize_declared_artifacts",
    "prompt_skill_pack_ids",
    "rank_branches",
    "reviewed_category_pack",
    "reviewed_category_packs",
    "role_prompt_contracts",
    "task_template_for_hint",
    "select_category_pack",
    "load_preflight_worker_config",
    "resolve_challenge_root",
]
