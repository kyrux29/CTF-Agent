"""Deterministic M4 scheduling policy for a deliberately small CTF portfolio.

This module is policy, not an agent framework: it does not call a model, read
the database, dispatch a tool, or execute a target request.  The repository
persists the decisions it receives from this policy under its normal
transaction/lease rules.  Keeping score and template selection pure makes the
two-worker cap explainable and directly testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ctfmesh_domain import (
    AgentRole,
    BranchScoreFactors,
    HintCategory,
    HintDirective,
    HintTemplate,
    RolePromptContract,
)

SCHEDULER_POLICY_VERSION = 1
MAX_ACTIVE_WORKER_BRANCHES = 2
STALL_TURN_THRESHOLD = 2


# These entries are checked into the reviewed image.  They are not downloaded
# from a challenge archive and a model cannot create a new arbitrary technique.
_HINT_TEMPLATES: tuple[HintTemplate, ...] = (
    HintTemplate(
        id="web.path_traversal.suspect.v1",
        version=1,
        label="Suspect path traversal",
        technique_id="web.path_traversal",
        category=HintCategory.SUSPECTED_VULNERABILITY,
        default_directive=HintDirective.PRIORITIZE,
        recommended_roles=(AgentRole.SOURCE_AUDITOR, AgentRole.HTTP_TESTER),
        recommended_tools=("source.search", "source.read", "http.request"),
        branch_seed="Check path normalization and the declared file boundary.",
        falsifiers=("control path", "encoded variant", "outside-root canary"),
    ),
    HintTemplate(
        id="web.authz_boundary.suspect.v1",
        version=1,
        label="Suspect authorization boundary",
        technique_id="web.authz_boundary",
        category=HintCategory.SUSPECTED_VULNERABILITY,
        default_directive=HintDirective.EXPLORE,
        recommended_roles=(AgentRole.SOURCE_AUDITOR, AgentRole.HTTP_TESTER),
        recommended_tools=("source.search", "source.read", "http.request"),
        branch_seed="Compare declared ownership checks with one bounded control request.",
        falsifiers=("same-owner control", "different-owner control", "missing-object control"),
    ),
    HintTemplate(
        id="web.sqli_basic.suspect.v1",
        version=1,
        label="Suspect input-to-query boundary",
        technique_id="web.sqli_basic",
        category=HintCategory.SUSPECTED_VULNERABILITY,
        default_directive=HintDirective.REQUIRE_PROBE,
        recommended_roles=(AgentRole.SOURCE_AUDITOR, AgentRole.HTTP_TESTER),
        recommended_tools=("source.search", "source.read", "http.request"),
        branch_seed="Trace parameter binding and compare one bounded control probe.",
        falsifiers=("parameterized-query evidence", "benign control", "error-shape control"),
    ),
)


@dataclass(frozen=True, slots=True)
class ScheduledBranch:
    """The normalized fields the scheduler may use to rank an existing branch."""

    branch_id: str
    technique_id: str
    role: AgentRole
    factors: BranchScoreFactors
    state: Literal["active", "stalled", "suspended", "completed", "failed"]


@dataclass(frozen=True, slots=True)
class SchedulerTaskTemplate:
    """A bounded role/objective pair derived only from a reviewed hint template."""

    technique_id: str
    role: AgentRole
    objective: str
    requires_control: bool


def hint_templates() -> tuple[HintTemplate, ...]:
    """Return the immutable, reviewed HintTemplate catalog in stable order."""

    return _HINT_TEMPLATES


def hint_template(template_id: str) -> HintTemplate | None:
    """Resolve one catalog entry without falling back to user-provided data."""

    return next((item for item in _HINT_TEMPLATES if item.id == template_id), None)


def branch_score(factors: BranchScoreFactors) -> float:
    """Score a branch with the versioned M4 formula from the execution plan."""

    return round(
        0.35 * factors.evidence_strength
        + 0.25 * factors.novelty
        + 0.20 * factors.hint_priority
        + 0.15 * factors.expected_value
        - 0.20 * factors.normalized_cost
        - factors.repetition_penalty,
        6,
    )


def rank_branches(branches: tuple[ScheduledBranch, ...]) -> tuple[ScheduledBranch, ...]:
    """Return runnable branches in a deterministic score/cost/ID order."""

    runnable = (branch for branch in branches if branch.state == "active")
    return tuple(
        sorted(
            runnable,
            key=lambda branch: (
                -branch_score(branch.factors),
                branch.factors.normalized_cost,
                branch.branch_id,
            ),
        )
    )


def task_template_for_hint(
    template: HintTemplate,
    *,
    role: AgentRole,
    directive: HintDirective,
) -> SchedulerTaskTemplate:
    """Build a fixed task objective; an operator note is intentionally absent.

    ``require_probe`` makes the control/falsifier requirement visible to the
    worker.  The actual allowed tool set still comes from the sealed role
    capability map and is independently rechecked by the gateway.
    """

    if role not in template.recommended_roles:
        raise ValueError("hint_template_role_not_recommended")
    if directive is HintDirective.AVOID:
        raise ValueError("avoid_hint_has_no_task_template")
    if directive is HintDirective.REQUIRE_PROBE:
        objective = (
            f"{template.branch_seed} Include one control or falsifier: "
            f"{template.falsifiers[0]}. Record only sealed evidence."
        )
        return SchedulerTaskTemplate(
            technique_id=template.technique_id,
            role=role,
            objective=objective,
            requires_control=True,
        )
    return SchedulerTaskTemplate(
        technique_id=template.technique_id,
        role=role,
        objective=template.branch_seed,
        requires_control=False,
    )


def deterministic_fallback_role(template: HintTemplate) -> AgentRole:
    """Choose the stable first reviewed worker role after a master stall."""

    return template.recommended_roles[0]


# Prompt contracts are metadata for the three reviewed web lab skill packs.
# The canonical prompt text/digest is calculated in Pi Runner at startup; the
# scheduler catalog documents which pack a role is permitted to receive.
ROLE_SKILL_PACK_IDS: dict[AgentRole, tuple[str, ...]] = {
    AgentRole.MASTER: (),
    AgentRole.SOURCE_AUDITOR: (
        "skill.web_path_traversal.v1",
        "skill.web_authz_boundary.v1",
        "skill.web_sqli_basic.v1",
    ),
    AgentRole.HTTP_TESTER: (
        "skill.web_path_traversal.v1",
        "skill.web_authz_boundary.v1",
        "skill.web_sqli_basic.v1",
    ),
    AgentRole.EXPLOIT_BUILDER: (),
    AgentRole.FALSIFIER: (
        "skill.web_path_traversal.v1",
        "skill.web_authz_boundary.v1",
        "skill.web_sqli_basic.v1",
    ),
}


def prompt_skill_pack_ids(role: AgentRole) -> tuple[str, ...]:
    """Return reviewed local skill pack IDs, never challenge-provided skills."""

    return ROLE_SKILL_PACK_IDS[role]


def role_prompt_contracts(prompt_digests: dict[AgentRole, str]) -> tuple[RolePromptContract, ...]:
    """Adapt Pi's locally computed prompt digests into typed audit metadata.

    The adapter is intentionally supplied the digest rather than reading prompt
    files from a challenge or any external source.
    """

    return tuple(
        RolePromptContract(
            role=role,
            version=1,
            digest=prompt_digests[role],
            skill_pack_ids=prompt_skill_pack_ids(role),
        )
        for role in AgentRole
    )


__all__ = [
    "MAX_ACTIVE_WORKER_BRANCHES",
    "ROLE_SKILL_PACK_IDS",
    "SCHEDULER_POLICY_VERSION",
    "STALL_TURN_THRESHOLD",
    "ScheduledBranch",
    "SchedulerTaskTemplate",
    "branch_score",
    "deterministic_fallback_role",
    "hint_template",
    "hint_templates",
    "prompt_skill_pack_ids",
    "rank_branches",
    "role_prompt_contracts",
    "task_template_for_hint",
]
