"""Typed, infrastructure-independent contracts for operator Hint Cards.

Hint Cards are deliberately *guidance*, not facts.  They can influence the
deterministic scheduler, but they cannot promote an observation, mark a
candidate verified, or change a run to ``solved``.  Keeping that distinction in
the domain contract makes it available to the API, scheduler, and UI without
letting any of those layers reinterpret free-form operator text as authority.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .base import ContractModel, FrozenSequence, Identifier, NonEmptyText, Sha256Digest, UtcDatetime
from .runtime import AgentRole


class HintCategory(StrEnum):
    """Reviewed hint families displayed by the local operator console."""

    SUSPECTED_VULNERABILITY = "suspected_vulnerability"
    TARGET_COMPONENT = "target_component"
    OBSERVED_BEHAVIOR = "observed_behavior"
    AVOID_PATH = "avoid_path"
    OPERATOR_CONSTRAINT = "operator_constraint"


class HintDirective(StrEnum):
    """The small deterministic set of effects a card may request."""

    EXPLORE = "explore"
    PRIORITIZE = "prioritize"
    REQUIRE_PROBE = "require_probe"
    AVOID = "avoid"


class HintStatus(StrEnum):
    """Lifecycle of an unverified human hypothesis."""

    ACTIVE = "active"
    FULFILLED = "fulfilled"
    CONTRADICTED = "contradicted"
    DISMISSED = "dismissed"
    EXPIRED = "expired"


class HintOutcome(StrEnum):
    """Evidence-backed terminal outcomes available to trusted kernel paths."""

    FULFILLED = "fulfilled"
    CONTRADICTED = "contradicted"


# Keep the domain boundary secret-free as well as the append-only event
# boundary.  A raw flag or credential should not be retained in an operator
# note merely because the note itself is otherwise untrusted data.
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_API_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


def _safe_note(value: str) -> str:
    """Normalize a bounded note while refusing obvious secrets and flags."""

    normalized = value.strip()
    if _RAW_FLAG.search(normalized) or _BEARER.search(normalized) or _API_KEY.search(normalized):
        raise ValueError("hint_note_contains_secret")
    return normalized


class HintTemplate(ContractModel):
    """A maintainer-reviewed catalog entry, pinned by ID and version."""

    id: Identifier
    version: int = Field(ge=1, le=1_000)
    label: NonEmptyText = Field(max_length=160)
    technique_id: Identifier
    category: HintCategory
    default_directive: HintDirective
    recommended_roles: FrozenSequence[AgentRole] = Field(min_length=1, max_length=2)
    recommended_tools: FrozenSequence[Identifier] = Field(min_length=1, max_length=8)
    branch_seed: NonEmptyText = Field(max_length=2_000)
    falsifiers: FrozenSequence[NonEmptyText] = Field(min_length=1, max_length=8)

    @field_validator("category", mode="before")
    @classmethod
    def _parse_category(cls, value: Any) -> Any:
        return HintCategory(value) if isinstance(value, str) else value

    @field_validator("default_directive", mode="before")
    @classmethod
    def _parse_default_directive(cls, value: Any) -> Any:
        return HintDirective(value) if isinstance(value, str) else value

    @field_validator("recommended_roles", mode="before")
    @classmethod
    def _parse_roles(cls, values: Any) -> Any:
        if not isinstance(values, list | tuple):
            return values
        return tuple(AgentRole(value) if isinstance(value, str) else value for value in values)

    @field_validator("recommended_roles", "recommended_tools", "falsifiers")
    @classmethod
    def _require_unique_values(cls, values: tuple[Any, ...]) -> tuple[Any, ...]:
        if len(values) != len(set(values)):
            raise ValueError("hint_template_values_cannot_contain_duplicates")
        return values

    @model_validator(mode="after")
    def _template_must_schedule_workers(self) -> HintTemplate:
        if AgentRole.MASTER in self.recommended_roles:
            raise ValueError("hint_template_cannot_recommend_master")
        return self


class HintCard(ContractModel):
    """One operator-attached hint instance with a non-factual lifecycle."""

    id: Identifier
    run_id: Identifier
    template_id: Identifier
    template_version: int = Field(ge=1, le=1_000)
    technique_id: Identifier
    category: HintCategory
    directive: HintDirective
    # Scope stays an identifier rather than a URL/path so attaching a card can
    # never add a target or source location to the execution authority.
    target_ref: Identifier = "run:all"
    priority: int = Field(ge=1, le=5)
    # A note is UI data.  It may be blank, but it cannot contain a raw flag or
    # credential and is never promoted to a system instruction.
    note: str = Field(default="", max_length=500)
    epistemic_status: Literal["human_hypothesis"] = "human_hypothesis"
    status: HintStatus = HintStatus.ACTIVE
    evidence_refs: FrozenSequence[Identifier] = Field(default_factory=tuple, max_length=32)
    actor_id: Identifier
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @field_validator("category", mode="before")
    @classmethod
    def _parse_category(cls, value: Any) -> Any:
        return HintCategory(value) if isinstance(value, str) else value

    @field_validator("directive", mode="before")
    @classmethod
    def _parse_directive(cls, value: Any) -> Any:
        return HintDirective(value) if isinstance(value, str) else value

    @field_validator("status", mode="before")
    @classmethod
    def _parse_status(cls, value: Any) -> Any:
        return HintStatus(value) if isinstance(value, str) else value

    @field_validator("note")
    @classmethod
    def _validate_note(cls, value: str) -> str:
        return _safe_note(value)

    @field_validator("evidence_refs")
    @classmethod
    def _require_unique_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("hint_evidence_refs_cannot_contain_duplicates")
        return values

    @model_validator(mode="after")
    def _terminal_status_requires_evidence(self) -> HintCard:
        if (
            self.status in {HintStatus.FULFILLED, HintStatus.CONTRADICTED}
            and not self.evidence_refs
        ):
            raise ValueError("hint_terminal_status_requires_evidence")
        if self.updated_at < self.created_at:
            raise ValueError("hint_updated_before_created")
        return self


class BranchScoreFactors(ContractModel):
    """Normalized, inspectable inputs to the deterministic branch score."""

    evidence_strength: float = Field(ge=0, le=1)
    novelty: float = Field(ge=0, le=1)
    hint_priority: float = Field(ge=0, le=1)
    expected_value: float = Field(ge=0, le=1)
    normalized_cost: float = Field(ge=0, le=1)
    repetition_penalty: float = Field(ge=0, le=1)


class RolePromptContract(ContractModel):
    """Digest-pinned reviewed prompt/skill-pack metadata for one Pi role."""

    role: AgentRole
    version: int = Field(ge=1, le=1_000)
    digest: Sha256Digest
    skill_pack_ids: FrozenSequence[Identifier] = Field(default_factory=tuple, max_length=16)

    @field_validator("skill_pack_ids")
    @classmethod
    def _require_unique_skill_packs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("role_prompt_skill_packs_cannot_contain_duplicates")
        return values


__all__ = [
    "BranchScoreFactors",
    "HintCard",
    "HintCategory",
    "HintDirective",
    "HintOutcome",
    "HintStatus",
    "HintTemplate",
    "RolePromptContract",
]
