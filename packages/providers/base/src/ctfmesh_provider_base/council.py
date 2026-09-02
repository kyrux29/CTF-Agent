"""Provider-neutral contracts for an evidence-first model council.

The council boundary deliberately describes *proposals*, never tool execution.
Provider adapters may implement :class:`CouncilBackend`, but credentials, tool
authorization, and run-state transitions remain outside this package.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CouncilRole(StrEnum):
    """Bounded roles used by the deliberation coordinator."""

    SCOUT = "scout"
    SPECIALIST = "specialist"
    FALSIFIER = "falsifier"
    ADJUDICATOR = "adjudicator"


class CouncilContractError(RuntimeError):
    """A stable error for invalid or ungrounded provider completions."""


class CouncilContractModel(BaseModel):
    """Strict immutable data crossing the provider/council boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


def _freeze_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


class ModelProfile(CouncilContractModel):
    """A pinned model capability record, independent of credential storage."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,159}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    model_id: str = Field(min_length=1, max_length=160)
    family: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    roles: tuple[CouncilRole, ...] = Field(min_length=1, max_length=8)
    structured_output: Literal["strict", "json_only", "post_validate"]
    demo: bool = False

    @field_validator("roles", mode="before")
    @classmethod
    def _freeze_roles(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @field_validator("roles")
    @classmethod
    def _unique_roles(cls, value: tuple[CouncilRole, ...]) -> tuple[CouncilRole, ...]:
        if len(value) != len(set(value)):
            raise ValueError("roles cannot contain duplicates")
        return value


class CouncilEvidence(CouncilContractModel):
    """A bounded, digest-pinned input supplied to a council participant."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    summary: str = Field(min_length=1, max_length=4_000)


class CouncilClaim(CouncilContractModel):
    """A falsifiable, evidence-cited proposal from one participant."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    branch_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    role: CouncilRole
    profile_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,159}$")
    statement: str = Field(min_length=1, max_length=4_000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    prediction: str = Field(min_length=1, max_length=2_000)
    falsifier: str = Field(min_length=1, max_length=2_000)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _freeze_evidence_ids(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @field_validator("evidence_ids")
    @classmethod
    def _unique_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_ids cannot contain duplicates")
        return value


class CouncilCritique(CouncilContractModel):
    """A concrete challenge to a previously submitted claim."""

    claim_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    verdict: Literal["supported", "unsupported", "rejected"]
    reason: str = Field(min_length=1, max_length=2_000)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def _freeze_evidence_ids(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @field_validator("evidence_ids")
    @classmethod
    def _unique_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_ids cannot contain duplicates")
        return value


class CouncilDecision(CouncilContractModel):
    """The adjudicator's bounded decision; it is never a tool invocation."""

    outcome: Literal["accept", "reject", "request_experiment", "defer"]
    selected_claim_ids: tuple[str, ...] = Field(default=(), max_length=16)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    summary: str = Field(min_length=1, max_length=2_000)
    safe_next_step: str | None = Field(default=None, min_length=1, max_length=2_000)

    @field_validator("selected_claim_ids", "evidence_ids", mode="before")
    @classmethod
    def _freeze_ids(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @field_validator("selected_claim_ids", "evidence_ids")
    @classmethod
    def _unique_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("decision identifiers cannot contain duplicates")
        return value

    @model_validator(mode="after")
    def _decision_has_a_coherent_selection(self) -> CouncilDecision:
        if self.outcome in {"accept", "request_experiment"} and not self.selected_claim_ids:
            raise ValueError("accept and request_experiment decisions require selected claims")
        if self.outcome == "request_experiment" and self.safe_next_step is None:
            raise ValueError("request_experiment decisions require a safe next step")
        if self.outcome in {"reject", "defer"} and self.safe_next_step is not None:
            raise ValueError("reject and defer decisions cannot schedule a next step")
        return self


class CouncilProposal(CouncilContractModel):
    """A persisted, non-executable follow-up request derived from a decision.

    This intentionally contains no tool name, arguments, target, or credential
    material. A later planner must independently turn it into a typed tool
    request and pass the normal manifest and policy checks.
    """

    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    intent: Literal["evidence_request"]
    summary: str = Field(min_length=1, max_length=2_000)
    selected_claim_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    execution_allowed: Literal[False] = False

    @field_validator("selected_claim_ids", "evidence_ids", mode="before")
    @classmethod
    def _freeze_ids(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @field_validator("selected_claim_ids", "evidence_ids")
    @classmethod
    def _unique_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("proposal identifiers cannot contain duplicates")
        return value


class CouncilTask(CouncilContractModel):
    """A role-specific, evidence-bounded request to one model profile."""

    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,160}$")
    round: int = Field(ge=1, le=16)
    role: CouncilRole
    profile: ModelProfile
    objective: str = Field(min_length=1, max_length=8_000)
    evidence: tuple[CouncilEvidence, ...] = Field(min_length=1, max_length=128)
    candidate_claims: tuple[CouncilClaim, ...] = Field(default=(), max_length=128)
    candidate_critiques: tuple[CouncilCritique, ...] = Field(default=(), max_length=128)

    @field_validator("evidence", "candidate_claims", "candidate_critiques", mode="before")
    @classmethod
    def _freeze_models(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @model_validator(mode="after")
    def _profile_must_authorize_role(self) -> CouncilTask:
        if self.role not in self.profile.roles:
            raise ValueError("model profile is not authorized for this council role")
        evidence_ids = tuple(item.id for item in self.evidence)
        claim_ids = tuple(item.id for item in self.candidate_claims)
        critique_claim_ids = tuple(item.claim_id for item in self.candidate_critiques)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("task evidence IDs cannot contain duplicates")
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("task candidate claim IDs cannot contain duplicates")
        if len(critique_claim_ids) != len(set(critique_claim_ids)):
            raise ValueError("task candidate critiques cannot target a claim more than once")
        if self.role in {CouncilRole.SCOUT, CouncilRole.SPECIALIST}:
            if self.candidate_claims or self.candidate_critiques:
                raise ValueError(
                    "independent branch tasks cannot receive prior claims or critiques"
                )
            return self
        if self.role is CouncilRole.FALSIFIER:
            if not self.candidate_claims:
                raise ValueError("falsifier tasks require candidate claims")
            if self.candidate_critiques:
                raise ValueError("falsifier tasks cannot receive prior critiques")
            return self
        if not self.candidate_claims or not self.candidate_critiques:
            raise ValueError("adjudication tasks require candidate claims and critiques")
        if set(critique_claim_ids) != set(claim_ids):
            raise ValueError("adjudication critiques must cover every candidate claim exactly once")
        available_evidence = set(evidence_ids)
        for critique in self.candidate_critiques:
            if not set(critique.evidence_ids).issubset(available_evidence):
                raise ValueError("task critique cites evidence outside the task evidence set")
        return self


class CouncilCompletion(CouncilContractModel):
    """One normalized provider response for a council task."""

    response_id: str | None = Field(default=None, min_length=1, max_length=160)
    claims: tuple[CouncilClaim, ...] = Field(default=(), max_length=32)
    critiques: tuple[CouncilCritique, ...] = Field(default=(), max_length=128)
    decision: CouncilDecision | None = None

    @field_validator("claims", "critiques", mode="before")
    @classmethod
    def _freeze_models(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @model_validator(mode="after")
    def _identifiers_must_be_unambiguous(self) -> CouncilCompletion:
        claim_ids = tuple(item.id for item in self.claims)
        branch_ids = tuple(item.branch_id for item in self.claims)
        critique_claim_ids = tuple(item.claim_id for item in self.critiques)
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("completion claim IDs cannot contain duplicates")
        if len(branch_ids) != len(set(branch_ids)):
            raise ValueError("completion branch IDs cannot contain duplicates")
        if len(critique_claim_ids) != len(set(critique_claim_ids)):
            raise ValueError("completion critiques cannot target a claim more than once")
        return self


class CouncilBackend(Protocol):
    """A provider adapter that returns normalized, non-executing proposals."""

    name: str

    async def complete(self, task: CouncilTask) -> CouncilCompletion: ...


def validate_council_completion(task: CouncilTask, completion: CouncilCompletion) -> None:
    """Reject output that cites unknown evidence or crosses a role boundary."""

    available_evidence = {item.id for item in task.evidence}
    candidate_ids = {item.id for item in task.candidate_claims}

    def ensure_evidence(ids: tuple[str, ...]) -> None:
        if not set(ids).issubset(available_evidence):
            raise CouncilContractError("completion_cites_unknown_evidence")

    if task.role in {CouncilRole.SCOUT, CouncilRole.SPECIALIST}:
        if not completion.claims or completion.critiques or completion.decision is not None:
            raise CouncilContractError("completion_content_forbidden_for_branch_role")
    elif task.role is CouncilRole.FALSIFIER:
        if completion.claims or not completion.critiques or completion.decision is not None:
            raise CouncilContractError("completion_content_forbidden_for_falsifier")
    elif completion.claims or completion.critiques:
        raise CouncilContractError("completion_content_forbidden_for_adjudicator")

    for claim in completion.claims:
        if claim.role is not task.role or claim.profile_id != task.profile.id:
            raise CouncilContractError("completion_claim_actor_mismatch")
        ensure_evidence(claim.evidence_ids)
    for critique in completion.critiques:
        if task.role is not CouncilRole.FALSIFIER:
            raise CouncilContractError("completion_critique_from_non_falsifier")
        if critique.claim_id not in candidate_ids:
            raise CouncilContractError("completion_critiques_unknown_claim")
        ensure_evidence(critique.evidence_ids)
    if (
        task.role is CouncilRole.FALSIFIER
        and {critique.claim_id for critique in completion.critiques} != candidate_ids
    ):
        raise CouncilContractError("falsifier_must_critique_every_candidate_claim")
    if completion.decision is not None:
        if task.role is not CouncilRole.ADJUDICATOR:
            raise CouncilContractError("completion_decision_from_non_adjudicator")
        ensure_evidence(completion.decision.evidence_ids)
        if not set(completion.decision.selected_claim_ids).issubset(candidate_ids):
            raise CouncilContractError("completion_selects_unknown_claim")
        disqualified_claim_ids = {
            critique.claim_id
            for critique in task.candidate_critiques
            if critique.verdict in {"unsupported", "rejected"}
        }
        if set(completion.decision.selected_claim_ids) & disqualified_claim_ids:
            raise CouncilContractError("completion_selects_disqualified_claim")
    elif task.role is CouncilRole.ADJUDICATOR:
        raise CouncilContractError("adjudicator_completion_requires_decision")


__all__ = [
    "CouncilBackend",
    "CouncilClaim",
    "CouncilCompletion",
    "CouncilContractError",
    "CouncilCritique",
    "CouncilDecision",
    "CouncilEvidence",
    "CouncilProposal",
    "CouncilRole",
    "CouncilTask",
    "ModelProfile",
    "validate_council_completion",
]
