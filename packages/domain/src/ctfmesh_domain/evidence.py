"""Evidence-first blackboard contracts and invariants."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from .base import (
    ContractModel,
    FrozenSequence,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    UtcDatetime,
)
from .core import ActorKind, ActorRef


class EvidenceRef(ContractModel):
    artifact_id: Identifier
    locator: NonEmptyText | None = None
    digest: Sha256Digest
    observed_at: UtcDatetime


class ArtifactRef(ContractModel):
    id: Identifier
    run_id: Identifier
    sha256: Sha256Digest
    size_bytes: int = Field(ge=0)
    mime_type: NonEmptyText
    producer: ActorRef
    created_at: UtcDatetime
    branch_id: Identifier | None = None
    task_id: Identifier | None = None
    tool_invocation_id: Identifier | None = None
    classification: Literal["public", "internal", "secret", "flag"] = "internal"


class FactStatus(StrEnum):
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    RETRACTED = "retracted"


class Fact(ContractModel):
    schema_name: Literal["ctfmesh.fact"] = Field("ctfmesh.fact", alias="schema")
    schema_version: Literal[1] = 1
    id: Identifier
    run_id: Identifier
    statement: NonEmptyText
    confidence: float = Field(ge=0, le=1)
    status: FactStatus
    evidence: FrozenSequence[EvidenceRef] = Field(default_factory=tuple)
    created_by: ActorRef
    created_at: UtcDatetime
    branch_id: Identifier | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _parse_status(cls, value: Any) -> Any:
        return FactStatus(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _confirmed_fact_has_evidence(self) -> Fact:
        if (
            self.status is FactStatus.CONFIRMED
            and not self.evidence
            and self.created_by.kind is not ActorKind.HUMAN
        ):
            raise ValueError("confirmed facts require evidence or a human assertion")
        return self


class HypothesisStatus(StrEnum):
    OPEN = "open"
    TESTING = "testing"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    MERGED = "merged"
    SUSPENDED = "suspended"


class Hypothesis(ContractModel):
    schema_name: Literal["ctfmesh.hypothesis"] = Field("ctfmesh.hypothesis", alias="schema")
    schema_version: Literal[1] = 1
    id: Identifier
    run_id: Identifier
    branch_id: Identifier
    family: NonEmptyText
    statement: NonEmptyText
    confidence: float = Field(ge=0, le=1)
    supporting_fact_ids: FrozenSequence[Identifier]
    contradicting_fact_ids: FrozenSequence[Identifier] = Field(default_factory=tuple)
    falsifiers: FrozenSequence[NonEmptyText] = Field(min_length=1)
    next_experiment_id: Identifier | None = None
    status: HypothesisStatus

    @field_validator("status", mode="before")
    @classmethod
    def _parse_status(cls, value: Any) -> Any:
        return HypothesisStatus(value) if isinstance(value, str) else value


_SECRET_FIELD_MARKERS = frozenset(
    {"authorization", "cookie", "api_key", "apikey", "password", "secret", "token", "flag"}
)
_REDACTED_VALUES = frozenset({"<redacted>", "[redacted]", "***"})


def _contains_plaintext_secret(value: object, *, parent_key: str = "") -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(marker in normalized for marker in _SECRET_FIELD_MARKERS):
                if isinstance(child, str) and child.lower() not in _REDACTED_VALUES:
                    return True
            if _contains_plaintext_secret(child, parent_key=normalized):
                return True
    elif isinstance(value, list):
        return any(_contains_plaintext_secret(item, parent_key=parent_key) for item in value)
    return False


class Experiment(ContractModel):
    schema_name: Literal["ctfmesh.experiment"] = Field("ctfmesh.experiment", alias="schema")
    schema_version: Literal[1] = 1
    id: Identifier
    hypothesis_id: Identifier
    objective: NonEmptyText
    expected_observation: NonEmptyText
    expected_information_gain: float = Field(ge=0, le=1)
    estimated_cost_units: int = Field(ge=1)
    risk_level: Literal["read_only", "workspace_write", "target_interaction", "high_impact"]
    tool_name: Annotated[
        str,
        Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$", min_length=3, max_length=128),
    ]
    tool_input: dict[str, Any]

    @field_validator("tool_input")
    @classmethod
    def _reject_plaintext_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        if _contains_plaintext_secret(value):
            raise ValueError("tool_input cannot contain plaintext secrets")
        return value
