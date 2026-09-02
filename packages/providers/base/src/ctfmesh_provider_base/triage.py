"""Provider-neutral contracts for bounded, evidence-backed CTF triage.

This module is intentionally transport and provider SDK free.  Provider
adapters translate these immutable contracts into their individual wire
formats, while callers retain ownership of credentials and authorization.
Neither a completion nor a backend has authority to execute a tool, contact a
challenge target, or mark a run as solved.
"""

from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

TriageCategory = Literal[
    "web",
    "crypto",
    "pwn",
    "reverse",
    "forensics",
    "osint",
    "misc",
    "ai_ml",
    "mobile",
    "blockchain",
    "hardware",
    "stego",
    "programming",
    "unknown",
]


class _TriageContractModel(BaseModel):
    """Strict, immutable values crossing the provider boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


def _freeze_tuple(value: Any) -> Any:
    """Accept JSON arrays while retaining immutable tuple contracts internally."""

    return tuple(value) if isinstance(value, list) else value


class TriageEvidence(_TriageContractModel):
    """A bounded observation supplied to a triage provider."""

    id: str = Field(min_length=1, max_length=160)
    kind: Literal["challenge", "artifact_excerpt", "tool_observation", "operator_note"]
    content: str = Field(min_length=1, max_length=16_000)


class TriageRequest(_TriageContractModel):
    """The provider-neutral input for one proposal-only triage request."""

    model: str = Field(min_length=1, max_length=160)
    max_output_tokens: int = Field(default=900, ge=128, le=4096)
    objective: str = Field(min_length=1, max_length=16_000)
    authorized_scope: str = Field(min_length=1, max_length=8_000)
    evidence: tuple[TriageEvidence, ...] = Field(min_length=1, max_length=128)

    @field_validator("evidence", mode="before")
    @classmethod
    def _freeze_evidence(cls, value: Any) -> Any:
        return _freeze_tuple(value)

    @field_validator("evidence")
    @classmethod
    def _unique_evidence_ids(cls, value: tuple[TriageEvidence, ...]) -> tuple[TriageEvidence, ...]:
        ids = tuple(item.id for item in value)
        if len(ids) != len(set(ids)):
            raise ValueError("evidence IDs cannot contain duplicates")
        return value


class TriageFact(_TriageContractModel):
    """A provider-proposed fact tied to supplied evidence."""

    statement: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0, le=1)
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


class TriageHypothesis(_TriageContractModel):
    """A provider-proposed, unverified hypothesis tied to evidence."""

    statement: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0, le=1)
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


class TriageNextAction(_TriageContractModel):
    """An unexecuted next action, grounded in supplied evidence."""

    statement: str = Field(min_length=1, max_length=2_000)
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


class TriageResult(_TriageContractModel):
    """A strictly validated proposal that remains non-executing."""

    category: TriageCategory
    summary: str = Field(min_length=1, max_length=4_000)
    facts: tuple[TriageFact, ...] = Field(max_length=64)
    hypotheses: tuple[TriageHypothesis, ...] = Field(max_length=32)
    next_actions: tuple[TriageNextAction, ...] = Field(min_length=1, max_length=16)

    @field_validator("facts", "hypotheses", "next_actions", mode="before")
    @classmethod
    def _freeze_models(cls, value: Any) -> Any:
        return _freeze_tuple(value)


class TriageCompletion(_TriageContractModel):
    """A normalized provider response with no hidden provider transcript."""

    response_id: str | None = Field(default=None, min_length=1, max_length=160)
    result: TriageResult


class TriageContractError(RuntimeError):
    """Stable error for structurally invalid or ungrounded model proposals."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProviderTriageError(RuntimeError):
    """A secret-safe provider failure suitable for a control-plane error map."""

    def __init__(self, code: str, diagnostic: str) -> None:
        self.code = code
        self.diagnostic = diagnostic
        super().__init__(f"{code}: {diagnostic}")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, diagnostic={self.diagnostic!r})"


class MissingTriageAPIKeyError(ProviderTriageError):
    """Raised before a provider transport is called with an empty credential."""

    def __init__(self) -> None:
        super().__init__("missing_api_key", "A provider API key is required")


class TriageTimeoutError(ProviderTriageError):
    """Raised when a bounded provider request exceeds its deadline."""

    def __init__(self) -> None:
        super().__init__("timeout", "The provider request timed out")


class TriageTransportError(ProviderTriageError):
    """Raised for a redacted connection or transport failure."""

    def __init__(self, diagnostic: str) -> None:
        super().__init__("transport_error", diagnostic)


class TriageHTTPError(ProviderTriageError):
    """Raised for a non-success provider response with a redacted diagnostic."""

    def __init__(self, *, status_code: int, diagnostic: str) -> None:
        self.status_code = status_code
        super().__init__("http_error", f"status={status_code}; detail={diagnostic}")


class TriageProtocolError(ProviderTriageError):
    """Raised when a provider returns an invalid, incomplete, or unsafe shape."""

    def __init__(self, code: str) -> None:
        super().__init__(code, "The provider returned an invalid structured triage response")


class TriageResponseTooLargeError(ProviderTriageError):
    """Raised before an oversized provider body is materialized in memory."""

    def __init__(self) -> None:
        super().__init__(
            "response_too_large", "The provider response exceeded the configured limit"
        )


class TriageBackend(Protocol):
    """One bounded, credential-injected proposal-only provider call."""

    name: str

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion: ...


def validate_triage_completion(
    completion: TriageCompletion,
    evidence: Sequence[TriageEvidence],
) -> None:
    """Reject a proposal that cites evidence not present in its request.

    Schema validation alone cannot ensure a model actually stayed within the
    bounded evidence set.  Callers should run this after parsing and before
    persisting any result or using it to guide subsequent work.
    """

    available = {item.id for item in evidence}
    for item in (*completion.result.facts, *completion.result.hypotheses):
        if not set(item.evidence_ids).issubset(available):
            raise TriageContractError("triage_cites_unknown_evidence")
    for item in completion.result.next_actions:
        if not set(item.evidence_ids).issubset(available):
            raise TriageContractError("triage_cites_unknown_evidence")


def triage_result_schema() -> dict[str, Any]:
    """Return a detached JSON Schema for prompt guidance, never mutable global state."""

    return copy.deepcopy(TriageResult.model_json_schema())


def parse_triage_result(value: object) -> TriageResult:
    """Normalize provider JSON without exposing malformed model text in errors."""

    if not isinstance(value, dict):
        raise TriageProtocolError("malformed_structured_output")
    try:
        return TriageResult.model_validate(value)
    except ValidationError:
        raise TriageProtocolError("triage_schema_violation") from None


__all__ = [
    "MissingTriageAPIKeyError",
    "ProviderTriageError",
    "TriageBackend",
    "TriageCategory",
    "TriageCompletion",
    "TriageContractError",
    "TriageEvidence",
    "TriageFact",
    "TriageHTTPError",
    "TriageHypothesis",
    "TriageNextAction",
    "TriageProtocolError",
    "TriageRequest",
    "TriageResponseTooLargeError",
    "TriageResult",
    "TriageTimeoutError",
    "TriageTransportError",
    "parse_triage_result",
    "triage_result_schema",
    "validate_triage_completion",
]
