"""Infrastructure-independent contracts for the durable v0.1 run kernel.

The models in this module deliberately describe identifiers, bounded data, and
digest-pinned references. They never carry a free-form worker context, tool
arguments, provider credentials, or raw flags.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .base import (
    ContractModel,
    FrozenSequence,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    UtcDatetime,
)
from .challenge import ChallengeManifest


class AgentJobKind(StrEnum):
    """Job types understood by the durable control-plane queue."""

    PREFLIGHT = "preflight"
    FAKE_HARNESS = "fake_harness"
    FAKE_VERIFY = "fake_verify"
    # M5 verification is consumed by a separate, non-Pi worker. It has a
    # deliberately different authentication boundary and can only complete
    # through an independent replay proof.
    VERIFY = "verify"
    # Pi work is deliberately expressed as durable control-plane jobs.  The
    # runner never receives a database connection or the authority to invent
    # an action from a model response.
    START_SESSION = "start_session"
    RUN_TURN = "run_turn"
    STEER = "steer"
    ABORT = "abort"
    DISPOSE = "dispose"
    # Power uses a separate lifecycle from v0.1's sealed ContextManifest
    # sessions.  These names make that boundary visible in the durable outbox
    # and prevent a generic Pi worker from accidentally treating a Power
    # workspace as a source-slot task.
    POWER_SESSION_START = "power_session_start"
    POWER_STEER = "power_steer"
    POWER_ABORT = "power_abort"


class AgentRole(StrEnum):
    """Reviewed Pi roles; a model cannot choose an arbitrary capability set."""

    MASTER = "master"
    SOURCE_AUDITOR = "source_auditor"
    HTTP_TESTER = "http_tester"
    EXPLOIT_BUILDER = "exploit_builder"
    FALSIFIER = "falsifier"


class AgentSessionState(StrEnum):
    """Durable lifecycle for a Pi session, separate from the run lifecycle."""

    STARTING = "starting"
    READY = "ready"
    RUNNING = "running"
    ABORTING = "aborting"
    DISPOSED = "disposed"
    FAILED = "failed"


class ToolInvocationState(StrEnum):
    """Durable state for one gateway-authorized tool invocation.

    ``RESERVED`` is intentionally non-retryable.  If a process dies after a
    target-facing dispatch, a duplicate request must observe that uncertain
    state instead of issuing a second side effect.
    """

    RESERVED = "reserved"
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


class AgentEventType(StrEnum):
    """The intentionally small, redacted Pi-to-kernel event vocabulary."""

    SESSION_STARTED = "agent.session.started"
    SESSION_READY = "agent.session.ready"
    TURN_STARTED = "agent.turn.started"
    TURN_COMPLETED = "agent.turn.completed"
    TOOL_STARTED = "agent.tool.started"
    TOOL_COMPLETED = "agent.tool.completed"
    SESSION_RETRY = "agent.session.retry"
    SESSION_COMPACTED = "agent.session.compacted"
    ERROR = "agent.error"


_ROLE_TOOL_IDS: dict[AgentRole, tuple[str, ...]] = {
    # Master retains only control-plane authority. It never receives a source
    # mount, a target alias, or a generic gateway request capability.
    AgentRole.MASTER: (
        "state.get",
        "task.delegate",
        "branch.suspend",
        "verify.request",
        "run.stop",
    ),
    # M3 grants source observers a deliberately small, read-only catalog. A
    # typed gateway checks this sealed tuple again before any slot dispatch.
    AgentRole.SOURCE_AUDITOR: (
        "source.list",
        "source.search",
        "source.read",
        "source.manifest",
        "artifacts.inspect",
        "transform.apply",
        "finding.submit",
    ),
    # HTTP testing is mediated by the same generic Pi tool but the kernel's
    # sealed capability is still granular. The gateway resolves only a
    # manifest-declared alias and a relative request inside a fixed slot.
    AgentRole.HTTP_TESTER: ("http.request", "finding.submit"),
    # An exploit builder can obtain fresh *typed* source/HTTP observations in
    # the M6 exact-instance lane before proposing a plan. It still receives no
    # target URL, shell, generic execution, verification result, or
    # state-transition API: the gateway resolves the sealed source slot and
    # target alias independently for every one of these capabilities.
    AgentRole.EXPLOIT_BUILDER: (
        "source.list",
        "source.search",
        "source.read",
        "source.manifest",
        "artifacts.inspect",
        "transform.apply",
        "http.request",
        "finding.submit",
        # A narrow manifest projection lets the builder select an allowed
        # capture expression without learning target/source data or gaining
        # verifier/control authority.
        "capture.get",
        "candidate.submit",
    ),
    # A falsifier independently checks a worker claim through the same
    # bounded source/HTTP gateway surfaces.  It receives neither execution,
    # candidate, verifier, nor state-transition authority; exact target and
    # artifact scope remain enforced by the context manifest and gateway.
    AgentRole.FALSIFIER: (
        "source.list",
        "source.search",
        "source.read",
        "source.manifest",
        "artifacts.inspect",
        "transform.apply",
        "http.request",
        "finding.submit",
    ),
}


def agent_role_tool_ids(role: AgentRole) -> tuple[str, ...]:
    """Return the reviewed custom-tool allowlist for one agent role."""

    return _ROLE_TOOL_IDS[role]


class RuntimeTaskState(StrEnum):
    """Leaseable worker-task lifecycle; terminal state carries no execution power."""

    QUEUED = "queued"
    LEASED = "leased"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PreflightObservationKind(StrEnum):
    """Observation groups created by the deterministic preflight pass."""

    ARCHIVE_MANIFEST = "archive_manifest"
    FILE_INVENTORY = "file_inventory"
    EXTENSION_HISTOGRAM = "extension_histogram"
    ROUTE_HEURISTIC = "route_heuristic"
    DEPENDENCY_HEURISTIC = "dependency_heuristic"
    REDACTED_SOURCE_SNIPPETS = "redacted_source_snippets"


class ContextBudgetSlice(ContractModel):
    """A bounded allocation, not a mutable budget ledger."""

    tool_calls: int = Field(ge=0, le=1_000_000)
    input_tokens: int = Field(ge=0, le=10_000_000)
    output_tokens: int = Field(ge=0, le=10_000_000)


class ContextEvidenceRef(ContractModel):
    """An observation/artifact pair that a task may cite by immutable digest."""

    observation_id: Identifier
    artifact_id: Identifier
    digest: Sha256Digest


class _ContextManifestPayload(ContractModel):
    """Validated payload used to create and verify a manifest digest."""

    schema_name: Literal["ctfmesh.context-manifest"] = Field(
        "ctfmesh.context-manifest", alias="schema"
    )
    schema_version: Literal[1] = 1
    id: Identifier
    run_id: Identifier
    task_id: Identifier
    challenge_digest: Sha256Digest
    role: Identifier
    objective: NonEmptyText = Field(max_length=4_000)
    allowed_tool_ids: FrozenSequence[Identifier] = Field(min_length=1, max_length=32)
    evidence_refs: FrozenSequence[ContextEvidenceRef] = Field(default_factory=tuple, max_length=128)
    hypothesis_refs: FrozenSequence[Identifier] = Field(default_factory=tuple, max_length=64)
    active_hint_refs: FrozenSequence[Identifier] = Field(default_factory=tuple, max_length=32)
    attempt_fingerprints: FrozenSequence[Sha256Digest] = Field(default_factory=tuple, max_length=64)
    budget_slice: ContextBudgetSlice
    created_at: UtcDatetime
    expires_at: UtcDatetime

    @field_validator(
        "allowed_tool_ids",
        "hypothesis_refs",
        "active_hint_refs",
        "attempt_fingerprints",
    )
    @classmethod
    def _require_unique_scalar_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("context manifest references cannot contain duplicates")
        return values

    @field_validator("evidence_refs")
    @classmethod
    def _require_unique_evidence_references(
        cls, values: tuple[ContextEvidenceRef, ...]
    ) -> tuple[ContextEvidenceRef, ...]:
        observation_ids = tuple(value.observation_id for value in values)
        artifact_ids = tuple(value.artifact_id for value in values)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("context evidence observation IDs cannot contain duplicates")
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("context evidence artifact IDs cannot contain duplicates")
        return values

    @model_validator(mode="after")
    def _require_future_expiry(self) -> _ContextManifestPayload:
        if self.expires_at <= self.created_at:
            raise ValueError("context manifest expiry must be after creation")
        return self


def context_manifest_digest(payload: Mapping[str, Any]) -> str:
    """Return the canonical digest used as a cross-process context identity."""

    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class ContextManifest(_ContextManifestPayload):
    """The sole context envelope a future worker may receive.

    A worker receives evidence references and a bounded budget slice rather
    than an untyped `dict` copied from an orchestrator or operator message.
    """

    digest: Sha256Digest

    @model_validator(mode="after")
    def _digest_must_match_payload(self) -> ContextManifest:
        payload = self.model_dump(mode="json", by_alias=True, exclude={"digest"})
        if self.digest != context_manifest_digest(payload):
            raise ValueError("context_manifest_digest_mismatch")
        return self

    @classmethod
    def issue(cls, **values: Any) -> ContextManifest:
        """Validate, normalize, and sign a payload without a second authority."""

        draft = _ContextManifestPayload.model_validate(values)
        payload = draft.model_dump(mode="json", by_alias=True)
        return cls.model_validate({**payload, "digest": context_manifest_digest(payload)})


class RuntimeTask(ContractModel):
    """A future worker task that points only to a sealed ContextManifest."""

    id: Identifier
    run_id: Identifier
    branch_id: Identifier
    role: Identifier
    objective: NonEmptyText = Field(max_length=4_000)
    required_evidence: FrozenSequence[Identifier] = Field(min_length=1, max_length=32)
    context_manifest_id: Identifier
    lease_version: int = Field(ge=0)
    deadline_at: UtcDatetime

    @field_validator("required_evidence")
    @classmethod
    def _require_unique_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("required evidence cannot contain duplicates")
        return values


class AgentSession(ContractModel):
    """A durable Pi session descriptor with no transcript or credential fields."""

    id: Identifier
    run_id: Identifier
    start_job_id: Identifier
    task_id: Identifier
    context_manifest_id: Identifier
    role: AgentRole
    state: AgentSessionState
    session_store_key: Identifier
    runner_id: Identifier | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @field_validator("role", mode="before")
    @classmethod
    def _parse_role(cls, value: Any) -> Any:
        return AgentRole(value) if isinstance(value, str) else value

    @field_validator("state", mode="before")
    @classmethod
    def _parse_state(cls, value: Any) -> Any:
        return AgentSessionState(value) if isinstance(value, str) else value


class ToolInvocationRequest(ContractModel):
    """Secret-free request metadata crossing from gateway into persistence.

    The actual tool arguments stay inside the typed gateway/slot contract.
    Persistence records only their canonical digest, which makes retries
    comparable without retaining cookies, request bodies, raw flags, or
    source text in the event database.
    """

    tool_call_id: Identifier
    tool_name: Identifier
    tool_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    idempotency_key: Identifier
    input_digest: Sha256Digest


class ToolInvocation(ContractModel):
    """Immutable audit view of a single, typed tool request and outcome."""

    id: Identifier
    run_id: Identifier
    agent_job_id: Identifier
    session_id: Identifier
    task_id: Identifier
    branch_id: Identifier | None = None
    tool_call_id: Identifier
    tool_name: Identifier
    tool_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    idempotency_key: Identifier
    input_digest: Sha256Digest
    policy_decision: Literal["allow", "deny"]
    policy_reason: Identifier
    state: ToolInvocationState
    tool_budget_ledger_id: Identifier | None = None
    http_budget_ledger_id: Identifier | None = None
    result_artifact_id: Identifier | None = None
    result_digest: Sha256Digest | None = None
    result_summary: NonEmptyText | None = Field(default=None, max_length=2_000)
    error_code: Identifier | None = None
    created_at: UtcDatetime
    completed_at: UtcDatetime | None = None

    @field_validator("state", mode="before")
    @classmethod
    def _parse_state(cls, value: Any) -> Any:
        return ToolInvocationState(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _state_matches_outcome(self) -> ToolInvocation:
        has_result = (
            self.result_artifact_id is not None
            or self.result_digest is not None
            or self.result_summary is not None
        )
        if self.state is ToolInvocationState.RESERVED:
            if self.policy_decision != "allow" or has_result or self.error_code is not None:
                raise ValueError("reserved_tool_invocation_has_terminal_outcome")
            if self.completed_at is not None:
                raise ValueError("reserved_tool_invocation_has_completion_time")
        elif self.state is ToolInvocationState.COMPLETED:
            if (
                self.policy_decision != "allow"
                or self.result_artifact_id is None
                or self.result_digest is None
                or self.result_summary is None
                or self.error_code is not None
                or self.completed_at is None
            ):
                raise ValueError("completed_tool_invocation_requires_artifact_outcome")
        elif self.state is ToolInvocationState.DENIED:
            if self.policy_decision != "deny" or has_result or self.error_code is not None:
                raise ValueError("denied_tool_invocation_has_invalid_outcome")
            if self.completed_at is None:
                raise ValueError("denied_tool_invocation_requires_completion_time")
        elif self.state is ToolInvocationState.FAILED:
            if self.policy_decision != "allow" or has_result or self.error_code is None:
                raise ValueError("failed_tool_invocation_requires_error_code")
            if self.completed_at is None:
                raise ValueError("failed_tool_invocation_requires_completion_time")
        return self


class ToolExecutionAuthority(ContractModel):
    """Server-derived authority provided only to the internal gateway.

    This is never sent to Pi Runner.  It ties a tool call to the exact active
    turn lease, sealed task context, and signed challenge manifest before the
    gateway can choose a fixed sandbox slot.
    """

    run_id: Identifier
    challenge_id: Identifier
    agent_job_id: Identifier
    session_id: Identifier
    task_id: Identifier
    branch_id: Identifier
    role: AgentRole
    context_manifest: ContextManifest
    challenge_manifest: ChallengeManifest
    lease_expires_at: UtcDatetime

    @field_validator("role", mode="before")
    @classmethod
    def _parse_role(cls, value: Any) -> Any:
        return AgentRole(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _authority_is_consistent(self) -> ToolExecutionAuthority:
        if (
            self.context_manifest.run_id != self.run_id
            or self.context_manifest.task_id != self.task_id
            or self.context_manifest.role != self.role.value
        ):
            raise ValueError("tool_execution_authority_context_mismatch")
        return self


_RAW_FLAG_PREVIEW = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER_PREVIEW = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_API_KEY_PREVIEW = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


def redact_agent_preview(value: str) -> str:
    """Keep a compact Pi event preview useful without retaining secrets/flags."""

    value = _RAW_FLAG_PREVIEW.sub("[REDACTED_FLAG]", value)
    value = _BEARER_PREVIEW.sub("Bearer [REDACTED]", value)
    return _API_KEY_PREVIEW.sub("[REDACTED_API_KEY]", value)


class AgentBridgeEvent(ContractModel):
    """One typed audit event accepted from a Pi runner.

    Full assistant reasoning, prompt text, tool bodies, session transcript, and
    provider responses are intentionally not represented.  The bridge keeps
    only digests, bounded redacted previews, usage, and stable error codes.
    """

    sequence: int = Field(ge=1, le=10_000)
    type: AgentEventType
    session_id: Identifier
    occurred_at: UtcDatetime
    message_digest: Sha256Digest | None = None
    preview: str | None = Field(default=None, min_length=1, max_length=480)
    tool_name: Identifier | None = None
    input_digest: Sha256Digest | None = None
    output_digest: Sha256Digest | None = None
    input_tokens: int | None = Field(default=None, ge=0, le=10_000_000)
    output_tokens: int | None = Field(default=None, ge=0, le=10_000_000)
    cost_usd: float | None = Field(default=None, ge=0, le=1_000_000)
    retry_attempt: int | None = Field(default=None, ge=1, le=100)
    error_code: Identifier | None = None
    # Prompt contract metadata is an audit digest only. The system prompt and
    # skill-pack text remain in the reviewed runner image, never in the DB.
    prompt_contract_version: int | None = Field(default=None, ge=1, le=1_000)
    prompt_contract_digest: Sha256Digest | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _parse_event_type(cls, value: Any) -> Any:
        return AgentEventType(value) if isinstance(value, str) else value

    @field_validator("preview")
    @classmethod
    def _redact_preview(cls, value: str | None) -> str | None:
        return None if value is None else redact_agent_preview(value)

    @model_validator(mode="after")
    def _validate_event_shape(self) -> AgentBridgeEvent:
        if self.type in {AgentEventType.TOOL_STARTED, AgentEventType.TOOL_COMPLETED}:
            if self.tool_name is None:
                raise ValueError("agent_tool_event_requires_tool_name")
        elif self.tool_name is not None:
            raise ValueError("agent_non_tool_event_cannot_name_tool")
        if self.type is AgentEventType.ERROR and self.error_code is None:
            raise ValueError("agent_error_event_requires_error_code")
        if self.type is not AgentEventType.ERROR and self.error_code is not None:
            raise ValueError("agent_non_error_event_cannot_include_error_code")
        if (self.prompt_contract_version is None) != (self.prompt_contract_digest is None):
            raise ValueError("agent_prompt_contract_metadata_incomplete")
        if (
            self.prompt_contract_digest is not None
            and self.type is not AgentEventType.SESSION_STARTED
        ):
            raise ValueError("agent_prompt_contract_metadata_requires_session_start")
        if self.type is AgentEventType.SESSION_RETRY and self.retry_attempt is None:
            raise ValueError("agent_retry_event_requires_attempt")
        if self.type is not AgentEventType.SESSION_RETRY and self.retry_attempt is not None:
            raise ValueError("agent_non_retry_event_cannot_include_attempt")
        return self


class FindingSubmission(ContractModel):
    """A worker's bounded evidence-backed finding, never a verified flag claim."""

    session_id: Identifier
    tool_call_id: Identifier
    statement: NonEmptyText = Field(max_length=2_000)
    evidence_ids: FrozenSequence[Identifier] = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0, le=1)
    # This labels an unverified observation's relationship to the current
    # hypothesis. It can drive a falsifier task or Hint Card lifecycle, but it
    # cannot promote a fact, candidate, verifier result, or run status.
    disposition: Literal["supports", "contradicts", "inconclusive"] = "inconclusive"

    @field_validator("evidence_ids")
    @classmethod
    def _require_unique_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("finding evidence IDs cannot contain duplicates")
        return values


class TaskDelegationRequest(ContractModel):
    """A master's bounded request for the kernel to create one worker task.

    This is intentionally a proposal rather than a task row.  The kernel owns
    IDs, branch/context construction, budgets, leases, and the Pi start job;
    a model can never manufacture those fields directly.
    """

    tool_call_id: Identifier
    role: AgentRole
    # The master selects only a reviewed technique identifier.  The kernel
    # later binds it to an active HintTemplate (or the neutral review path),
    # rather than treating the value as a tool name or executable instruction.
    technique_id: Identifier = "general.review"
    objective: NonEmptyText = Field(max_length=2_000)
    evidence_ids: FrozenSequence[Identifier] = Field(min_length=1, max_length=32)

    @field_validator("role", mode="before")
    @classmethod
    def _parse_role(cls, value: Any) -> Any:
        return AgentRole(value) if isinstance(value, str) else value

    @field_validator("evidence_ids")
    @classmethod
    def _require_unique_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("delegated task evidence IDs cannot contain duplicates")
        return values

    @model_validator(mode="after")
    def _forbid_nested_master(self) -> TaskDelegationRequest:
        if self.role is AgentRole.MASTER:
            raise ValueError("master_cannot_delegate_master_task")
        return self


class PreflightObservation(ContractModel):
    """A compact evidence record whose complete body is an immutable artifact."""

    id: Identifier
    run_id: Identifier
    kind: PreflightObservationKind
    artifact_id: Identifier
    digest: Sha256Digest
    summary: NonEmptyText = Field(max_length=2_000)
    created_at: UtcDatetime

    @field_validator("kind", mode="before")
    @classmethod
    def _parse_kind(cls, value: Any) -> Any:
        return PreflightObservationKind(value) if isinstance(value, str) else value


class RuntimeArtifact(ContractModel):
    """Metadata for an immutable artifact generated by the runtime itself."""

    id: Identifier
    run_id: Identifier
    sha256: Sha256Digest
    name: NonEmptyText = Field(max_length=240)
    media_type: NonEmptyText = Field(max_length=160)
    size_bytes: int = Field(ge=0, le=1_099_511_627_776)
    classification: Literal["public", "internal", "secret", "flag"] = "internal"
    producer: Identifier
    locator: NonEmptyText = Field(max_length=500)
    created_at: UtcDatetime


class CleanReplay(ContractModel):
    """One deterministic replay result supplied by the independent verifier."""

    attempt: int = Field(ge=1, le=100)
    reset_id: Identifier
    passed: Literal[True]
    started_from_clean_reset: Literal[True]


class VerificationProof(ContractModel):
    """Opaque replay proof; raw flags are intentionally absent from this contract."""

    id: Identifier
    run_id: Identifier
    artifact_id: Identifier
    digest: Sha256Digest
    replays: FrozenSequence[CleanReplay] = Field(min_length=1, max_length=100)
    created_at: UtcDatetime

    @field_validator("replays")
    @classmethod
    def _require_unique_replay_attempts(
        cls, values: tuple[CleanReplay, ...]
    ) -> tuple[CleanReplay, ...]:
        attempts = tuple(value.attempt for value in values)
        if len(attempts) != len(set(attempts)):
            raise ValueError("verification replay attempts cannot contain duplicates")
        return values
