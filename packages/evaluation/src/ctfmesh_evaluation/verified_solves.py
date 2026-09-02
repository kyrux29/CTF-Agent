"""Offline M6 contracts for evidence-backed verified-solve evaluation.

The evaluator receives reviewed, secret-free receipts after a run has finished.
It never starts a provider, target, tool, Docker process, or verifier.  This is
important: an evaluation report can describe an unsafe or false ``solved``
outcome, but it can never create one or turn a model self-report into evidence.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from .models import ElapsedTimeStats, EvaluationModel, MetricFraction

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_DURATION_MILLISECONDS = 86_400_000
_CREDENTIAL_SHAPED_IDENTIFIER = re.compile(
    r"(?:^sk-[A-Za-z0-9_-]{8,}$)|(?:^AIza[A-Za-z0-9_-]{20,}$)"
)
_CONDITIONS = (
    "single_session",
    "master_workers_no_hint",
    "master_workers_with_hint",
)


class VerifiedSolveCondition(StrEnum):
    """The three M6 conditions compared using the same model and budget."""

    SINGLE_SESSION = "single_session"
    MASTER_WORKERS_NO_HINT = "master_workers_no_hint"
    MASTER_WORKERS_WITH_HINT = "master_workers_with_hint"


class VerifiedSolveStatus(StrEnum):
    """Terminal outcome captured by the evaluator, not a state transition API."""

    SOLVED = "solved"
    NOT_SOLVED = "not_solved"
    VERIFICATION_REJECTED = "verification_rejected"
    INFRASTRUCTURE_FAILED = "infrastructure_failed"
    CANCELLED = "cancelled"


class EvaluationBudget(EvaluationModel):
    """The common, digest-free resource cap applied to every compared run."""

    wall_time_seconds: int = Field(ge=1, le=86_400)
    max_worker_turns: int = Field(ge=1, le=10_000)
    max_tool_calls: int = Field(ge=0, le=100_000)
    max_http_requests: int = Field(ge=0, le=100_000)
    max_cost_microusd: int = Field(ge=0, le=10_000_000_000)


def _validate_opaque_identifier(value: object, field_name: str) -> str:
    """Reject identifier-shaped API credentials before a report can retain them."""

    if not isinstance(value, str) or re.fullmatch(_IDENTIFIER_PATTERN, value) is None:
        raise ValueError(f"{field_name} must be an opaque identifier")
    # IDs are audit handles, not a fallback secret carrier. Field patterns
    # already reject a conventional ``CTF{...}`` flag; catch provider-key
    # shapes that consist only of otherwise valid identifier characters too.
    if _CREDENTIAL_SHAPED_IDENTIFIER.fullmatch(value) is not None:
        raise ValueError(f"{field_name} must not contain credential-shaped text")
    return value


class VerifiedSolveProtocol(EvaluationModel):
    """Reviewed M6 evaluation configuration shared by every matrix entry.

    A raw seed is deliberately absent: for reset-driven labs a public seed can
    become a flag-reproduction input. ``run_seed_digest`` remains on each run
    record so an operator can match it to protected evaluation evidence.
    """

    schema_version: Literal["ctfmesh.verified-solve-evaluation.v1"] = (
        "ctfmesh.verified-solve-evaluation.v1"
    )
    suite_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    suite_digest: str = Field(pattern=_SHA256_PATTERN)
    model_configuration_digest: str = Field(pattern=_SHA256_PATTERN)
    budget: EvaluationBudget
    repetitions_per_lab_condition: int = Field(ge=5, le=100)
    run_seed_policy: Literal["per-run-secret-seed"] = "per-run-secret-seed"
    internet_access: Literal["disabled"] = "disabled"
    public_answer_retrieval_allowed: Literal[False] = False
    verified_solve_rate_target: float = Field(default=0.6, ge=0.0, le=1.0)

    @field_validator("suite_id", mode="before")
    @classmethod
    def _validate_suite_id(cls, value: object) -> str:
        return _validate_opaque_identifier(value, "suite_id")


class VerifiedSolveLab(EvaluationModel):
    """A reviewed local lab binding, represented only by opaque digests."""

    lab_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    challenge_digest: str = Field(pattern=_SHA256_PATTERN)
    target_image_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("lab_id", mode="before")
    @classmethod
    def _validate_lab_id(cls, value: object) -> str:
        return _validate_opaque_identifier(value, "lab_id")


def _freeze_sequence(value: object) -> object:
    """Accept JSON arrays while retaining immutable tuples in evaluation data."""

    return tuple(value) if isinstance(value, list) else value


def _validate_identifier_sequence(value: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    """Validate opaque IDs without exposing a user-provided value in errors."""

    for item in value:
        _validate_opaque_identifier(item, field_name)
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} cannot contain duplicates")
    return value


class VerifierProofReceipt(EvaluationModel):
    """Secret-free evidence needed to assess a verifier-backed solve outcome.

    ``signature_verified`` is an auditor assertion that the independently
    retained proof was verified against its controller public key before this
    record was written. The raw flag and original candidate never enter the
    evaluation contract.
    """

    proof_artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    verifier_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    replay_count: int = Field(ge=0, le=100)
    reset_ids: tuple[str, ...] = Field(default=(), max_length=100)
    signature_verified: bool

    @field_validator("verifier_id", mode="before")
    @classmethod
    def _validate_verifier_id(cls, value: object) -> str:
        return _validate_opaque_identifier(value, "verifier_id")

    @field_validator("reset_ids", mode="before")
    @classmethod
    def _freeze_reset_ids(cls, value: object) -> object:
        return _freeze_sequence(value)

    @field_validator("reset_ids")
    @classmethod
    def _validate_reset_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_identifier_sequence(value, "reset_ids")

    @model_validator(mode="after")
    def _replay_count_matches_reset_receipts(self) -> VerifierProofReceipt:
        if self.replay_count != len(self.reset_ids):
            raise ValueError("replay_count must match reset_ids length")
        return self

    @property
    def has_two_clean_replays(self) -> bool:
        """Return whether this receipt meets M5's independent-proof minimum."""

        # M5's closed verifier contract performs exactly two fresh replays.
        # Accepting a larger unbound count here would let a different protocol
        # masquerade as the reviewed M5 receipt.
        return self.signature_verified and self.replay_count == 2 and len(self.reset_ids) == 2


class VerifiedSolveRunRecord(EvaluationModel):
    """One completed run in the M6 A/B/C matrix, containing no model text.

    It intentionally permits a ``solved`` status with a missing or insufficient
    receipt. That represents a defect in the evaluated system and must be
    visible as a false solve in the output rather than rejected and hidden.
    """

    run_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    lab_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    condition: VerifiedSolveCondition
    attempt: int = Field(ge=1, le=100)
    run_seed_digest: str = Field(pattern=_SHA256_PATTERN)
    challenge_digest: str = Field(pattern=_SHA256_PATTERN)
    target_image_digest: str = Field(pattern=_SHA256_PATTERN)
    model_configuration_digest: str = Field(pattern=_SHA256_PATTERN)
    prompt_digest: str = Field(pattern=_SHA256_PATTERN)
    skill_pack_digest: str = Field(pattern=_SHA256_PATTERN)
    condition_configuration_digest: str = Field(pattern=_SHA256_PATTERN)
    budget: EvaluationBudget
    status: VerifiedSolveStatus
    agent_claimed_solved: bool = False
    verifier_proof: VerifierProofReceipt | None = None
    elapsed_milliseconds: int = Field(ge=0, le=_MAX_DURATION_MILLISECONDS)
    tool_call_count: int = Field(ge=0, le=100_000)
    task_execution_count: int = Field(ge=0, le=100_000)
    duplicate_execution_count: int = Field(ge=0, le=100_000)
    duplicate_execution_with_reason_count: int = Field(ge=0, le=100_000)
    verification_attempt_count: int = Field(ge=0, le=100_000)
    invalid_worker_output_count: int = Field(ge=0, le=100_000)
    out_of_scope_action_count: int = Field(ge=0, le=100_000)
    public_answer_retrieval_count: int = Field(ge=0, le=100_000)
    active_hint_event_count: int = Field(ge=0, le=100_000)
    reflected_hint_event_count: int = Field(ge=0, le=100_000)
    verifier_timed_out: bool = False
    failure_code: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN, max_length=160)

    @field_validator("run_id", "lab_id", mode="before")
    @classmethod
    def _validate_record_identifiers(cls, value: object, info: ValidationInfo) -> str:
        field_name = info.field_name or "record_identifier"
        return _validate_opaque_identifier(value, field_name)

    @field_validator("failure_code", mode="before")
    @classmethod
    def _validate_failure_code(cls, value: object) -> object:
        if value is None:
            return None
        return _validate_opaque_identifier(value, "failure_code")

    @field_validator("condition", mode="before")
    @classmethod
    def _parse_condition(cls, value: object) -> object:
        return VerifiedSolveCondition(value) if isinstance(value, str) else value

    @field_validator("status", mode="before")
    @classmethod
    def _parse_status(cls, value: object) -> object:
        return VerifiedSolveStatus(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _validate_secret_free_run_counters(self) -> VerifiedSolveRunRecord:
        if self.duplicate_execution_count > self.task_execution_count:
            raise ValueError("duplicate_execution_count cannot exceed task_execution_count")
        if self.duplicate_execution_with_reason_count > self.duplicate_execution_count:
            raise ValueError(
                "duplicate_execution_with_reason_count cannot exceed duplicate_execution_count"
            )
        if self.reflected_hint_event_count > self.active_hint_event_count:
            raise ValueError("reflected_hint_event_count cannot exceed active_hint_event_count")
        if self.condition is not VerifiedSolveCondition.MASTER_WORKERS_WITH_HINT and (
            self.active_hint_event_count != 0 or self.reflected_hint_event_count != 0
        ):
            raise ValueError("only master_workers_with_hint records can carry hint events")
        if self.condition is VerifiedSolveCondition.MASTER_WORKERS_WITH_HINT and (
            self.active_hint_event_count < 1 or self.reflected_hint_event_count < 1
        ):
            raise ValueError("master_workers_with_hint records require a reflected hint event")
        proof = self.verifier_proof
        if proof is not None and proof.has_two_clean_replays:
            if self.status is not VerifiedSolveStatus.SOLVED:
                raise ValueError("a valid verifier proof requires solved status")
            if self.verification_attempt_count < 1:
                raise ValueError("a valid verifier proof requires a verification attempt")
        if self.status is VerifiedSolveStatus.SOLVED and self.failure_code is not None:
            raise ValueError("solved status cannot carry a failure_code")
        if self.status is VerifiedSolveStatus.SOLVED and self.verifier_timed_out:
            raise ValueError("solved status cannot carry a verifier timeout")
        return self

    @property
    def has_valid_verified_solve(self) -> bool:
        """Return true only for a terminal solved state backed by two replays."""

        return (
            self.status is VerifiedSolveStatus.SOLVED
            and self.verifier_proof is not None
            and self.verifier_proof.has_two_clean_replays
        )


class VerifiedSolveEvaluation(EvaluationModel):
    """Complete five-or-more-run A/B/C matrix over reviewed local lab receipts."""

    protocol: VerifiedSolveProtocol
    labs: tuple[VerifiedSolveLab, ...] = Field(min_length=1, max_length=1_000)
    records: tuple[VerifiedSolveRunRecord, ...] = Field(min_length=1, max_length=1_000_000)

    @field_validator("labs", "records", mode="before")
    @classmethod
    def _freeze_labs_and_records(cls, value: object) -> object:
        return _freeze_sequence(value)

    @model_validator(mode="after")
    def _require_complete_comparable_matrix(self) -> VerifiedSolveEvaluation:
        labs_by_id = {lab.lab_id: lab for lab in self.labs}
        if len(labs_by_id) != len(self.labs):
            raise ValueError("labs cannot contain duplicate lab_id values")

        pairs: set[tuple[str, VerifiedSolveCondition, int]] = set()
        run_ids: set[str] = set()
        seed_digests: set[str] = set()
        condition_configs: dict[VerifiedSolveCondition, tuple[str, str, str]] = {}
        for record in self.records:
            lab = labs_by_id.get(record.lab_id)
            if lab is None:
                raise ValueError("record references unknown lab_id")
            if record.attempt > self.protocol.repetitions_per_lab_condition:
                raise ValueError("record attempt exceeds protocol repetitions_per_lab_condition")
            if (
                record.challenge_digest != lab.challenge_digest
                or record.target_image_digest != lab.target_image_digest
            ):
                raise ValueError("record challenge/image digest does not match its lab")
            if record.model_configuration_digest != self.protocol.model_configuration_digest:
                raise ValueError("record model_configuration_digest does not match protocol")
            if record.budget != self.protocol.budget:
                raise ValueError("record budget does not match protocol")
            if record.run_id in run_ids:
                raise ValueError("records cannot contain duplicate run_id values")
            run_ids.add(record.run_id)
            if record.run_seed_digest in seed_digests:
                raise ValueError("records cannot reuse a run_seed_digest")
            seed_digests.add(record.run_seed_digest)
            pair = (record.lab_id, record.condition, record.attempt)
            if pair in pairs:
                raise ValueError(
                    "records cannot contain duplicate (lab_id, condition, attempt) pairs"
                )
            pairs.add(pair)
            configuration = (
                record.prompt_digest,
                record.skill_pack_digest,
                record.condition_configuration_digest,
            )
            previous = condition_configs.setdefault(record.condition, configuration)
            if previous != configuration:
                raise ValueError(
                    "prompt/skill/condition configuration must not drift within a condition"
                )

        expected = {
            (lab_id, VerifiedSolveCondition(condition), attempt)
            for lab_id in labs_by_id
            for condition in _CONDITIONS
            for attempt in range(1, self.protocol.repetitions_per_lab_condition + 1)
        }
        if pairs != expected:
            raise ValueError(
                "records must contain every condition and repetition for each reviewed lab"
            )
        return self


class MetricRatio(EvaluationModel):
    """A non-bounded exact ratio for count-per-solve style operational metrics."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)

    @property
    def value(self) -> float | None:
        """Return the ratio or ``None`` where no denominator exists."""

        if self.denominator == 0:
            return None
        return self.numerator / self.denominator


class VerifiedSolveCohortMetrics(EvaluationModel):
    """Raw counts and derived rates for one condition or one lab/condition cell."""

    run_count: int = Field(ge=0)
    solved_status_count: int = Field(ge=0)
    verified_solve_count: int = Field(ge=0)
    false_solve_count: int = Field(ge=0)
    agent_claimed_solved_count: int = Field(ge=0)
    verification_attempt_count: int = Field(ge=0)
    verified_solve_rate: MetricFraction
    verifier_replay_stability: MetricFraction
    tool_call_count: int = Field(ge=0)
    tool_calls_per_verified_solve: MetricRatio
    task_execution_count: int = Field(ge=0)
    duplicate_execution_count: int = Field(ge=0)
    duplicate_execution_with_reason_count: int = Field(ge=0)
    unexplained_duplicate_execution_count: int = Field(ge=0)
    duplicate_execution_rate: MetricFraction
    invalid_worker_output_count: int = Field(ge=0)
    out_of_scope_action_count: int = Field(ge=0)
    public_answer_retrieval_count: int = Field(ge=0)
    active_hint_event_count: int = Field(ge=0)
    reflected_hint_event_count: int = Field(ge=0)
    hint_reflection_rate: MetricFraction
    verifier_timeout_count: int = Field(ge=0)
    elapsed_time: ElapsedTimeStats

    @model_validator(mode="after")
    def _validate_aggregate_counts(self) -> VerifiedSolveCohortMetrics:
        if self.solved_status_count > self.run_count:
            raise ValueError("solved_status_count cannot exceed run_count")
        if self.verified_solve_count > self.solved_status_count:
            raise ValueError("verified_solve_count cannot exceed solved_status_count")
        if self.false_solve_count != self.solved_status_count - self.verified_solve_count:
            raise ValueError("false_solve_count must equal solved minus verified solve count")
        if self.duplicate_execution_count > self.task_execution_count:
            raise ValueError("duplicate_execution_count cannot exceed task_execution_count")
        if self.duplicate_execution_with_reason_count > self.duplicate_execution_count:
            raise ValueError("duplicate_execution_with_reason_count cannot exceed duplicates")
        if self.unexplained_duplicate_execution_count != (
            self.duplicate_execution_count - self.duplicate_execution_with_reason_count
        ):
            raise ValueError("unexplained duplicate count must match duplicate counters")
        if self.reflected_hint_event_count > self.active_hint_event_count:
            raise ValueError("reflected hint count cannot exceed active hint count")
        if self.elapsed_time.sample_count != self.run_count:
            raise ValueError("elapsed_time sample_count must equal run_count")
        return self


class VerifiedSolveConditionConfiguration(EvaluationModel):
    """Auditable prompt/skill topology digest for one compared condition."""

    condition: VerifiedSolveCondition
    prompt_digest: str = Field(pattern=_SHA256_PATTERN)
    skill_pack_digest: str = Field(pattern=_SHA256_PATTERN)
    condition_configuration_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("condition", mode="before")
    @classmethod
    def _parse_condition(cls, value: object) -> object:
        return VerifiedSolveCondition(value) if isinstance(value, str) else value


class VerifiedSolveConditionReport(EvaluationModel):
    """Overall M6 result for one A/B/C condition."""

    condition: VerifiedSolveCondition
    metrics: VerifiedSolveCohortMetrics

    @field_validator("condition", mode="before")
    @classmethod
    def _parse_condition(cls, value: object) -> object:
        return VerifiedSolveCondition(value) if isinstance(value, str) else value


class VerifiedSolveLabReport(EvaluationModel):
    """Per-lab raw counts prevent an overall rate from hiding a weak lab."""

    lab: VerifiedSolveLab
    by_condition: tuple[VerifiedSolveConditionReport, ...]

    @field_validator("by_condition", mode="before")
    @classmethod
    def _freeze_conditions(cls, value: object) -> object:
        return _freeze_sequence(value)


class VerifiedSolveDelta(EvaluationModel):
    """Descriptive condition-minus-baseline deltas; they do not alter a run."""

    verified_solve_rate: float | None = None
    median_elapsed_milliseconds: float | None = None
    tool_calls_per_verified_solve: float | None = None
    duplicate_execution_rate: float | None = None
    invalid_worker_output_count: int


class VerifiedSolveGateStatus(EvaluationModel):
    """M6 data-gate outcomes, separated from any external test command result."""

    no_false_solved: bool
    all_solved_have_two_replay_proof: bool
    no_out_of_scope_actions: bool
    no_public_answer_retrieval: bool
    all_hint_events_reflected: bool
    duplicate_execution_acceptable: bool
    safety_gate_passed: bool
    all_labs_meet_verified_solve_rate_target: bool
    release_candidate_ready: bool


class VerifiedSolveEvaluationReport(EvaluationModel):
    """Deterministic M6 output with raw counts, configuration, and gate status."""

    schema_version: Literal["ctfmesh.verified-solve-report.v1"] = "ctfmesh.verified-solve-report.v1"
    evaluation_digest: str = Field(pattern=_SHA256_PATTERN)
    protocol: VerifiedSolveProtocol
    condition_configurations: tuple[VerifiedSolveConditionConfiguration, ...]
    overall_by_condition: tuple[VerifiedSolveConditionReport, ...]
    by_lab: tuple[VerifiedSolveLabReport, ...]
    master_workers_no_hint_minus_single_session: VerifiedSolveDelta
    master_workers_with_hint_minus_single_session: VerifiedSolveDelta
    gates: VerifiedSolveGateStatus

    @field_validator("condition_configurations", "overall_by_condition", "by_lab", mode="before")
    @classmethod
    def _freeze_report_sequences(cls, value: object) -> object:
        return _freeze_sequence(value)


__all__ = [
    "EvaluationBudget",
    "MetricRatio",
    "VerifierProofReceipt",
    "VerifiedSolveCohortMetrics",
    "VerifiedSolveCondition",
    "VerifiedSolveConditionConfiguration",
    "VerifiedSolveConditionReport",
    "VerifiedSolveDelta",
    "VerifiedSolveEvaluation",
    "VerifiedSolveEvaluationReport",
    "VerifiedSolveGateStatus",
    "VerifiedSolveLab",
    "VerifiedSolveLabReport",
    "VerifiedSolveProtocol",
    "VerifiedSolveRunRecord",
    "VerifiedSolveStatus",
]
