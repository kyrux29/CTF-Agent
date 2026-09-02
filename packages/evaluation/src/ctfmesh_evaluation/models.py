"""Strict, provider-neutral contracts for paired CTF triage evaluation.

The contracts intentionally retain only reviewed metadata: category labels,
evidence identifiers, proposal validity annotations, elapsed time, and counts
of rejected outputs.  They do not retain prompts, raw model output, API keys,
or flags.  Consequently this package is safe to use for offline benchmark
calculation and has no provider, tool-runtime, or network dependency.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_DURATION_MILLISECONDS = 86_400_000


class EvaluationModel(BaseModel):
    """Strict immutable base for evaluation data crossing a package boundary."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        allow_inf_nan=False,
    )


class TriageCategory(StrEnum):
    """Supported CTF disciplines for benchmark labels and predictions."""

    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    OSINT = "osint"
    MISC = "misc"
    AI_ML = "ai_ml"
    MOBILE = "mobile"
    BLOCKCHAIN = "blockchain"
    HARDWARE = "hardware"
    STEGO = "stego"
    PROGRAMMING = "programming"


class TriageApproach(StrEnum):
    """The two intentionally paired conditions in a benchmark."""

    BASELINE = "baseline"
    AI_ASSISTED = "ai_assisted"


class CategoryVisibility(StrEnum):
    """Whether the gold category was disclosed to the evaluated condition."""

    BLIND = "blind"
    DECLARED = "declared"


class ProposalKind(StrEnum):
    """Bounded proposal types assessed by an independent reviewer."""

    FACT = "fact"
    HYPOTHESIS = "hypothesis"
    NEXT_ACTION = "next_action"


class EvaluationProtocol(EvaluationModel):
    """Frozen metadata required to interpret a paired benchmark honestly.

    Digest values identify reviewed inputs/configuration without storing raw
    prompts, artifacts, transcripts, flags, credentials, or reviewer details.
    """

    suite_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    suite_digest: str = Field(pattern=_SHA256_PATTERN)
    review_protocol_digest: str = Field(pattern=_SHA256_PATTERN)
    baseline_configuration_digest: str = Field(pattern=_SHA256_PATTERN)
    ai_assisted_configuration_digest: str = Field(pattern=_SHA256_PATTERN)
    category_visibility: CategoryVisibility
    repetitions_per_case: int = Field(ge=1, le=100)
    reviewer_count: int = Field(ge=1, le=100)
    timing_method: Literal["monotonic_end_to_end"]

    @field_validator("category_visibility", mode="before")
    @classmethod
    def _parse_category_visibility(cls, value: object) -> object:
        return CategoryVisibility(value) if isinstance(value, str) else value


def _freeze_sequence(value: object) -> object:
    """Accept JSON arrays while retaining immutable tuples internally."""

    return tuple(value) if isinstance(value, list) else value


def _parse_identifier_sequence(value: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    """Validate a canonical, duplicate-free set of opaque identifiers."""

    for item in value:
        if not isinstance(item, str) or not re.fullmatch(_IDENTIFIER_PATTERN, item):
            raise ValueError(f"{field_name} must contain valid opaque identifiers")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} cannot contain duplicates")
    if value != tuple(sorted(value)):
        raise ValueError(f"{field_name} must use deterministic sorted order")
    return value


class TriageCase(EvaluationModel):
    """Gold labels and supplied evidence IDs for one offline triage fixture."""

    case_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    fixture_digest: str = Field(pattern=_SHA256_PATTERN)
    expected_category: TriageCategory
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=512)
    relevant_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=512)

    @field_validator("expected_category", mode="before")
    @classmethod
    def _parse_expected_category(cls, value: object) -> object:
        return TriageCategory(value) if isinstance(value, str) else value

    @field_validator("evidence_ids", "relevant_evidence_ids", mode="before")
    @classmethod
    def _freeze_identifier_sequences(cls, value: object) -> object:
        return _freeze_sequence(value)

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _parse_identifier_sequence(value, "evidence_ids")

    @field_validator("relevant_evidence_ids")
    @classmethod
    def _validate_relevant_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _parse_identifier_sequence(value, "relevant_evidence_ids")

    @model_validator(mode="after")
    def _relevant_evidence_must_be_supplied(self) -> TriageCase:
        if not set(self.relevant_evidence_ids).issubset(self.evidence_ids):
            raise ValueError("relevant_evidence_ids must be a subset of evidence_ids")
        return self


class ProposalAssessment(EvaluationModel):
    """One independently reviewed proposed fact, hypothesis, or next action.

    ``valid`` must be supplied by a reviewer or a deterministic fixture oracle;
    it is never a provider self-assessment.
    """

    proposal_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    kind: ProposalKind
    valid: bool

    @field_validator("kind", mode="before")
    @classmethod
    def _parse_kind(cls, value: object) -> object:
        return ProposalKind(value) if isinstance(value, str) else value


class TriageRecord(EvaluationModel):
    """A reviewed result from exactly one condition for one triage case.

    The model deliberately contains no raw proposal text.  This keeps a
    benchmark focused on independently assessed quality and prevents it from
    becoming a store for flags, credentials, or provider transcripts.
    """

    case_id: str = Field(pattern=_IDENTIFIER_PATTERN, min_length=1, max_length=160)
    approach: TriageApproach
    attempt: int = Field(ge=1, le=100)
    configuration_digest: str = Field(pattern=_SHA256_PATTERN)
    provenance_digest: str = Field(pattern=_SHA256_PATTERN)
    predicted_category: TriageCategory | Literal["unknown"]
    cited_evidence_ids: tuple[str, ...] = Field(default=(), max_length=512)
    proposals: tuple[ProposalAssessment, ...] = Field(default=(), max_length=512)
    elapsed_milliseconds: int = Field(ge=0, le=_MAX_DURATION_MILLISECONDS)
    invalid_output_count: int = Field(ge=0, le=10_000)

    @field_validator("approach", mode="before")
    @classmethod
    def _parse_approach(cls, value: object) -> object:
        return TriageApproach(value) if isinstance(value, str) else value

    @field_validator("predicted_category", mode="before")
    @classmethod
    def _parse_predicted_category(cls, value: object) -> object:
        if isinstance(value, str) and value != "unknown":
            return TriageCategory(value)
        return value

    @field_validator("cited_evidence_ids", "proposals", mode="before")
    @classmethod
    def _freeze_sequences(cls, value: object) -> object:
        return _freeze_sequence(value)

    @field_validator("cited_evidence_ids")
    @classmethod
    def _validate_cited_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _parse_identifier_sequence(value, "cited_evidence_ids")

    @field_validator("proposals")
    @classmethod
    def _validate_unique_proposals(
        cls,
        value: tuple[ProposalAssessment, ...],
    ) -> tuple[ProposalAssessment, ...]:
        proposal_ids = tuple(proposal.proposal_id for proposal in value)
        if len(proposal_ids) != len(set(proposal_ids)):
            raise ValueError("proposals cannot contain duplicate proposal_id values")
        return value


class PairedTriageEvaluation(EvaluationModel):
    """A complete, paired offline comparison of baseline and AI-assisted triage.

    Every case must have exactly one record for each approach.  A rejected or
    malformed provider result is represented by an ``unknown`` prediction and
    a non-zero ``invalid_output_count`` rather than silently dropping the case.
    This preserves comparability without treating a model assertion as truth.
    """

    protocol: EvaluationProtocol
    cases: tuple[TriageCase, ...] = Field(min_length=1, max_length=10_000)
    records: tuple[TriageRecord, ...] = Field(max_length=20_000)

    @field_validator("cases", "records", mode="before")
    @classmethod
    def _freeze_cases_and_records(cls, value: object) -> object:
        return _freeze_sequence(value)

    @model_validator(mode="after")
    def _require_complete_pairing(self) -> PairedTriageEvaluation:
        case_ids = tuple(case.case_id for case in self.cases)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("cases cannot contain duplicate case_id values")

        known_case_ids = set(case_ids)
        records_by_pair: set[tuple[str, TriageApproach, int]] = set()
        for record in self.records:
            if record.case_id not in known_case_ids:
                raise ValueError(f"record references unknown case_id: {record.case_id}")
            if record.attempt > self.protocol.repetitions_per_case:
                raise ValueError("record attempt exceeds protocol repetitions_per_case")
            expected_configuration = (
                self.protocol.baseline_configuration_digest
                if record.approach is TriageApproach.BASELINE
                else self.protocol.ai_assisted_configuration_digest
            )
            if record.configuration_digest != expected_configuration:
                raise ValueError("record configuration_digest does not match its paired condition")
            pair = (record.case_id, record.approach, record.attempt)
            if pair in records_by_pair:
                raise ValueError(
                    "records cannot contain duplicate (case_id, approach, attempt) pairs"
                )
            records_by_pair.add(pair)

        expected_pairs = {
            (case_id, approach, attempt)
            for case_id in case_ids
            for approach in (TriageApproach.BASELINE, TriageApproach.AI_ASSISTED)
            for attempt in range(1, self.protocol.repetitions_per_case + 1)
        }
        if records_by_pair != expected_pairs:
            raise ValueError(
                "records must contain every protocol attempt for baseline and ai_assisted per case"
            )
        return self


class MetricFraction(EvaluationModel):
    """An exact aggregate fraction, undefined only when its denominator is zero."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)

    @model_validator(mode="after")
    def _numerator_cannot_exceed_denominator(self) -> MetricFraction:
        if self.numerator > self.denominator:
            raise ValueError("numerator cannot exceed denominator")
        return self

    @property
    def value(self) -> float | None:
        """Return the ratio or ``None`` when it is not defined."""

        if self.denominator == 0:
            return None
        return self.numerator / self.denominator


class ElapsedTimeStats(EvaluationModel):
    """Deterministic summary of elapsed milliseconds for one benchmark cohort."""

    sample_count: int = Field(ge=0)
    minimum_milliseconds: int | None = Field(default=None, ge=0)
    maximum_milliseconds: int | None = Field(default=None, ge=0)
    mean_milliseconds: float | None = Field(default=None, ge=0)
    median_milliseconds: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_empty_or_nonempty_statistics(self) -> ElapsedTimeStats:
        values = (
            self.minimum_milliseconds,
            self.maximum_milliseconds,
            self.mean_milliseconds,
            self.median_milliseconds,
        )
        if self.sample_count == 0:
            if any(value is not None for value in values):
                raise ValueError("empty elapsed-time statistics must not include values")
            return self
        if any(value is None for value in values):
            raise ValueError("non-empty elapsed-time statistics require all values")
        assert self.minimum_milliseconds is not None
        assert self.maximum_milliseconds is not None
        assert self.mean_milliseconds is not None
        assert self.median_milliseconds is not None
        if self.minimum_milliseconds > self.maximum_milliseconds:
            raise ValueError("minimum_milliseconds cannot exceed maximum_milliseconds")
        if not self.minimum_milliseconds <= self.mean_milliseconds <= self.maximum_milliseconds:
            raise ValueError("mean_milliseconds must be within the observed range")
        if not self.minimum_milliseconds <= self.median_milliseconds <= self.maximum_milliseconds:
            raise ValueError("median_milliseconds must be within the observed range")
        return self


class ConditionMetrics(EvaluationModel):
    """Quality and timing metrics for one condition without any solve claim."""

    record_count: int = Field(ge=0)
    category_accuracy: MetricFraction
    evidence_citation_precision: MetricFraction
    evidence_citation_coverage: MetricFraction
    valid_proposal_rate: MetricFraction
    invalid_output_count: int = Field(ge=0)
    elapsed_time: ElapsedTimeStats

    @model_validator(mode="after")
    def _validate_record_bound_metrics(self) -> ConditionMetrics:
        if self.category_accuracy.denominator > self.record_count:
            raise ValueError("category_accuracy denominator cannot exceed record_count")
        if self.elapsed_time.sample_count != self.record_count:
            raise ValueError("elapsed_time sample_count must equal record_count")
        return self


class MetricDelta(EvaluationModel):
    """AI-assisted minus baseline values; signs are descriptive, not a value judgment."""

    category_accuracy: float | None = None
    evidence_citation_precision: float | None = None
    evidence_citation_coverage: float | None = None
    valid_proposal_rate: float | None = None
    elapsed_mean_milliseconds: float | None = None
    elapsed_median_milliseconds: float | None = None
    invalid_output_count: int


class ConditionComparison(EvaluationModel):
    """Paired metrics and the signed AI-assisted-minus-baseline difference."""

    baseline: ConditionMetrics
    ai_assisted: ConditionMetrics
    ai_assisted_minus_baseline: MetricDelta


class CategoryComparison(EvaluationModel):
    """Comparison subset for cases with a single expected CTF category."""

    category: TriageCategory
    comparison: ConditionComparison

    @field_validator("category", mode="before")
    @classmethod
    def _parse_category(cls, value: object) -> object:
        return TriageCategory(value) if isinstance(value, str) else value


class TriageEvaluationReport(EvaluationModel):
    """A deterministic report over all paired cases and each expected category."""

    protocol: EvaluationProtocol
    category_metric: Literal["blind_routing_accuracy", "not_scored_declared_category"]
    overall: ConditionComparison
    by_category: tuple[CategoryComparison, ...]

    @field_validator("by_category", mode="before")
    @classmethod
    def _freeze_category_comparisons(cls, value: object) -> object:
        return _freeze_sequence(value)

    @field_validator("by_category")
    @classmethod
    def _validate_category_comparisons(
        cls,
        value: tuple[CategoryComparison, ...],
    ) -> tuple[CategoryComparison, ...]:
        categories = tuple(item.category for item in value)
        if len(categories) != len(set(categories)):
            raise ValueError("by_category cannot contain duplicate categories")
        if categories != tuple(sorted(categories, key=str)):
            raise ValueError("by_category must use deterministic sorted category order")
        return value
