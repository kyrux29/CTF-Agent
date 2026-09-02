"""Pure deterministic aggregation for paired CTF triage evaluation records."""

from __future__ import annotations

from collections.abc import Iterable
from statistics import median

from .models import (
    CategoryComparison,
    CategoryVisibility,
    ConditionComparison,
    ConditionMetrics,
    ElapsedTimeStats,
    EvaluationProtocol,
    MetricDelta,
    MetricFraction,
    PairedTriageEvaluation,
    TriageApproach,
    TriageCase,
    TriageEvaluationReport,
    TriageRecord,
)


def evaluate_paired_triage(evaluation: PairedTriageEvaluation) -> TriageEvaluationReport:
    """Compare paired baseline and AI-assisted triage records.

    The function performs no I/O and does not infer whether a challenge was
    solved.  Metrics are calculated from the supplied independently reviewed
    labels only.  It is invariant to the order of input cases and records.
    """

    cases_by_id = {case.case_id: case for case in evaluation.cases}
    records = tuple(
        sorted(
            evaluation.records,
            key=lambda record: (record.case_id, record.approach.value),
        )
    )
    overall = _build_comparison(cases_by_id, records, protocol=evaluation.protocol)

    categories = tuple(sorted({case.expected_category for case in evaluation.cases}, key=str))
    by_category = tuple(
        CategoryComparison(
            category=category,
            comparison=_build_comparison(
                cases_by_id,
                tuple(
                    record
                    for record in records
                    if cases_by_id[record.case_id].expected_category is category
                ),
                protocol=evaluation.protocol,
            ),
        )
        for category in categories
    )
    category_metric = (
        "blind_routing_accuracy"
        if evaluation.protocol.category_visibility is CategoryVisibility.BLIND
        else "not_scored_declared_category"
    )
    return TriageEvaluationReport(
        protocol=evaluation.protocol,
        category_metric=category_metric,
        overall=overall,
        by_category=by_category,
    )


def _build_comparison(
    cases_by_id: dict[str, TriageCase],
    records: tuple[TriageRecord, ...],
    *,
    protocol: EvaluationProtocol,
) -> ConditionComparison:
    baseline = _summarize_condition(
        cases_by_id,
        (record for record in records if record.approach is TriageApproach.BASELINE),
        protocol=protocol,
    )
    ai_assisted = _summarize_condition(
        cases_by_id,
        (record for record in records if record.approach is TriageApproach.AI_ASSISTED),
        protocol=protocol,
    )
    return ConditionComparison(
        baseline=baseline,
        ai_assisted=ai_assisted,
        ai_assisted_minus_baseline=_build_delta(baseline, ai_assisted),
    )


def _summarize_condition(
    cases_by_id: dict[str, TriageCase],
    records: Iterable[TriageRecord],
    *,
    protocol: EvaluationProtocol,
) -> ConditionMetrics:
    materialized_records = tuple(records)
    category_correct_count = 0
    relevant_citation_count = 0
    citation_count = 0
    available_relevant_evidence_count = 0
    valid_proposal_count = 0
    proposal_count = 0
    invalid_output_count = 0
    elapsed_milliseconds: list[int] = []

    for record in materialized_records:
        case = cases_by_id[record.case_id]
        if protocol.category_visibility is CategoryVisibility.BLIND:
            category_correct_count += int(record.predicted_category == case.expected_category)

        relevant_evidence_ids = set(case.relevant_evidence_ids)
        relevant_citation_count += len(set(record.cited_evidence_ids) & relevant_evidence_ids)
        citation_count += len(record.cited_evidence_ids)
        available_relevant_evidence_count += len(relevant_evidence_ids)

        valid_proposal_count += sum(int(proposal.valid) for proposal in record.proposals)
        proposal_count += len(record.proposals)
        invalid_output_count += record.invalid_output_count
        elapsed_milliseconds.append(record.elapsed_milliseconds)

    record_count = len(materialized_records)
    category_denominator = (
        record_count if protocol.category_visibility is CategoryVisibility.BLIND else 0
    )
    return ConditionMetrics(
        record_count=record_count,
        category_accuracy=MetricFraction(
            numerator=category_correct_count,
            denominator=category_denominator,
        ),
        evidence_citation_precision=MetricFraction(
            numerator=relevant_citation_count,
            denominator=citation_count,
        ),
        evidence_citation_coverage=MetricFraction(
            numerator=relevant_citation_count,
            denominator=available_relevant_evidence_count,
        ),
        valid_proposal_rate=MetricFraction(
            numerator=valid_proposal_count,
            denominator=proposal_count,
        ),
        invalid_output_count=invalid_output_count,
        elapsed_time=_elapsed_time_stats(elapsed_milliseconds),
    )


def _elapsed_time_stats(values: list[int]) -> ElapsedTimeStats:
    if not values:
        return ElapsedTimeStats(sample_count=0)
    return ElapsedTimeStats(
        sample_count=len(values),
        minimum_milliseconds=min(values),
        maximum_milliseconds=max(values),
        mean_milliseconds=sum(values) / len(values),
        median_milliseconds=float(median(values)),
    )


def _build_delta(baseline: ConditionMetrics, ai_assisted: ConditionMetrics) -> MetricDelta:
    """Build signed differences while preserving undefined denominator cases."""

    return MetricDelta(
        category_accuracy=_difference(
            baseline.category_accuracy.value,
            ai_assisted.category_accuracy.value,
        ),
        evidence_citation_precision=_difference(
            baseline.evidence_citation_precision.value,
            ai_assisted.evidence_citation_precision.value,
        ),
        evidence_citation_coverage=_difference(
            baseline.evidence_citation_coverage.value,
            ai_assisted.evidence_citation_coverage.value,
        ),
        valid_proposal_rate=_difference(
            baseline.valid_proposal_rate.value,
            ai_assisted.valid_proposal_rate.value,
        ),
        elapsed_mean_milliseconds=_difference(
            baseline.elapsed_time.mean_milliseconds,
            ai_assisted.elapsed_time.mean_milliseconds,
        ),
        elapsed_median_milliseconds=_difference(
            baseline.elapsed_time.median_milliseconds,
            ai_assisted.elapsed_time.median_milliseconds,
        ),
        invalid_output_count=ai_assisted.invalid_output_count - baseline.invalid_output_count,
    )


def _difference(baseline: float | None, ai_assisted: float | None) -> float | None:
    if baseline is None or ai_assisted is None:
        return None
    return ai_assisted - baseline
