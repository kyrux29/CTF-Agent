from __future__ import annotations

import hashlib

import pytest
from ctfmesh_evaluation import (
    CategoryVisibility,
    EvaluationProtocol,
    PairedTriageEvaluation,
    ProposalAssessment,
    ProposalKind,
    TriageApproach,
    TriageCase,
    TriageCategory,
    TriageRecord,
    evaluate_paired_triage,
)
from pydantic import ValidationError


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _protocol(
    *,
    category_visibility: CategoryVisibility = CategoryVisibility.BLIND,
    repetitions_per_case: int = 1,
) -> EvaluationProtocol:
    return EvaluationProtocol(
        suite_id="reviewed-local-suite",
        suite_digest=_digest("suite"),
        review_protocol_digest=_digest("review-protocol"),
        baseline_configuration_digest=_digest("baseline-config"),
        ai_assisted_configuration_digest=_digest("ai-assisted-config"),
        category_visibility=category_visibility,
        repetitions_per_case=repetitions_per_case,
        reviewer_count=2,
        timing_method="monotonic_end_to_end",
    )


def _case(
    *,
    case_id: str,
    expected_category: TriageCategory,
    evidence_ids: tuple[str, ...],
    relevant_evidence_ids: tuple[str, ...],
) -> TriageCase:
    return TriageCase(
        case_id=case_id,
        fixture_digest=_digest(f"fixture:{case_id}"),
        expected_category=expected_category,
        evidence_ids=evidence_ids,
        relevant_evidence_ids=relevant_evidence_ids,
    )


def _record(
    *,
    case_id: str,
    approach: TriageApproach,
    predicted_category: TriageCategory | str,
    elapsed_milliseconds: int,
    invalid_output_count: int,
    cited_evidence_ids: tuple[str, ...] = (),
    proposals: tuple[ProposalAssessment, ...] = (),
    attempt: int = 1,
) -> TriageRecord:
    configuration_digest = _digest(
        "baseline-config" if approach is TriageApproach.BASELINE else "ai-assisted-config"
    )
    return TriageRecord(
        case_id=case_id,
        approach=approach,
        attempt=attempt,
        configuration_digest=configuration_digest,
        provenance_digest=_digest(f"{case_id}:{approach.value}:{attempt}"),
        predicted_category=predicted_category,  # type: ignore[arg-type]
        cited_evidence_ids=cited_evidence_ids,
        proposals=proposals,
        elapsed_milliseconds=elapsed_milliseconds,
        invalid_output_count=invalid_output_count,
    )


def _paired_evaluation() -> PairedTriageEvaluation:
    return PairedTriageEvaluation(
        protocol=_protocol(),
        cases=(
            _case(
                case_id="crypto-case",
                expected_category=TriageCategory.CRYPTO,
                evidence_ids=("crypto-brief", "crypto-file", "crypto-hint"),
                relevant_evidence_ids=("crypto-brief", "crypto-hint"),
            ),
            _case(
                case_id="web-case",
                expected_category=TriageCategory.WEB,
                evidence_ids=("web-brief", "web-log"),
                relevant_evidence_ids=("web-log",),
            ),
        ),
        records=(
            _record(
                case_id="crypto-case",
                approach=TriageApproach.BASELINE,
                predicted_category=TriageCategory.WEB,
                cited_evidence_ids=("crypto-file",),
                proposals=(
                    ProposalAssessment(
                        proposal_id="baseline-crypto-fact",
                        kind=ProposalKind.FACT,
                        valid=False,
                    ),
                ),
                elapsed_milliseconds=1_000,
                invalid_output_count=1,
            ),
            _record(
                case_id="crypto-case",
                approach=TriageApproach.AI_ASSISTED,
                predicted_category=TriageCategory.CRYPTO,
                cited_evidence_ids=("crypto-brief", "crypto-hint"),
                proposals=(
                    ProposalAssessment(
                        proposal_id="assisted-crypto-fact",
                        kind=ProposalKind.FACT,
                        valid=True,
                    ),
                    ProposalAssessment(
                        proposal_id="assisted-crypto-action",
                        kind=ProposalKind.NEXT_ACTION,
                        valid=True,
                    ),
                ),
                elapsed_milliseconds=500,
                invalid_output_count=0,
            ),
            _record(
                case_id="web-case",
                approach=TriageApproach.BASELINE,
                predicted_category=TriageCategory.WEB,
                cited_evidence_ids=("web-log",),
                proposals=(
                    ProposalAssessment(
                        proposal_id="baseline-web-action",
                        kind=ProposalKind.NEXT_ACTION,
                        valid=True,
                    ),
                ),
                elapsed_milliseconds=800,
                invalid_output_count=0,
            ),
            _record(
                case_id="web-case",
                approach=TriageApproach.AI_ASSISTED,
                predicted_category=TriageCategory.WEB,
                cited_evidence_ids=("web-brief",),
                proposals=(
                    ProposalAssessment(
                        proposal_id="assisted-web-hypothesis",
                        kind=ProposalKind.HYPOTHESIS,
                        valid=False,
                    ),
                ),
                elapsed_milliseconds=700,
                invalid_output_count=2,
            ),
        ),
    )


def test_evaluation_aggregates_quality_timing_and_invalid_output_metrics() -> None:
    report = evaluate_paired_triage(_paired_evaluation())

    baseline = report.overall.baseline
    assisted = report.overall.ai_assisted
    delta = report.overall.ai_assisted_minus_baseline

    assert baseline.record_count == 2
    assert baseline.category_accuracy.model_dump() == {"numerator": 1, "denominator": 2}
    assert baseline.category_accuracy.value == 0.5
    assert baseline.evidence_citation_precision.model_dump() == {"numerator": 1, "denominator": 2}
    assert baseline.evidence_citation_coverage.model_dump() == {"numerator": 1, "denominator": 3}
    assert baseline.valid_proposal_rate.model_dump() == {"numerator": 1, "denominator": 2}
    assert baseline.invalid_output_count == 1
    assert baseline.elapsed_time.model_dump() == {
        "sample_count": 2,
        "minimum_milliseconds": 800,
        "maximum_milliseconds": 1_000,
        "mean_milliseconds": 900.0,
        "median_milliseconds": 900.0,
    }

    assert assisted.category_accuracy.value == 1.0
    assert assisted.evidence_citation_precision.model_dump() == {"numerator": 2, "denominator": 3}
    assert assisted.evidence_citation_coverage.model_dump() == {"numerator": 2, "denominator": 3}
    assert assisted.valid_proposal_rate.model_dump() == {"numerator": 2, "denominator": 3}
    assert assisted.invalid_output_count == 2
    assert assisted.elapsed_time.mean_milliseconds == 600.0
    assert delta.category_accuracy == 0.5
    assert delta.evidence_citation_precision == pytest.approx(1 / 6)
    assert delta.evidence_citation_coverage == pytest.approx(1 / 3)
    assert delta.valid_proposal_rate == pytest.approx(1 / 6)
    assert delta.elapsed_mean_milliseconds == -300.0
    assert delta.elapsed_median_milliseconds == -300.0
    assert delta.invalid_output_count == 1

    assert tuple(item.category for item in report.by_category) == (
        TriageCategory.CRYPTO,
        TriageCategory.WEB,
    )
    assert report.by_category[0].comparison.baseline.category_accuracy.value == 0.0
    assert report.by_category[1].comparison.ai_assisted.category_accuracy.value == 1.0


def test_evaluation_is_invariant_to_input_order() -> None:
    evaluation = _paired_evaluation()
    reordered = PairedTriageEvaluation(
        protocol=evaluation.protocol,
        cases=tuple(reversed(evaluation.cases)),
        records=tuple(reversed(evaluation.records)),
    )

    assert evaluate_paired_triage(evaluation) == evaluate_paired_triage(reordered)


def test_empty_proposals_leave_valid_proposal_rate_undefined() -> None:
    evaluation = PairedTriageEvaluation(
        protocol=_protocol(category_visibility=CategoryVisibility.DECLARED),
        cases=(
            _case(
                case_id="misc-case",
                expected_category=TriageCategory.MISC,
                evidence_ids=("brief",),
                relevant_evidence_ids=("brief",),
            ),
        ),
        records=(
            _record(
                case_id="misc-case",
                approach=TriageApproach.BASELINE,
                predicted_category="unknown",
                elapsed_milliseconds=10,
                invalid_output_count=1,
            ),
            _record(
                case_id="misc-case",
                approach=TriageApproach.AI_ASSISTED,
                predicted_category=TriageCategory.MISC,
                elapsed_milliseconds=20,
                invalid_output_count=0,
            ),
        ),
    )

    report = evaluate_paired_triage(evaluation)

    assert report.overall.baseline.valid_proposal_rate.value is None
    assert report.overall.ai_assisted.valid_proposal_rate.value is None
    assert report.overall.ai_assisted_minus_baseline.valid_proposal_rate is None
    assert report.overall.baseline.evidence_citation_precision.value is None
    assert report.overall.baseline.evidence_citation_coverage.value == 0.0
    assert report.category_metric == "not_scored_declared_category"
    assert report.overall.ai_assisted.category_accuracy.value is None


@pytest.mark.parametrize(
    ("cases", "records", "message"),
    [
        (
            (
                _case(
                    case_id="case-one",
                    expected_category=TriageCategory.CRYPTO,
                    evidence_ids=("brief",),
                    relevant_evidence_ids=("brief",),
                ),
            ),
            (
                _record(
                    case_id="case-one",
                    approach=TriageApproach.BASELINE,
                    predicted_category=TriageCategory.CRYPTO,
                    elapsed_milliseconds=1,
                    invalid_output_count=0,
                ),
            ),
            "every protocol attempt",
        ),
        (
            (
                _case(
                    case_id="case-two",
                    expected_category=TriageCategory.PWN,
                    evidence_ids=("brief",),
                    relevant_evidence_ids=("brief",),
                ),
            ),
            (
                _record(
                    case_id="unknown-case",
                    approach=TriageApproach.BASELINE,
                    predicted_category=TriageCategory.PWN,
                    elapsed_milliseconds=1,
                    invalid_output_count=0,
                ),
                _record(
                    case_id="case-two",
                    approach=TriageApproach.AI_ASSISTED,
                    predicted_category=TriageCategory.PWN,
                    elapsed_milliseconds=1,
                    invalid_output_count=0,
                ),
            ),
            "unknown case_id",
        ),
    ],
)
def test_pairing_rejects_incomplete_or_unknown_records(
    cases: tuple[TriageCase, ...],
    records: tuple[TriageRecord, ...],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        PairedTriageEvaluation(protocol=_protocol(), cases=cases, records=records)


def test_case_rejects_unknown_gold_evidence_and_record_rejects_duplicate_citations() -> None:
    with pytest.raises(ValidationError, match="subset"):
        _case(
            case_id="bad-case",
            expected_category=TriageCategory.FORENSICS,
            evidence_ids=("provided",),
            relevant_evidence_ids=("not-provided",),
        )

    with pytest.raises(ValidationError, match="duplicates"):
        _record(
            case_id="bad-case",
            approach=TriageApproach.BASELINE,
            predicted_category=TriageCategory.FORENSICS,
            cited_evidence_ids=("same", "same"),
            elapsed_milliseconds=1,
            invalid_output_count=0,
        )


def test_evaluation_rejects_mixed_configuration_and_missing_repetition() -> None:
    cases = (
        _case(
            case_id="repeat-case",
            expected_category=TriageCategory.REVERSE,
            evidence_ids=("brief",),
            relevant_evidence_ids=("brief",),
        ),
    )
    protocol = _protocol(repetitions_per_case=2)
    records = (
        _record(
            case_id="repeat-case",
            approach=TriageApproach.BASELINE,
            attempt=1,
            predicted_category=TriageCategory.REVERSE,
            elapsed_milliseconds=10,
            invalid_output_count=0,
        ),
        _record(
            case_id="repeat-case",
            approach=TriageApproach.AI_ASSISTED,
            attempt=1,
            predicted_category=TriageCategory.REVERSE,
            elapsed_milliseconds=10,
            invalid_output_count=0,
        ),
    )
    with pytest.raises(ValidationError, match="every protocol attempt"):
        PairedTriageEvaluation(protocol=protocol, cases=cases, records=records)

    bad_configuration = records[0].model_copy(update={"configuration_digest": _digest("other")})
    complete_records = (
        bad_configuration,
        _record(
            case_id="repeat-case",
            approach=TriageApproach.BASELINE,
            attempt=2,
            predicted_category=TriageCategory.REVERSE,
            elapsed_milliseconds=10,
            invalid_output_count=0,
        ),
        records[1],
        _record(
            case_id="repeat-case",
            approach=TriageApproach.AI_ASSISTED,
            attempt=2,
            predicted_category=TriageCategory.REVERSE,
            elapsed_milliseconds=10,
            invalid_output_count=0,
        ),
    )
    with pytest.raises(ValidationError, match="configuration_digest"):
        PairedTriageEvaluation(protocol=protocol, cases=cases, records=complete_records)
