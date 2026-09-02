"""Offline, provider-neutral evaluation contracts for CTFMesh.

This package only calculates deterministic benchmark metrics from reviewed
receipts. It performs no provider calls, tool invocations, network access, or
challenge solving.
"""

from .metrics import evaluate_paired_triage
from .models import (
    CategoryComparison,
    CategoryVisibility,
    ConditionComparison,
    ConditionMetrics,
    ElapsedTimeStats,
    EvaluationModel,
    EvaluationProtocol,
    MetricDelta,
    MetricFraction,
    PairedTriageEvaluation,
    ProposalAssessment,
    ProposalKind,
    TriageApproach,
    TriageCase,
    TriageCategory,
    TriageEvaluationReport,
    TriageRecord,
)
from .verified_metrics import evaluate_verified_solves
from .verified_solves import (
    EvaluationBudget,
    MetricRatio,
    VerifiedSolveCohortMetrics,
    VerifiedSolveCondition,
    VerifiedSolveConditionConfiguration,
    VerifiedSolveConditionReport,
    VerifiedSolveDelta,
    VerifiedSolveEvaluation,
    VerifiedSolveEvaluationReport,
    VerifiedSolveGateStatus,
    VerifiedSolveLab,
    VerifiedSolveLabReport,
    VerifiedSolveProtocol,
    VerifiedSolveRunRecord,
    VerifiedSolveStatus,
    VerifierProofReceipt,
)

__all__ = [
    "CategoryComparison",
    "CategoryVisibility",
    "ConditionComparison",
    "ConditionMetrics",
    "EvaluationBudget",
    "ElapsedTimeStats",
    "EvaluationProtocol",
    "EvaluationModel",
    "MetricDelta",
    "MetricFraction",
    "MetricRatio",
    "PairedTriageEvaluation",
    "ProposalAssessment",
    "ProposalKind",
    "TriageApproach",
    "TriageCase",
    "TriageCategory",
    "TriageEvaluationReport",
    "TriageRecord",
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
    "evaluate_paired_triage",
    "evaluate_verified_solves",
]
