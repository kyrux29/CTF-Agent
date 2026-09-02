from __future__ import annotations

from typing import Literal

import pytest
from ctfmesh_provider_base import (
    CouncilClaim,
    CouncilCompletion,
    CouncilContractError,
    CouncilCritique,
    CouncilDecision,
    CouncilEvidence,
    CouncilRole,
    CouncilTask,
    ModelProfile,
    validate_council_completion,
)
from pydantic import ValidationError


def _profile(
    role: CouncilRole = CouncilRole.SCOUT,
    *,
    profile_id: str = "demo-test-scout",
) -> ModelProfile:
    return ModelProfile(
        id=profile_id,
        provider="simulation",
        model_id="scripted-v1",
        family="simulation",
        roles=(role,),
        structured_output="strict",
        demo=True,
    )


def _task() -> CouncilTask:
    return CouncilTask(
        id="task.demo.scout",
        run_id="run_demo",
        round=1,
        role=CouncilRole.SCOUT,
        profile=_profile(),
        objective="Propose an evidence-cited hypothesis.",
        evidence=(
            CouncilEvidence(
                id="artifact_1",
                digest="a" * 64,
                summary="A declared offline artifact.",
            ),
        ),
    )


def _candidate_claim(*, claim_id: str = "claim_1") -> CouncilClaim:
    return CouncilClaim(
        id=claim_id,
        branch_id="branch_1",
        role=CouncilRole.SCOUT,
        profile_id="demo-test-scout",
        statement="A claim grounded in the supplied artifact.",
        confidence=0.5,
        evidence_ids=("artifact_1",),
        prediction="A bounded observation would confirm it.",
        falsifier="A bounded observation would reject it.",
    )


def _critique(
    *,
    claim_id: str = "claim_1",
    verdict: Literal["supported", "unsupported", "rejected"] = "supported",
) -> CouncilCritique:
    return CouncilCritique(
        claim_id=claim_id,
        verdict=verdict,
        reason="The supplied artifact supports this bounded judgement.",
        evidence_ids=("artifact_1",),
    )


def test_council_validation_rejects_claims_that_cite_unsupplied_evidence() -> None:
    task = _task()
    completion = CouncilCompletion(
        claims=(
            CouncilClaim(
                id="claim_1",
                branch_id="branch_1",
                role=CouncilRole.SCOUT,
                profile_id=task.profile.id,
                statement="A claim with a forged citation.",
                confidence=0.5,
                evidence_ids=("artifact_missing",),
                prediction="A bounded observation would confirm it.",
                falsifier="A bounded observation would reject it.",
            ),
        )
    )
    with pytest.raises(CouncilContractError, match="completion_cites_unknown_evidence"):
        validate_council_completion(task, completion)


def test_non_falsifier_cannot_submit_a_critique() -> None:
    """Only the dedicated falsifier may challenge a candidate claim."""

    task = CouncilTask(
        id="task.demo.adjudicator.untrusted-critique",
        run_id="run_demo",
        round=3,
        role=CouncilRole.ADJUDICATOR,
        profile=_profile(
            CouncilRole.ADJUDICATOR,
            profile_id="demo-test-adjudicator",
        ),
        objective="Select only a reviewed claim.",
        evidence=(
            CouncilEvidence(
                id="artifact_1",
                digest="a" * 64,
                summary="A declared offline artifact.",
            ),
        ),
        candidate_claims=(_candidate_claim(),),
        candidate_critiques=(_critique(),),
    )

    with pytest.raises(
        CouncilContractError,
        match="completion_content_forbidden_for_adjudicator",
    ):
        validate_council_completion(task, CouncilCompletion(critiques=(_critique(),)))


def test_adjudicator_task_requires_supplied_falsifier_critiques() -> None:
    """An adjudicator must see independent review, not only raw claims."""

    with pytest.raises(
        ValidationError,
        match="adjudication tasks require candidate claims and critiques",
    ):
        CouncilTask(
            id="task.demo.adjudicator",
            run_id="run_demo",
            round=3,
            role=CouncilRole.ADJUDICATOR,
            profile=_profile(
                CouncilRole.ADJUDICATOR,
                profile_id="demo-test-adjudicator",
            ),
            objective="Select only a reviewed claim.",
            evidence=(
                CouncilEvidence(
                    id="artifact_1",
                    digest="a" * 64,
                    summary="A declared offline artifact.",
                ),
            ),
            candidate_claims=(_candidate_claim(),),
            candidate_critiques=(),
        )


def test_adjudicator_cannot_select_a_claim_rejected_by_the_falsifier() -> None:
    """A rejected branch stays visible but is unavailable for selection."""

    task = CouncilTask(
        id="task.demo.adjudicator.rejected",
        run_id="run_demo",
        round=3,
        role=CouncilRole.ADJUDICATOR,
        profile=_profile(
            CouncilRole.ADJUDICATOR,
            profile_id="demo-test-adjudicator",
        ),
        objective="Select only a reviewed claim.",
        evidence=(
            CouncilEvidence(
                id="artifact_1",
                digest="a" * 64,
                summary="A declared offline artifact.",
            ),
        ),
        candidate_claims=(_candidate_claim(),),
        candidate_critiques=(_critique(verdict="rejected"),),
    )
    completion = CouncilCompletion(
        decision=CouncilDecision(
            outcome="accept",
            selected_claim_ids=("claim_1",),
            evidence_ids=("artifact_1",),
            summary="Select the candidate despite the falsifier result.",
        )
    )

    with pytest.raises(
        CouncilContractError,
        match="completion_selects_disqualified_claim",
    ):
        validate_council_completion(task, completion)


def test_task_rejects_duplicate_evidence_and_candidate_claim_ids() -> None:
    """Task-local identity sets must be unambiguous before a model sees them."""

    evidence = CouncilEvidence(
        id="artifact_1",
        digest="a" * 64,
        summary="A declared offline artifact.",
    )
    with pytest.raises(ValidationError, match="task evidence IDs cannot contain duplicates"):
        CouncilTask(
            id="task.demo.duplicate-evidence",
            run_id="run_demo",
            round=1,
            role=CouncilRole.SCOUT,
            profile=_profile(),
            objective="Propose an evidence-cited hypothesis.",
            evidence=(evidence, evidence),
        )

    with pytest.raises(
        ValidationError,
        match="task candidate claim IDs cannot contain duplicates",
    ):
        CouncilTask(
            id="task.demo.duplicate-claims",
            run_id="run_demo",
            round=2,
            role=CouncilRole.SCOUT,
            profile=_profile(),
            objective="Review an existing branch.",
            evidence=(evidence,),
            candidate_claims=(_candidate_claim(), _candidate_claim()),
        )


def test_completion_rejects_duplicate_generated_claim_ids() -> None:
    """A completion cannot create two different records with one claim identity."""

    duplicate = _candidate_claim()
    with pytest.raises(ValidationError, match="completion claim IDs cannot contain duplicates"):
        CouncilCompletion(claims=(duplicate, duplicate))
