from __future__ import annotations

import pytest
from ctfmesh_provider_base import (
    TriageCompletion,
    TriageContractError,
    TriageEvidence,
    TriageFact,
    TriageNextAction,
    TriageProtocolError,
    TriageRequest,
    TriageResult,
    parse_triage_result,
    validate_triage_completion,
)


def evidence() -> TriageEvidence:
    return TriageEvidence(
        id="brief",
        kind="challenge",
        content="An authorized CTF attachment is available for read-only triage.",
    )


def completion(*, evidence_id: str = "brief") -> TriageCompletion:
    return TriageCompletion(
        response_id="resp_fixture",
        result=TriageResult(
            category="reverse",
            summary="A native artifact is available for static review.",
            facts=(
                TriageFact(
                    statement="The supplied evidence describes one attachment.",
                    confidence=0.9,
                    evidence_ids=(evidence_id,),
                ),
            ),
            hypotheses=(),
            next_actions=(
                TriageNextAction(
                    statement="Inspect the declared artifact metadata in the authorized workspace.",
                    evidence_ids=(evidence_id,),
                ),
            ),
        ),
    )


def test_triage_request_rejects_duplicate_evidence_ids() -> None:
    with pytest.raises(ValueError, match="evidence IDs cannot contain duplicates"):
        TriageRequest(
            model="operator-model",
            objective="Classify only supplied evidence.",
            authorized_scope="Read-only local case.",
            evidence=(evidence(), evidence()),
        )


def test_completion_cannot_cite_evidence_outside_the_request() -> None:
    with pytest.raises(TriageContractError, match="triage_cites_unknown_evidence"):
        validate_triage_completion(completion(evidence_id="unknown"), (evidence(),))


def test_parser_rejects_unknown_result_fields_without_echoing_model_content() -> None:
    with pytest.raises(TriageProtocolError, match="triage_schema_violation") as raised:
        parse_triage_result(
            {
                "category": "web",
                "summary": "A safe fixture was supplied.",
                "facts": [],
                "hypotheses": [],
                "next_actions": [{"statement": "Inspect the fixture.", "evidence_ids": ["brief"]}],
                "untrusted_model_text": "must not be echoed",
            }
        )

    assert "must not be echoed" not in str(raised.value)
