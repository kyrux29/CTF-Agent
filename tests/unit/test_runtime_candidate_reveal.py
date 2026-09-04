"""Regression coverage for precise Power candidate capture."""

from __future__ import annotations

from pathlib import Path

import pytest
from ctfmesh_api.runtime_candidate_reveal import (
    RuntimeCandidateArtifact,
    RuntimeCandidateRevealService,
)
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_tools import LocalArtifactStore


@pytest.mark.asyncio
async def test_configured_wildcard_template_captures_base64_body_without_decoys(
    tmp_path: Path,
) -> None:
    """`DH{*}` is exact by prefix but accepts standard Base64 punctuation."""

    run_id = "run-runtime-candidate-format"
    candidate = "DH{YW55L2JvZHk9PQ==}"
    decoy = "CTF{syntactic_decoy}"
    wrong_case_decoy = "dh{lowercase_prefix}"
    artifact = await LocalArtifactStore(tmp_path).put_bytes(
        f"noise {decoy}\nwrong case {wrong_case_decoy}\ncorrect {candidate}\n".encode("ascii"),
        run_id=run_id,
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )

    revealed = await RuntimeCandidateRevealService(
        artifact_root=tmp_path,
        patterns=(r"\bDH\{[^\s{}]{1,512}\}",),
    ).reveal(
        run_id=run_id,
        observations=(RuntimeCandidateArtifact(artifact_id=artifact.id, racer_label="A"),),
        include_broad_detector=False,
    )

    assert revealed["candidates"] == [{"value": candidate, "racer_labels": ["A"]}]
    assert revealed["candidate_count"] == 1
    assert decoy not in repr(revealed["candidates"])
    assert wrong_case_decoy not in repr(revealed["candidates"])


@pytest.mark.asyncio
async def test_current_review_reveal_includes_only_opaque_source_session(
    tmp_path: Path,
) -> None:
    """A local queue attributes a candidate without persisting its value."""

    run_id = "run-runtime-candidate-provenance"
    candidate = "DH{review_source_a}"
    artifact = await LocalArtifactStore(tmp_path).put_bytes(
        candidate.encode("ascii"),
        run_id=run_id,
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )

    revealed = await RuntimeCandidateRevealService(
        artifact_root=tmp_path,
        patterns=(r"\bDH\{[^\s{}]{1,512}\}",),
    ).reveal(
        run_id=run_id,
        observations=(
            RuntimeCandidateArtifact(
                artifact_id=artifact.id,
                racer_label="A",
                racer_session_id="power-pi-racer-a",
            ),
        ),
        include_broad_detector=False,
    )

    assert revealed["candidates"] == [
        {
            "value": candidate,
            "racer_labels": ["A"],
            "racer_session_ids": ["power-pi-racer-a"],
        }
    ]
