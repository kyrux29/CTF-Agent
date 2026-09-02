"""Durable M5 candidate-to-verifier state-machine regression coverage."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from ctfmesh_db import Database, Repository
from ctfmesh_domain import (
    AgentRole,
    ExploitCandidateSubmission,
    ExploitPlanDraftV1,
    HintCard,
    HintDirective,
    TaskDelegationRequest,
    VerificationProofEnvelopeV1,
    VerificationReplayAttemptV1,
    VerifierCompletionV1,
)
from ctfmesh_orchestrator import CandidateArtifactService, RunEngine, hint_template

_TARGET_DIGEST = "aa271474cd131f616b8363275f3fbb5fcea669d658f5f74c1e55476dd53d9a58"
_FLAG_PATTERN = r"CTF\{[A-Za-z0-9_-]{1,128}\}"


def _manifest(
    run_label: str,
    *,
    target_service: str = "lab-path-traversal",
) -> dict[str, object]:
    """A persisted M5 manifest whose target remains private to the verifier."""

    return {
        "apiVersion": "ctfmesh.io/v1alpha1",
        "kind": "Challenge",
        "metadata": {
            "name": "web-path-traversal",
            "category": "web",
            "tags": [f"m5-{run_label}"],
        },
        "spec": {
            "mode": "assisted",
            "target": {
                "type": "docker_compose",
                "compose_file": "docker-compose.yml",
                "service": target_service,
                "healthcheck": {
                    "url": f"http://{target_service}:8080/health",
                    "expected_status": 200,
                },
                "allowed_endpoints": [
                    {"host": target_service, "ports": [8080], "protocols": ["http"]}
                ],
                "target_aliases": {"lab": f"http://{target_service}:8080"},
            },
            "artifacts": [{"path": "source/README.md", "role": "source"}],
            "flag": {
                "patterns": [_FLAG_PATTERN],
                "source_policy": {
                    "allow_from_target_response": True,
                    "allow_from_target_filesystem": False,
                    "deny_from_input_artifacts": True,
                },
                "replay_count": 2,
            },
            "limits": {
                "wall_time_seconds": 300,
                "max_worker_turns": 20,
                "max_tool_calls": 20,
                "max_http_requests": 10,
                "max_parallel_requests": 1,
                "max_cost_usd": 1.0,
                "max_artifact_bytes": 1_000_000,
            },
            "providers": {"preferred": "fixture", "fallbacks": []},
            "memory": {
                "namespace": f"m5-candidate-pipeline-{run_label}",
                "cutoff": "2026-08-29T00:00:00Z",
                "internet_search": False,
            },
            "tool_profile": ["http.request"],
        },
    }


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[Repository]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'm5-candidate.db'}")
    await database.create_schema()
    try:
        yield Repository(database)
    finally:
        await database.close()


def _mapping(value: object) -> Mapping[str, Any]:
    assert isinstance(value, Mapping)
    return value


def _string(value: object) -> str:
    assert isinstance(value, str)
    return value


def _lease(job: Mapping[str, Any]) -> int:
    value = job["lease_version"]
    assert isinstance(value, int)
    return value


async def _activate_next(
    repository: Repository, *, runner_id: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    start = await repository.claim_agent_job(
        worker_id=runner_id,
        lease_seconds=60,
        kinds=("start_session",),
    )
    assert start is not None
    start_job = _mapping(start)
    reservation = _mapping(
        await repository.reserve_pi_session(
            _string(start_job["id"]), worker_id=runner_id, lease_version=_lease(start_job)
        )
    )
    session = _mapping(reservation["session"])
    activated = await repository.activate_pi_session(
        _string(start_job["id"]),
        session_id=_string(session["id"]),
        worker_id=runner_id,
        lease_version=_lease(start_job),
    )
    assert activated["state"] == "ready"
    return start_job, session


async def _next_turn(
    repository: Repository, *, runner_id: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    claimed = await repository.claim_agent_job(
        worker_id=runner_id,
        lease_seconds=60,
        kinds=("run_turn",),
    )
    assert claimed is not None
    job = _mapping(claimed)
    work = _mapping(
        await repository.get_pi_agent_job_work(
            _string(job["id"]), worker_id=runner_id, lease_version=_lease(job)
        )
    )
    return job, work


async def _exploit_builder_turn(
    repository: Repository,
    tmp_path: Path,
    *,
    run_label: str,
    target_service: str = "lab-path-traversal",
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], str, str]:
    """Start the real M2/M4 queue path through one exploit-builder turn."""

    challenge = await repository.create_challenge(
        _manifest(run_label, target_service=target_service), name="web-path-traversal"
    )
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=_string(challenge["id"]),
        mode="assisted",
        provider="fixture",
        budget={
            "wall_time_seconds": 300,
            "max_tool_calls": 8,
            "max_http_requests": 4,
            "max_cost_usd": 0.5,
        },
        idempotency_key=f"m5-run-{challenge['id']}",
    )
    assert await engine.process_next_preflight(worker_id="m5-preflight") is not None
    template = hint_template("web.path_traversal.suspect.v1")
    assert template is not None
    now = datetime.now(UTC)
    # M4's scheduler requires the operator to activate a reviewed technique;
    # its automatically queued source reviewer is completed below before the
    # master-created exploit-builder branch is selected.
    await repository.create_hint_card(
        HintCard(
            id=f"hint_m5_{_string(run['id'])[-16:]}",
            run_id=_string(run["id"]),
            template_id=template.id,
            template_version=template.version,
            technique_id=template.technique_id,
            category=template.category,
            directive=HintDirective.PRIORITIZE,
            target_ref="run:all",
            priority=4,
            note="",
            actor_id="m5-operator",
            created_at=now,
            updated_at=now,
        ),
        template=template,
        idempotency_key=f"m5-hint-{_string(run['id'])[-16:]}",
    )
    runner_id = "m5-runner"
    _, master_session = await _activate_next(repository, runner_id=runner_id)
    master_turn, master_work = await _next_turn(repository, runner_id=runner_id)
    assert _mapping(master_work["session"])["id"] == master_session["id"]
    evidence = _mapping(master_work["context_manifest"])["evidence_refs"]
    assert isinstance(evidence, list) and evidence
    observation_id = _string(_mapping(evidence[0])["observation_id"])
    delegated = await repository.delegate_pi_task(
        TaskDelegationRequest(
            tool_call_id="m5-delegate-exploit-builder",
            role=AgentRole.EXPLOIT_BUILDER,
            technique_id="web.path_traversal",
            objective="Create one evidence-backed declarative replay candidate.",
            evidence_ids=(observation_id,),
        ),
        job_id=_string(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease(master_turn),
    )
    assert delegated["task"]["role"] == AgentRole.EXPLOIT_BUILDER.value
    await repository.complete_pi_turn(
        _string(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease(master_turn),
        result_ref="agent:delegated",
    )
    # The approved hint's deterministic source task was enqueued before the
    # master delegation. Drain that unrelated reviewed task rather than
    # bypassing the real FIFO/session lifecycle in this M5 integration test.
    _, scheduled_session = await _activate_next(repository, runner_id=runner_id)
    assert scheduled_session["role"] == AgentRole.SOURCE_AUDITOR.value
    scheduled_turn, _scheduled_work = await _next_turn(repository, runner_id=runner_id)
    await repository.complete_pi_turn(
        _string(scheduled_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease(scheduled_turn),
        result_ref="agent:inconclusive",
    )
    _, exploit_session = await _activate_next(repository, runner_id=runner_id)
    exploit_turn, exploit_work = await _next_turn(repository, runner_id=runner_id)
    assert _mapping(exploit_work["session"])["id"] == exploit_session["id"]
    return run, exploit_turn, exploit_session, observation_id, _string(challenge["digest"])


async def _submit_candidate(
    repository: Repository,
    tmp_path: Path,
    *,
    path: str,
    target_service: str = "lab-path-traversal",
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], str]:
    run, exploit_turn, exploit_session, evidence_id, challenge_digest = await _exploit_builder_turn(
        repository,
        tmp_path,
        run_label=path.removeprefix("/"),
        target_service=target_service,
    )
    submission = ExploitCandidateSubmission(
        session_id=_string(exploit_session["id"]),
        tool_call_id="m5-candidate-tool-call",
        idempotency_key="m5-candidate-tool-call",
        plan=ExploitPlanDraftV1.model_validate(
            {
                "schema_version": "ctfmesh.exploit-plan.v1",
                "challenge_digest": challenge_digest,
                "technique_id": "web.path_traversal",
                "steps": [
                    {
                        "op": "http.request",
                        "path": path,
                        "query": {"file": "../../run/ctfmesh/flag/flag"},
                        "capture": {"flag": f"regex:{_FLAG_PATTERN}"},
                    }
                ],
                "assertions": ["capture.flag exists"],
                "evidence_refs": [evidence_id],
            }
        ),
    )
    plan = submission.issued_plan()
    artifacts = CandidateArtifactService(tmp_path / "artifacts")
    artifact = await artifacts.persist_plan(
        run_id=_string(run["id"]),
        session_id=submission.session_id,
        tool_call_id=submission.tool_call_id,
        plan=plan,
    )
    accepted = _mapping(
        await repository.submit_pi_candidate(
            _string(exploit_turn["id"]),
            worker_id="m5-runner",
            lease_version=_lease(exploit_turn),
            submission=submission,
            plan=plan,
            plan_artifact=artifact,
        )
    )
    return run, exploit_turn, accepted, challenge_digest


def _successful_replays() -> tuple[VerificationReplayAttemptV1, VerificationReplayAttemptV1]:
    return (
        VerificationReplayAttemptV1(
            attempt=1,
            reset_id="reset_one",
            target_generation=1,
            passed=True,
            started_from_clean_reset=True,
            flag_sha256="b" * 64,
            controller_lab_id="web-path-traversal",
            controller_issued_at="2026-08-29T00:00:01Z",
            controller_proof_id="proof_one",
            controller_signature="c" * 128,
        ),
        VerificationReplayAttemptV1(
            attempt=2,
            reset_id="reset_two",
            target_generation=2,
            passed=True,
            started_from_clean_reset=True,
            flag_sha256="d" * 64,
            controller_lab_id="web-path-traversal",
            controller_issued_at="2026-08-29T00:00:02Z",
            controller_proof_id="proof_two",
            controller_signature="e" * 128,
        ),
    )


@pytest.mark.asyncio
async def test_candidate_requires_independent_proof_before_the_only_solved_transition(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """Pi acceptance queues verification but cannot convert its own claim into SOLVED."""

    run, exploit_turn, accepted, challenge_digest = await _submit_candidate(
        repository, tmp_path, path="/download"
    )
    run_id = _string(run["id"])
    candidate = _mapping(accepted["candidate"])
    verification_job = _mapping(accepted["verification_job"])
    assert (await repository.get_run(run_id))["status"] == "verifying"  # type: ignore[index]
    assert candidate["status"] == "verifying"
    # The Pi turn can close only as a candidate record; it cannot attach a
    # verification proof or choose SOLVED even after its candidate was queued.
    await repository.complete_pi_turn(
        _string(exploit_turn["id"]),
        worker_id="m5-runner",
        lease_version=_lease(exploit_turn),
        result_ref=f"candidate:{candidate['id']}",
    )
    assert (await repository.get_run(run_id))["status"] == "verifying"  # type: ignore[index]

    claimed = await repository.claim_agent_job(
        worker_id="independent-verifier", lease_seconds=60, kinds=("verify",)
    )
    assert claimed is not None
    verifier_job = _mapping(claimed)
    assert verifier_job["id"] == verification_job["id"]
    work = await repository.get_verification_job_work(
        _string(verifier_job["id"]),
        worker_id="independent-verifier",
        lease_version=_lease(verifier_job),
    )
    assert set(_mapping(work["candidate"])) == {
        "id",
        "run_id",
        "plan_artifact_digest",
        "evidence_refs",
    }
    serialized_work = str(work)
    assert "target_aliases" not in serialized_work
    assert "lab-path-traversal:8080" not in serialized_work

    replays = _successful_replays()
    proof = VerificationProofEnvelopeV1(
        run_id=run_id,
        candidate_id=_string(candidate["id"]),
        challenge_digest=challenge_digest,
        plan_artifact_digest=_string(candidate["plan_artifact_digest"]),
        target_image_digest=_TARGET_DIGEST,
        replays=replays,
        created_at=datetime.now(UTC),
    )
    completion = VerifierCompletionV1(
        candidate_id=_string(candidate["id"]),
        verified=True,
        environment_digest=_TARGET_DIGEST,
        replay_results=replays,
        proof=proof,
    )
    proof_artifact = await CandidateArtifactService(tmp_path / "artifacts").persist_proof(proof)
    completed = await repository.complete_verification_job(
        _string(verifier_job["id"]),
        worker_id="independent-verifier",
        lease_version=_lease(verifier_job),
        completion=completion,
        proof_artifact=proof_artifact,
    )
    assert completed["candidate"]["status"] == "verified"
    assert (await repository.get_run(run_id))["status"] == "solved"  # type: ignore[index]
    verifications = await repository.list_verifications(run_id)
    assert len(verifications) == 1
    assert verifications[0]["verification_proof_ref"] == proof_artifact.id
    assert "CTF{" not in str(verifications)


@pytest.mark.asyncio
async def test_text_claim_cannot_rescue_a_wrong_plan_and_verifier_failure_stays_verifying(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """A candidate never self-solves when replay rejects it or verifier is unavailable."""

    run, _turn, accepted, _digest = await _submit_candidate(repository, tmp_path, path="/wrong")
    run_id = _string(run["id"])
    candidate = _mapping(accepted["candidate"])
    claimed = await repository.claim_agent_job(
        worker_id="independent-verifier", lease_seconds=60, kinds=("verify",)
    )
    assert claimed is not None
    verifier_job = _mapping(claimed)
    rejected = VerifierCompletionV1(
        candidate_id=_string(candidate["id"]),
        verified=False,
        environment_digest=_TARGET_DIGEST,
        replay_results=(
            VerificationReplayAttemptV1(
                attempt=1,
                reset_id="reset_wrong_one",
                target_generation=1,
                passed=False,
                started_from_clean_reset=True,
                failure_code="target_flag_not_observed",
            ),
            VerificationReplayAttemptV1(
                attempt=2,
                reset_id="reset_wrong_two",
                target_generation=2,
                passed=False,
                started_from_clean_reset=True,
                failure_code="target_flag_not_observed",
            ),
        ),
        failure_code="replay_failed",
    )
    await repository.complete_verification_job(
        _string(verifier_job["id"]),
        worker_id="independent-verifier",
        lease_version=_lease(verifier_job),
        completion=rejected,
        proof_artifact=None,
    )
    assert (await repository.get_run(run_id))["status"] == "running"  # type: ignore[index]
    assert (await repository.list_exploit_candidates(run_id))[0]["status"] == "rejected"

    unavailable_run, _second_turn, unavailable, _second_digest = await _submit_candidate(
        repository, tmp_path, path="/download"
    )
    unavailable_run_id = _string(unavailable_run["id"])
    claimed_unavailable = await repository.claim_agent_job(
        worker_id="independent-verifier-two", lease_seconds=60, kinds=("verify",)
    )
    assert claimed_unavailable is not None
    unavailable_job = _mapping(claimed_unavailable)
    assert unavailable_job["id"] == _mapping(unavailable["verification_job"])["id"]
    failed = await repository.fail_verification_job(
        _string(unavailable_job["id"]),
        worker_id="independent-verifier-two",
        lease_version=_lease(unavailable_job),
        reason="lab_controller_unavailable",
    )
    assert failed["candidate"]["status"] == "unavailable"
    assert (await repository.get_run(unavailable_run_id))["status"] == "verifying"  # type: ignore[index]


@pytest.mark.asyncio
async def test_candidate_rejects_a_manifest_rebound_to_an_unreviewed_target(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """A reviewed technique cannot be reused to point M5 at another service."""

    with pytest.raises(ValueError, match="candidate_technique_not_reviewed"):
        await _submit_candidate(
            repository,
            tmp_path,
            path="/download",
            target_service="operator-controlled-lab",
        )
