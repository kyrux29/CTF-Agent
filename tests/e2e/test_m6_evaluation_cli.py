"""CLI coverage for the offline M6 verified-solve report command."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ctfmesh_cli.main import app
from ctfmesh_evaluation import (
    EvaluationBudget,
    VerifiedSolveCondition,
    VerifiedSolveEvaluation,
    VerifiedSolveLab,
    VerifiedSolveProtocol,
    VerifiedSolveRunRecord,
    VerifiedSolveStatus,
    VerifierProofReceipt,
)
from typer.testing import CliRunner

runner = CliRunner()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _matrix() -> VerifiedSolveEvaluation:
    """Create one complete non-secret M6 matrix for CLI contract coverage."""

    budget = EvaluationBudget(
        wall_time_seconds=120,
        max_worker_turns=10,
        max_tool_calls=10,
        max_http_requests=5,
        max_cost_microusd=100_000,
    )
    lab = VerifiedSolveLab(
        lab_id="cli-local-lab",
        challenge_digest=_digest("challenge"),
        target_image_digest=_digest("image"),
    )
    protocol = VerifiedSolveProtocol(
        suite_id="cli-m6-suite",
        suite_digest=_digest("suite"),
        model_configuration_digest=_digest("model"),
        budget=budget,
        repetitions_per_lab_condition=5,
    )
    records = []
    for condition in VerifiedSolveCondition:
        for attempt in range(1, 6):
            token = f"{condition.value}:{attempt}"
            records.append(
                VerifiedSolveRunRecord(
                    run_id=f"run_{condition.value}_{attempt}",
                    lab_id=lab.lab_id,
                    condition=condition,
                    attempt=attempt,
                    run_seed_digest=_digest(f"seed:{token}"),
                    challenge_digest=lab.challenge_digest,
                    target_image_digest=lab.target_image_digest,
                    model_configuration_digest=protocol.model_configuration_digest,
                    prompt_digest=_digest(f"prompt:{condition.value}"),
                    skill_pack_digest=_digest(f"skills:{condition.value}"),
                    condition_configuration_digest=_digest(f"config:{condition.value}"),
                    budget=budget,
                    status=VerifiedSolveStatus.SOLVED,
                    agent_claimed_solved=True,
                    verifier_proof=VerifierProofReceipt(
                        proof_artifact_digest=_digest(f"proof:{token}"),
                        verifier_id="independent-verifier",
                        replay_count=2,
                        reset_ids=(f"reset_{token}_one", f"reset_{token}_two"),
                        signature_verified=True,
                    ),
                    elapsed_milliseconds=100,
                    tool_call_count=2,
                    task_execution_count=2,
                    duplicate_execution_count=0,
                    duplicate_execution_with_reason_count=0,
                    verification_attempt_count=1,
                    invalid_worker_output_count=0,
                    out_of_scope_action_count=0,
                    public_answer_retrieval_count=0,
                    active_hint_event_count=(
                        1 if condition is VerifiedSolveCondition.MASTER_WORKERS_WITH_HINT else 0
                    ),
                    reflected_hint_event_count=(
                        1 if condition is VerifiedSolveCondition.MASTER_WORKERS_WITH_HINT else 0
                    ),
                )
            )
    return VerifiedSolveEvaluation(protocol=protocol, labs=(lab,), records=tuple(records))


def test_verified_solve_cli_writes_a_new_safe_report(tmp_path: Path) -> None:
    """The command only aggregates a strict JSON matrix and will not overwrite output."""

    input_path = tmp_path / "matrix.json"
    output_path = tmp_path / "report.json"
    input_path.write_text(json.dumps(_matrix().model_dump(mode="json")), encoding="utf-8")

    result = runner.invoke(
        app,
        ["benchmark", "verified-solve-evaluate", str(input_path), "--output", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    assert "Verified-solve evaluation report" in result.output
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "ctfmesh.verified-solve-report.v1"
    assert report["gates"]["release_candidate_ready"] is True
    repeated = runner.invoke(
        app,
        ["benchmark", "verified-solve-evaluate", str(input_path), "--output", str(output_path)],
    )
    assert repeated.exit_code != 0
    assert "must not already exist" in repeated.output


def test_verified_solve_cli_rejects_untrusted_input_without_echoing_it(tmp_path: Path) -> None:
    """A malformed fixture never turns its text into CLI diagnostics or a report."""

    input_path = tmp_path / "invalid.json"
    raw_marker = "CTF{untrusted_fixture_must_not_echo}"
    input_path.write_text(json.dumps({"unexpected": raw_marker}), encoding="utf-8")

    result = runner.invoke(app, ["benchmark", "verified-solve-evaluate", str(input_path)])

    assert result.exit_code != 0
    assert "valid M6 verified-solve JSON matrix" in result.output
    assert raw_marker not in result.output
