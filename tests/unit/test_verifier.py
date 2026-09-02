from __future__ import annotations

import hashlib

import pytest
from ctfmesh_verifier import DeclarativeExploitPlan, IndependentVerifier, ReplayObservation


class StaticDriver:
    environment_digest = hashlib.sha256(b"test-environment").hexdigest()

    def __init__(self, body: str) -> None:
        self.body = body
        self.generation = 0

    async def reset(self) -> int:
        self.generation += 1
        return self.generation

    async def replay(self, plan: DeclarativeExploitPlan, *, session_id: str) -> ReplayObservation:
        del plan, session_id
        return ReplayObservation(
            status=200,
            target_generation=self.generation,
            body=self.body,
            source="target_response",
            evidence_ref=f"target:{self.generation}",
            duration_ms=1,
        )


def plan() -> DeclarativeExploitPlan:
    return DeclarativeExploitPlan(
        path="/api/records/2",
        headers={"x-user": "alice"},
        expected_flag_pattern=r"CTF\{[A-Za-z0-9_]+\}",
        artifact_digest=hashlib.sha256(b"solve.py").hexdigest(),
    )


def sealed_plan_artifact() -> bytes:
    return rb'''"""A bounded proof artifact; the verifier reads only the literal below."""
CTFMESH_HTTP_PLAN = {
    "schema_version": 1,
    "runtime": "ctfmesh-http-plan/v1",
    "entrypoint": "solve.py",
    "method": "GET",
    "path": "/api/records/2",
    "headers": {"x-user": "alice"},
    "expected_flag_pattern": r"CTF\{[A-Za-z0-9_]+\}",
    "timeout_seconds": 15,
}
'''


@pytest.mark.asyncio
async def test_verifier_requires_two_clean_target_response_replays() -> None:
    verifier = IndependentVerifier(
        StaticDriver('{"flag":"CTF{target_only}"}'),
        flag_patterns=(r"CTF\{[A-Za-z0-9_]+\}",),
        replay_count=2,
    )

    result = await verifier.verify(plan())

    assert result.verified is True
    assert result.status == "verified"
    assert result.masked_flag is not None
    assert "target_only" not in result.masked_flag
    assert all(item["started_from_clean_reset"] for item in result.replay_results)


@pytest.mark.asyncio
async def test_verifier_rejects_a_flag_present_in_input_artifact() -> None:
    raw_flag = "CTF{copied_from_source}"
    verifier = IndependentVerifier(
        StaticDriver(raw_flag),
        flag_patterns=(r"CTF\{[A-Za-z0-9_]+\}",),
        replay_count=2,
    )

    result = await verifier.verify(plan(), forbidden_input_text=f"source says {raw_flag}")

    assert result.verified is False
    assert result.status == "unverifiable"
    assert result.provenance["input_artifact_flag_rejected"] is True


@pytest.mark.asyncio
async def test_verifier_binds_replay_to_the_exact_sealed_solve_artifact() -> None:
    artifact = sealed_plan_artifact()
    digest = hashlib.sha256(artifact).hexdigest()
    verifier = IndependentVerifier(
        StaticDriver('{"flag":"CTF{target_only}"}'),
        flag_patterns=(r"CTF\{[A-Za-z0-9_]+\}",),
        replay_count=2,
    )

    result = await verifier.verify_artifact(artifact, expected_artifact_digest=digest)

    assert result.verified is True
    assert result.exploit_digest == digest
    assert result.provenance["artifact_parser"] == "ast-literal-v1"
    assert result.provenance["artifact_digest_match"] is True
    assert all(item["artifact_digest_match"] for item in result.replay_results)


@pytest.mark.asyncio
async def test_verifier_refuses_a_tampered_artifact_before_target_replay() -> None:
    artifact = sealed_plan_artifact()
    expected_digest = hashlib.sha256(artifact).hexdigest()
    driver = StaticDriver('{"flag":"CTF{target_only}"}')
    verifier = IndependentVerifier(
        driver,
        flag_patterns=(r"CTF\{[A-Za-z0-9_]+\}",),
        replay_count=2,
    )

    result = await verifier.verify_artifact(
        artifact + b"\n# tampered after sealing\n",
        expected_artifact_digest=expected_digest,
    )

    assert result.verified is False
    assert result.status == "unverifiable"
    assert driver.generation == 0
    assert not any(item["artifact_digest_match"] for item in result.replay_results)
    assert all(
        item["failure_reason"] == "exploit_artifact_digest_mismatch"
        for item in result.replay_results
    )
