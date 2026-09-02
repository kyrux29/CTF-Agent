"""Verifier that accepts only declarative plans in the deterministic profile.

It intentionally has no facility to execute a host command or Python script.
Production runners must implement the SandboxRunner contract separately.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import re
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class DeclarativeExploitPlan(StrictModel):
    schema_version: Literal[1] = 1
    runtime: Literal["ctfmesh-http-plan/v1"] = "ctfmesh-http-plan/v1"
    entrypoint: Literal["solve.py"] = "solve.py"
    method: Literal["GET", "POST"] = "GET"
    path: str = Field(min_length=1, max_length=1024)
    headers: dict[str, str] = Field(default_factory=dict)
    expected_flag_pattern: str = Field(min_length=1, max_length=512)
    timeout_seconds: int = Field(default=15, ge=1, le=120)
    artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_solve_artifact(
        cls,
        artifact: bytes,
        *,
        artifact_digest: str,
    ) -> DeclarativeExploitPlan:
        """Parse the restricted plan literal from a sealed ``solve.py``.

        The deterministic verifier deliberately does not execute generated
        Python. It accepts exactly one literal ``CTFMESH_HTTP_PLAN`` assignment
        and binds the parsed plan to the caller-computed artifact digest.
        """

        if len(artifact) > 128 * 1024:
            raise ValueError("exploit_artifact_too_large")
        if not re.fullmatch(r"[0-9a-f]{64}", artifact_digest):
            raise ValueError("exploit_artifact_digest_invalid")
        try:
            source = artifact.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("exploit_artifact_not_utf8") from exc
        try:
            module = ast.parse(source, filename="solve.py", mode="exec")
        except SyntaxError as exc:
            raise ValueError("exploit_artifact_syntax_invalid") from exc

        values: list[ast.expr] = []
        for statement in module.body:
            if isinstance(statement, ast.Assign):
                values.extend(
                    statement.value
                    for target in statement.targets
                    if isinstance(target, ast.Name) and target.id == "CTFMESH_HTTP_PLAN"
                )
            elif (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.target.id == "CTFMESH_HTTP_PLAN"
                and statement.value is not None
            ):
                values.append(statement.value)
        if len(values) != 1:
            raise ValueError("exploit_artifact_requires_one_plan_literal")
        try:
            raw_plan = ast.literal_eval(values[0])
        except (TypeError, ValueError) as exc:
            raise ValueError("exploit_artifact_plan_must_be_literal") from exc
        if not isinstance(raw_plan, dict) or "artifact_digest" in raw_plan:
            raise ValueError("exploit_artifact_plan_invalid")
        return cls.model_validate({**raw_plan, "artifact_digest": artifact_digest})

    @field_validator("path")
    @classmethod
    def safe_target_relative_path(cls, value: str) -> str:
        if not value.startswith("/") or "//" in value or ".." in value or "\x00" in value:
            raise ValueError("exploit path must be an absolute target-relative path")
        return value

    @field_validator("headers")
    @classmethod
    def bounded_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32:
            raise ValueError("too many headers")
        for key, item in value.items():
            if not key or any(char in key for char in "\r\n:\x00"):
                raise ValueError("invalid header name")
            if any(char in item for char in "\r\n\x00"):
                raise ValueError("invalid header value")
        return value

    @field_validator("expected_flag_pattern")
    @classmethod
    def valid_flag_pattern(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("invalid expected_flag_pattern") from exc
        return value


class ReplayObservation(StrictModel):
    status: int = Field(ge=100, le=599)
    target_generation: int = Field(ge=1)
    body: str = Field(max_length=4 * 1024 * 1024)
    source: Literal["target_response", "target_filesystem"]
    evidence_ref: str = Field(min_length=1, max_length=256)
    duration_ms: int = Field(ge=0)


class TargetReplayDriver(Protocol):
    environment_digest: str

    async def reset(self) -> int: ...

    async def replay(
        self, plan: DeclarativeExploitPlan, *, session_id: str
    ) -> ReplayObservation: ...


class VerificationResult(StrictModel):
    id: str
    verified: bool
    exploit_digest: str
    environment_digest: str
    flag_sha256: str | None = None
    masked_flag: str | None = None
    replay_results: list[dict[str, Any]]
    provenance: dict[str, Any]
    status: Literal["verified", "failed", "flaky", "unverifiable"]


def mask_flag(flag: str) -> str:
    if len(flag) < 8:
        return "[masked]"
    if flag.startswith("CTF{") and flag.endswith("}"):
        return f"CTF{{{flag[4:6]}…{flag[-3:-1]}}}"
    return f"{flag[:2]}…{flag[-2:]}"


class IndependentVerifier:
    """Reset and replay a declarative exploit in fresh sessions.

    ``forbidden_input_text`` provides provenance rejection in CI. It is never
    persisted and is only used to ensure a candidate flag was not supplied by
    source/input artifacts.
    """

    def __init__(
        self,
        driver: TargetReplayDriver,
        *,
        flag_patterns: tuple[str, ...],
        replay_count: int = 2,
    ) -> None:
        if replay_count < 1:
            raise ValueError("replay_count must be positive")
        self.driver = driver
        self.flag_patterns = tuple(re.compile(pattern) for pattern in flag_patterns)
        self.replay_count = replay_count

    async def verify(
        self,
        plan: DeclarativeExploitPlan,
        *,
        forbidden_input_text: str = "",
    ) -> VerificationResult:
        """Verify a plan supplied by a trusted test fixture.

        Product flows should prefer :meth:`verify_artifact`, which binds the
        parsed literal plan to bytes read from content-addressed storage.
        """

        return await self._verify(
            plan,
            forbidden_input_text=forbidden_input_text,
            artifact_digest_match=True,
            parser_profile="trusted-plan-fixture",
        )

    async def verify_artifact(
        self,
        artifact: bytes,
        *,
        expected_artifact_digest: str,
        forbidden_input_text: str = "",
    ) -> VerificationResult:
        """Verify an exact sealed artifact without executing its Python code."""

        actual_digest = hashlib.sha256(artifact).hexdigest()
        digest_match = hmac.compare_digest(actual_digest, expected_artifact_digest)
        try:
            plan = DeclarativeExploitPlan.from_solve_artifact(
                artifact,
                artifact_digest=actual_digest,
            )
        except (TypeError, ValueError):
            return self._unverifiable_artifact_result(
                artifact_digest=actual_digest,
                artifact_digest_match=digest_match,
                failure_reason="exploit_artifact_parse_failed",
            )
        if not digest_match:
            return self._unverifiable_artifact_result(
                artifact_digest=actual_digest,
                artifact_digest_match=False,
                failure_reason="exploit_artifact_digest_mismatch",
            )
        return await self._verify(
            plan,
            forbidden_input_text=forbidden_input_text,
            artifact_digest_match=True,
            parser_profile="ast-literal-v1",
        )

    async def _verify(
        self,
        plan: DeclarativeExploitPlan,
        *,
        forbidden_input_text: str,
        artifact_digest_match: bool,
        parser_profile: str,
    ) -> VerificationResult:
        replay_results: list[dict[str, Any]] = []
        flag_digests: list[str] = []
        candidate_flag: str | None = None
        rejected_provenance = False
        for attempt in range(1, self.replay_count + 1):
            target_generation = await self.driver.reset()
            session_id = f"verifier_{uuid4().hex}"
            observation = await self.driver.replay(plan, session_id=session_id)
            match = self._extract_flag(observation.body, plan.expected_flag_pattern)
            passed = (
                observation.status < 400
                and observation.source == "target_response"
                and match is not None
                and observation.target_generation == target_generation
                and artifact_digest_match
            )
            if match is not None and match in forbidden_input_text:
                passed = False
                rejected_provenance = True
            if passed and match is not None:
                candidate_flag = match
                flag_digests.append(hashlib.sha256(match.encode()).hexdigest())
            replay_results.append(
                {
                    "attempt": attempt,
                    "passed": passed,
                    "started_from_clean_reset": observation.target_generation == target_generation,
                    "artifact_digest_match": artifact_digest_match,
                    "duration_ms": observation.duration_ms,
                    "evidence_ref": observation.evidence_ref,
                    "target_generation": target_generation,
                    "failure_reason": None
                    if passed
                    else self._failure_reason(observation, match, rejected_provenance),
                }
            )
        all_passed = len(replay_results) == self.replay_count and all(
            item["passed"] for item in replay_results
        )
        same_flag = len(set(flag_digests)) == 1 and len(flag_digests) == self.replay_count
        verified = all_passed and same_flag and candidate_flag is not None
        status: Literal["verified", "failed", "flaky", "unverifiable"]
        if verified:
            status = "verified"
        elif any(item["passed"] for item in replay_results):
            status = "flaky"
        elif rejected_provenance:
            status = "unverifiable"
        else:
            status = "failed"
        return VerificationResult(
            id=f"verify_{uuid4().hex}",
            verified=verified,
            exploit_digest=plan.artifact_digest,
            environment_digest=self.driver.environment_digest,
            flag_sha256=flag_digests[0] if verified else None,
            masked_flag=mask_flag(candidate_flag) if verified and candidate_flag else None,
            replay_results=replay_results,
            provenance={
                "source": "target_response" if verified else "unverified",
                "input_artifact_flag_rejected": rejected_provenance,
                "replay_count_required": self.replay_count,
                "runner_profile": "deterministic-ci-declarative",
                "artifact_digest_match": artifact_digest_match,
                "artifact_parser": parser_profile,
            },
            status=status,
        )

    def _unverifiable_artifact_result(
        self,
        *,
        artifact_digest: str,
        artifact_digest_match: bool,
        failure_reason: str,
    ) -> VerificationResult:
        replay_results = [
            {
                "attempt": attempt,
                "passed": False,
                "started_from_clean_reset": False,
                "artifact_digest_match": artifact_digest_match,
                "duration_ms": 0,
                "evidence_ref": "artifact:unverified",
                "target_generation": None,
                "failure_reason": failure_reason,
            }
            for attempt in range(1, self.replay_count + 1)
        ]
        return VerificationResult(
            id=f"verify_{uuid4().hex}",
            verified=False,
            exploit_digest=artifact_digest,
            environment_digest=self.driver.environment_digest,
            replay_results=replay_results,
            provenance={
                "source": "unverified",
                "input_artifact_flag_rejected": False,
                "replay_count_required": self.replay_count,
                "runner_profile": "deterministic-ci-declarative",
                "artifact_digest_match": artifact_digest_match,
                "artifact_parser": "ast-literal-v1",
            },
            status="unverifiable",
        )

    def _extract_flag(self, body: str, expected: str) -> str | None:
        expected_pattern = re.compile(expected)
        match = expected_pattern.search(body)
        if match is None:
            return None
        candidate = match.group(0)
        if not any(pattern.fullmatch(candidate) for pattern in self.flag_patterns):
            return None
        return candidate

    @staticmethod
    def _failure_reason(
        observation: ReplayObservation, match: str | None, rejected_provenance: bool
    ) -> str:
        if rejected_provenance:
            return "input_artifact_provenance_rejected"
        if observation.status >= 400:
            return f"target_status_{observation.status}"
        if observation.source != "target_response":
            return "invalid_flag_provenance"
        if match is None:
            return "flag_not_observed"
        return "reset_or_replay_mismatch"


__all__ = [
    "DeclarativeExploitPlan",
    "IndependentVerifier",
    "ReplayObservation",
    "TargetReplayDriver",
    "VerificationResult",
    "mask_flag",
]
