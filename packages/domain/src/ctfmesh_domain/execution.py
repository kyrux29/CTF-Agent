"""Closed-world contracts for M5 exploit candidates and replay plans.

The models in this module deliberately describe a *declarative* HTTP replay.
They are not a scripting format: there is no URL, executable source, shell,
file operation, redirect setting, or dynamic import anywhere in the schema.
The verifier derives the only target origin from a code-owned mapping of the
reviewed plan technique after this contract has been parsed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .base import ContractModel, FrozenSequence, Identifier, Sha256Digest, UtcDatetime

_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z][A-Za-z0-9_]{0,63})\}$")
_VARIABLE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_HEADER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SAFE_HEADERS = frozenset({"accept", "content-type", "x-ctfmesh-user"})
_FLAG_LIKE = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_CONTROLLER_ISSUED_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def canonical_exploit_plan_json(value: Mapping[str, Any]) -> bytes:
    """Serialize a plan deterministically before it enters artifact storage."""

    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def exploit_plan_digest(value: Mapping[str, Any]) -> str:
    """Return the semantic digest of a plan payload that omits ``digest``."""

    return hashlib.sha256(canonical_exploit_plan_json(value)).hexdigest()


def _safe_target_path(value: str) -> str:
    """Allow an absolute path *inside* the already-selected target origin."""

    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or ".." in value.split("/")
        or any(character in value for character in "\r\n\x00?#")
        or "://" in value
    ):
        raise ValueError("exploit_plan_path_must_be_target_relative")
    return value


def _safe_template_value(value: str) -> str:
    """Accept a literal or one whole-value variable reference, never templating code."""

    if not value or len(value) > 4_096 or any(character in value for character in "\r\n\x00"):
        raise ValueError("exploit_plan_template_value_invalid")
    # A candidate cannot smuggle a previously observed raw flag into an
    # otherwise declarative replay. The verifier independently obtains any
    # flag only from a fresh target response.
    if _FLAG_LIKE.search(value):
        raise ValueError("exploit_plan_contains_raw_flag")
    if "${" in value and _PLACEHOLDER.fullmatch(value) is None:
        raise ValueError("exploit_plan_placeholder_must_cover_entire_value")
    return value


class ExploitPlanStepV1(ContractModel):
    """One safe, idempotent target-relative HTTP observation/replay step."""

    op: Literal["http.request"]
    # M5 labs intentionally need only read-only requests. Keeping the replay
    # profile to GET avoids model-authored target mutations and cookie/form
    # side effects during independent verification.
    method: Literal["GET"] = "GET"
    path: str = Field(min_length=1, max_length=2_048)
    query: dict[Identifier, str] = Field(default_factory=dict, max_length=32)
    headers: dict[str, str] = Field(default_factory=dict, max_length=8)
    # The string is pinned against challenge flag patterns by
    # ``ExploitPlanV1.validate_for_flag_patterns`` before persistence.
    capture: dict[Literal["flag"], str] | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_target_path(value)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not _VARIABLE_NAME.fullmatch(key):
                raise ValueError("exploit_plan_query_key_invalid")
            _safe_template_value(item)
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            normalized = key.lower()
            if key != normalized or not _HEADER_NAME.fullmatch(key) or key not in _SAFE_HEADERS:
                raise ValueError("exploit_plan_header_not_allowed")
            _safe_template_value(item)
        return value

    @field_validator("capture")
    @classmethod
    def validate_capture(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return None
        if tuple(value) != ("flag",):
            raise ValueError("exploit_plan_capture_must_contain_only_flag")
        pattern = value["flag"]
        if not pattern.startswith("regex:") or len(pattern) > 1_024:
            raise ValueError("exploit_plan_capture_must_be_regex")
        try:
            re.compile(pattern.removeprefix("regex:"))
        except re.error as exc:
            raise ValueError("exploit_plan_capture_regex_invalid") from exc
        return value

    def referenced_variables(self) -> tuple[str, ...]:
        """Return only exact placeholders used by this strictly typed step."""

        values = (*self.query.values(), *self.headers.values())
        return tuple(
            match.group(1)
            for value in values
            if (match := _PLACEHOLDER.fullmatch(value)) is not None
        )


class _ExploitPlanPayloadV1(ContractModel):
    """The digest-covered portion of :class:`ExploitPlanV1`."""

    schema_version: Literal["ctfmesh.exploit-plan.v1"] = "ctfmesh.exploit-plan.v1"
    challenge_digest: Sha256Digest
    technique_id: Identifier
    variables: dict[str, str] = Field(default_factory=dict, max_length=16)
    steps: FrozenSequence[ExploitPlanStepV1] = Field(min_length=1, max_length=8)
    assertions: FrozenSequence[Literal["capture.flag exists"]] = Field(min_length=1, max_length=1)
    evidence_refs: FrozenSequence[Identifier] = Field(min_length=1, max_length=32)

    @field_validator("variables")
    @classmethod
    def validate_variables(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not _VARIABLE_NAME.fullmatch(key):
                raise ValueError("exploit_plan_variable_name_invalid")
            _safe_template_value(item)
            if _PLACEHOLDER.fullmatch(item) is not None:
                raise ValueError("exploit_plan_variable_cannot_reference_variable")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def unique_evidence_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("exploit_plan_evidence_refs_must_be_unique")
        return value

    @model_validator(mode="after")
    def validate_plan_structure(self) -> _ExploitPlanPayloadV1:
        captures = [step for step in self.steps if step.capture is not None]
        if len(captures) != 1 or self.steps[-1].capture is None:
            raise ValueError("exploit_plan_requires_one_final_flag_capture")
        available = set(self.variables)
        unknown = {
            name
            for step in self.steps
            for name in step.referenced_variables()
            if name not in available
        }
        if unknown:
            raise ValueError("exploit_plan_references_unknown_variable")
        return self

    def digest_payload(self) -> dict[str, Any]:
        """Return the exact JSON object used for the semantic plan digest."""

        # This method is inherited by ``ExploitPlanV1``; excluding by name
        # keeps the semantic digest non-recursive when the concrete model also
        # carries its already-computed ``digest`` field.
        return self.model_dump(mode="json", exclude={"digest"})


class ExploitPlanV1(_ExploitPlanPayloadV1):
    """Digest-pinned candidate plan stored as an immutable artifact.

    ``digest`` is a semantic digest of fields above it. The artifact store adds
    a second digest over the full canonical serialized document; both are
    checked by the verifier so neither a plan body nor its artifact binding
    can be silently substituted.
    """

    digest: Sha256Digest

    @model_validator(mode="after")
    def digest_matches_payload(self) -> ExploitPlanV1:
        if self.digest != exploit_plan_digest(self.digest_payload()):
            raise ValueError("exploit_plan_digest_mismatch")
        return self

    @classmethod
    def issue(cls, **values: Any) -> ExploitPlanV1:
        """Validate and attach the canonical semantic digest in one operation."""

        payload = _ExploitPlanPayloadV1.model_validate(values)
        return cls.model_validate(
            {
                **payload.model_dump(mode="json"),
                "digest": exploit_plan_digest(payload.digest_payload()),
            }
        )

    def canonical_bytes(self) -> bytes:
        """Return bytes persisted to content-addressed artifact storage."""

        return canonical_exploit_plan_json(self.model_dump(mode="json"))

    def artifact_digest(self) -> str:
        """Return the content-addressed digest of :meth:`canonical_bytes`."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def validate_for_flag_patterns(self, patterns: tuple[str, ...]) -> None:
        """Pin flag extraction to a reviewed challenge pattern, not model regex."""

        capture = self.steps[-1].capture
        assert capture is not None  # enforced by ``validate_plan_structure``
        candidate = capture["flag"].removeprefix("regex:")
        if candidate not in patterns:
            raise ValueError("exploit_plan_capture_pattern_not_declared")


class ExploitPlanDraftV1(_ExploitPlanPayloadV1):
    """Pi-facing draft whose canonical semantic digest is kernel-issued.

    A model should not need to implement a JSON canonicalizer or invent a
    digest. The API turns this exact strict draft into ``ExploitPlanV1`` before
    content-addressing it, so the candidate cannot choose its own binding.
    """

    def issue(self) -> ExploitPlanV1:
        return ExploitPlanV1.issue(**self.model_dump(mode="json"))


class ExploitCandidateSubmission(ContractModel):
    """One Pi-to-kernel candidate proposal; it cannot carry a raw flag field."""

    session_id: Identifier
    tool_call_id: Identifier
    idempotency_key: Identifier
    plan: ExploitPlanDraftV1

    def issued_plan(self) -> ExploitPlanV1:
        """Return the kernel-canonicalized candidate plan for persistence."""

        return self.plan.issue()


class VerificationReplayAttemptV1(ContractModel):
    """Secret-free record of one independent verifier replay.

    The verifier can temporarily see a flag only to submit it to the local lab
    controller or to create an ephemeral local reveal lease. It reports a
    controller-issued proof for resettable local labs, or a response/origin
    digest for a bounded public exact-instance replay, never raw candidate
    text. The two proof variants are deliberately mutually exclusive.
    """

    attempt: int = Field(ge=1, le=100)
    reset_id: Identifier
    target_generation: int = Field(ge=1)
    passed: bool
    started_from_clean_reset: bool
    flag_sha256: Sha256Digest | None = None
    # These two non-secret fields preserve the complete controller-signed
    # payload. A stored proof can therefore be independently checked later;
    # retaining only a signature, hash, reset ID and generation would not be
    # enough because Ed25519 signs the controller lab ID and issued timestamp.
    controller_lab_id: Identifier | None = None
    controller_issued_at: str | None = None
    controller_proof_id: Identifier | None = None
    controller_signature: str | None = Field(default=None, pattern=r"^[a-f0-9]{128}$")
    # Remote instances cannot provide the M5 controller's signed reset proof.
    # Bind their replay evidence to a specific response and sealed origin
    # instead; the actual flag still remains only in verifier process memory.
    remote_response_sha256: Sha256Digest | None = None
    remote_origin_sha256: Sha256Digest | None = None
    failure_code: Identifier | None = None

    @field_validator("controller_issued_at")
    @classmethod
    def validate_controller_issued_at(cls, value: str | None) -> str | None:
        """Retain the exact canonical UTC text that the controller signed."""

        if value is None:
            return None
        if _CONTROLLER_ISSUED_AT.fullmatch(value) is None:
            raise ValueError("controller_proof_issued_at_invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("controller_proof_issued_at_invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
            raise ValueError("controller_proof_issued_at_invalid")
        return value

    @model_validator(mode="after")
    def validate_outcome(self) -> VerificationReplayAttemptV1:
        has_controller_proof = any(
            value is not None
            for value in (
                self.controller_lab_id,
                self.controller_issued_at,
                self.controller_proof_id,
                self.controller_signature,
            )
        )
        controller_proof_complete = all(
            value is not None
            for value in (
                self.controller_lab_id,
                self.controller_issued_at,
                self.controller_proof_id,
                self.controller_signature,
            )
        )
        has_remote_proof = any(
            value is not None for value in (self.remote_response_sha256, self.remote_origin_sha256)
        )
        remote_proof_complete = (
            self.remote_response_sha256 is not None and self.remote_origin_sha256 is not None
        )
        if self.passed:
            if (
                not self.started_from_clean_reset
                or self.flag_sha256 is None
                or self.failure_code is not None
                or has_controller_proof == has_remote_proof
                or (has_controller_proof and not controller_proof_complete)
                or (has_remote_proof and not remote_proof_complete)
            ):
                raise ValueError("verified_replay_requires_clean_independent_proof")
        elif has_controller_proof or has_remote_proof or self.flag_sha256 is not None:
            raise ValueError("failed_replay_cannot_carry_flag_or_independent_proof")
        return self


class VerificationProofEnvelopeV1(ContractModel):
    """Opaque signed proof artifact that binds a solved run to two replays."""

    schema_version: Literal["ctfmesh.verification-proof.v1"] = "ctfmesh.verification-proof.v1"
    run_id: Identifier
    candidate_id: Identifier
    challenge_digest: Sha256Digest
    plan_artifact_digest: Sha256Digest
    target_image_digest: Sha256Digest
    replays: FrozenSequence[VerificationReplayAttemptV1] = Field(min_length=1, max_length=100)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def require_complete_successful_replays(self) -> VerificationProofEnvelopeV1:
        attempts = tuple(replay.attempt for replay in self.replays)
        if len(attempts) != len(set(attempts)) or not all(replay.passed for replay in self.replays):
            raise ValueError("verification_proof_requires_unique_successful_replays")
        return self

    def canonical_bytes(self) -> bytes:
        """Serialize a proof deterministically before content-addressing it."""

        return canonical_exploit_plan_json(self.model_dump(mode="json"))


class VerifierCompletionV1(ContractModel):
    """The verifier's authoritative, raw-flag-free job completion payload."""

    candidate_id: Identifier
    verified: bool
    environment_digest: Sha256Digest
    replay_results: FrozenSequence[VerificationReplayAttemptV1] = Field(
        min_length=1, max_length=100
    )
    proof: VerificationProofEnvelopeV1 | None = None
    failure_code: Identifier | None = None

    @model_validator(mode="after")
    def validate_completion(self) -> VerifierCompletionV1:
        all_passed = all(
            replay.passed and replay.started_from_clean_reset for replay in self.replay_results
        )
        if self.verified:
            if self.proof is None or not all_passed or self.failure_code is not None:
                raise ValueError("verified_completion_requires_clean_proof")
        elif self.proof is not None or self.failure_code is None:
            raise ValueError("rejected_completion_requires_failure_code_without_proof")
        return self


__all__ = [
    "ExploitCandidateSubmission",
    "ExploitPlanStepV1",
    "ExploitPlanDraftV1",
    "ExploitPlanV1",
    "VerificationProofEnvelopeV1",
    "VerificationReplayAttemptV1",
    "VerifierCompletionV1",
    "canonical_exploit_plan_json",
    "exploit_plan_digest",
]
