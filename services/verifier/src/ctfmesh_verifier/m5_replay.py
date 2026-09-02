"""M5 replay implementation for fixed local labs and declarative plans.

This module has no subprocess, shell, filesystem write, Docker API, provider
client, or configurable target URL. A candidate can influence only validated
relative query/header values in a plan that has already been bound to one
trusted local lab profile by the control plane.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Final, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from ctfmesh_domain import (
    ExploitPlanV1,
    VerificationProofEnvelopeV1,
    VerificationReplayAttemptV1,
    VerifierCompletionV1,
)

from .lab_controller import LAB_IDS, verify_controller_signature

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_ED25519_SIGNATURE = re.compile(r"^[a-f0-9]{128}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_MAX_PLAN_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024


def _profile_digest(lab_id: str) -> str:
    """Pin the deployed M5 target profile without Docker-daemon authority."""

    return hashlib.sha256(f"ctfmesh.m5.lab-target.v1:{lab_id}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedLab:
    """Code-owned mapping from an approved lab identifier to one origin."""

    id: str
    origin: str
    target_image_digest: str


TRUSTED_LABS: Final[dict[str, TrustedLab]] = {
    "web-path-traversal": TrustedLab(
        id="web-path-traversal",
        origin="http://lab-path-traversal:8080",
        target_image_digest=_profile_digest("web-path-traversal"),
    ),
    "web-authz-boundary": TrustedLab(
        id="web-authz-boundary",
        origin="http://lab-authz-boundary:8080",
        target_image_digest=_profile_digest("web-authz-boundary"),
    ),
    "web-sqli-basic": TrustedLab(
        id="web-sqli-basic",
        origin="http://lab-sqli-basic:8080",
        target_image_digest=_profile_digest("web-sqli-basic"),
    ),
}

# A candidate declares a reviewed technique rather than a target host or a
# controller/lab name.  This code-owned mapping is the final binding from a
# canonical plan to the one internal origin that may be contacted.
TECHNIQUE_LABS: Final[dict[str, str]] = {
    "web.path_traversal": "web-path-traversal",
    "web.authz_boundary": "web-authz-boundary",
    "web.sqli_basic": "web-sqli-basic",
}
_M5_REPLAY_COUNT = 2


class VerificationProcessingError(RuntimeError):
    """Stable failure code that can be persisted without secret material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _NoRedirect(HTTPRedirectHandler):
    """Turn every redirect into a response failure; never follow candidate input."""

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True, slots=True)
class ControllerReset:
    lab_id: str
    generation: int
    reset_id: str


@dataclass(frozen=True, slots=True)
class ControllerProof:
    lab_id: str
    generation: int
    reset_id: str
    proof_id: str
    flag_sha256: str
    issued_at: str
    signature: str


@dataclass(frozen=True, slots=True)
class _TargetOutcome:
    """Ephemeral target output. ``candidate`` never crosses this module boundary."""

    candidate: str | None
    target_generation: int | None
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class M5VerificationWork:
    """The four candidate inputs allowed across the verifier boundary.

    The job lease is transport metadata and is deliberately parsed by the
    worker, not copied into this object.  All target selection derives from
    the canonical plan's reviewed technique after the artifact is read.
    """

    run_id: str
    candidate_id: str
    manifest_digest: str
    plan_artifact_digest: str
    evidence_refs: tuple[str, ...]


class LabController(Protocol):
    """The narrow reset/proof capability used by the replay implementation."""

    async def reset(self, lab_id: str) -> ControllerReset:
        """Reset exactly one code-owned local lab."""
        ...

    async def verify(self, *, reset: ControllerReset, candidate: str) -> ControllerProof | None:
        """Return opaque proof only for a target-observed fresh flag."""
        ...


@dataclass(frozen=True, slots=True)
class LabControllerClient:
    """Fixed-origin client for the controller's reset/proof API."""

    token: str = field(repr=False)
    proof_public_key: bytes = field(repr=False)
    base_url: str = "http://lab-controller:8085"
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.base_url != "http://lab-controller:8085":
            raise ValueError("lab_controller_origin_not_allowed")
        if not 16 <= len(self.token) <= 512 or len(self.proof_public_key) != 32:
            raise ValueError("lab_controller_credentials_invalid")
        if not 0.1 <= self.timeout_seconds <= 15:
            raise ValueError("lab_controller_timeout_invalid")

    async def reset(self, lab_id: str) -> ControllerReset:
        """Ask the controller for a new random-flag generation."""

        if lab_id not in LAB_IDS:
            raise VerificationProcessingError("verifier_lab_not_allowed")
        payload = await asyncio.to_thread(self._post, f"/v1/labs/{lab_id}/reset", {})
        expected = {"lab_id", "generation", "reset_id", "issued_at"}
        if set(payload) != expected or payload.get("lab_id") != lab_id:
            raise VerificationProcessingError("controller_reset_response_invalid")
        generation = payload.get("generation")
        reset_id = payload.get("reset_id")
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 1
            or not isinstance(reset_id, str)
            or _IDENTIFIER.fullmatch(reset_id) is None
        ):
            raise VerificationProcessingError("controller_reset_response_invalid")
        return ControllerReset(lab_id=lab_id, generation=generation, reset_id=reset_id)

    async def verify(
        self,
        *,
        reset: ControllerReset,
        candidate: str,
    ) -> ControllerProof | None:
        """Validate only a fresh target-observed candidate; controller returns no flag."""

        try:
            payload = await asyncio.to_thread(
                self._post,
                f"/v1/labs/{reset.lab_id}/verify",
                {"generation": reset.generation, "candidate": candidate},
            )
        except VerificationProcessingError as exc:
            # A correct controller response for a wrong candidate is a normal
            # rejected replay, while controller auth/transport/schema faults
            # are availability failures that must not silently reject/solve.
            if exc.code == "controller_candidate_rejected":
                return None
            raise
        if not verify_controller_signature(payload, public_key=self.proof_public_key):
            raise VerificationProcessingError("controller_proof_signature_invalid")
        if (
            payload.get("lab_id") != reset.lab_id
            or payload.get("generation") != reset.generation
            or payload.get("reset_id") != reset.reset_id
        ):
            raise VerificationProcessingError("controller_proof_binding_invalid")
        proof_id = payload.get("proof_id")
        flag_sha256 = payload.get("flag_sha256")
        issued_at = payload.get("issued_at")
        signature = payload.get("signature")
        if (
            not isinstance(proof_id, str)
            or _IDENTIFIER.fullmatch(proof_id) is None
            or not isinstance(flag_sha256, str)
            or _SHA256.fullmatch(flag_sha256) is None
            or not isinstance(issued_at, str)
            or not _is_canonical_utc_timestamp(issued_at)
            or not isinstance(signature, str)
            or _ED25519_SIGNATURE.fullmatch(signature) is None
        ):
            raise VerificationProcessingError("controller_proof_response_invalid")
        return ControllerProof(
            lab_id=reset.lab_id,
            generation=reset.generation,
            reset_id=reset.reset_id,
            proof_id=proof_id,
            flag_sha256=flag_sha256,
            issued_at=issued_at,
            signature=signature,
        )

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Use a no-proxy/no-redirect stdlib request with bounded JSON I/O."""

        # The origin is validated in ``__post_init__`` and ``path`` is a
        # controller-owned constant; no candidate can select a URL scheme.
        request = Request(  # noqa: S310
            f"{self.base_url}{path}",
            data=json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CTFMesh-Controller-Token": self.token,
            },
        )
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                status = response.status
                body = _read_bounded(response, _MAX_RESPONSE_BYTES)
        except HTTPError as exc:
            status = exc.code
            body = _read_bounded(exc, _MAX_RESPONSE_BYTES)
        except (OSError, URLError) as exc:
            raise VerificationProcessingError("lab_controller_unavailable") from exc
        parsed = _json_mapping(body, "controller_response_invalid")
        if status == 422 and parsed == {"verified": False}:
            raise VerificationProcessingError("controller_candidate_rejected")
        if status != 200:
            raise VerificationProcessingError("lab_controller_request_rejected")
        return parsed


class M5ReplayVerifier:
    """Replay one content-addressed plan twice using fresh controller/HTTP state."""

    def __init__(
        self,
        controller: LabController,
        *,
        request_timeout_seconds: float = 5.0,
        controller_timeout_seconds: float = 5.0,
        labs: Mapping[str, TrustedLab] = TRUSTED_LABS,
    ) -> None:
        if not 0.1 <= request_timeout_seconds <= 15:
            raise ValueError("verifier_request_timeout_invalid")
        if not 0.1 <= controller_timeout_seconds <= 15:
            raise ValueError("verifier_controller_timeout_invalid")
        if not labs:
            raise ValueError("verifier_trusted_labs_required")
        self._controller = controller
        self._request_timeout_seconds = request_timeout_seconds
        # ``LabControllerClient`` has a transport timeout, but the narrow
        # protocol also admits another async implementation in tests and at a
        # future composition boundary. Bound that capability here as well: a
        # stuck controller must fail verification, never leave a candidate in
        # a path that could be mistaken for a successful replay.
        self._controller_timeout_seconds = controller_timeout_seconds
        self._labs = dict(labs)

    async def verify(self, work: M5VerificationWork, plan_bytes: bytes) -> VerifierCompletionV1:
        """Produce a raw-flag-free success or controlled candidate rejection."""

        plan = self._parse_and_bind_plan(work, plan_bytes)
        lab_id = TECHNIQUE_LABS.get(plan.technique_id)
        lab = None if lab_id is None else self._labs.get(lab_id)
        if lab is None:
            raise VerificationProcessingError("verifier_technique_not_allowed")
        attempts: list[VerificationReplayAttemptV1] = []
        for index in range(1, _M5_REPLAY_COUNT + 1):
            reset = await self._controller_reset(lab.id)
            target = await asyncio.to_thread(self._replay_target, lab, plan, reset)
            if target.failure_code in {
                "target_profile_mismatch",
                "target_reset_generation_mismatch",
            }:
                raise VerificationProcessingError(target.failure_code)
            if target.failure_code is not None or target.candidate is None:
                attempts.append(
                    VerificationReplayAttemptV1(
                        attempt=index,
                        reset_id=reset.reset_id,
                        target_generation=reset.generation,
                        passed=False,
                        started_from_clean_reset=target.target_generation == reset.generation,
                        failure_code=target.failure_code or "target_flag_not_observed",
                    )
                )
                continue
            proof = await self._controller_verify(reset=reset, candidate=target.candidate)
            if proof is None:
                attempts.append(
                    VerificationReplayAttemptV1(
                        attempt=index,
                        reset_id=reset.reset_id,
                        target_generation=reset.generation,
                        passed=False,
                        started_from_clean_reset=True,
                        failure_code="controller_rejected_candidate",
                    )
                )
                continue
            if (
                proof.lab_id != lab.id
                or proof.generation != reset.generation
                or proof.reset_id != reset.reset_id
            ):
                raise VerificationProcessingError("controller_proof_binding_invalid")
            attempts.append(
                VerificationReplayAttemptV1(
                    attempt=index,
                    reset_id=proof.reset_id,
                    target_generation=proof.generation,
                    passed=True,
                    started_from_clean_reset=True,
                    flag_sha256=proof.flag_sha256,
                    controller_lab_id=proof.lab_id,
                    controller_issued_at=proof.issued_at,
                    controller_proof_id=proof.proof_id,
                    controller_signature=proof.signature,
                )
            )

        all_passed = len(attempts) == _M5_REPLAY_COUNT and all(
            attempt.passed for attempt in attempts
        )
        if not all_passed:
            return VerifierCompletionV1(
                candidate_id=work.candidate_id,
                verified=False,
                environment_digest=lab.target_image_digest,
                replay_results=tuple(attempts),
                failure_code="replay_failed",
            )
        proof = VerificationProofEnvelopeV1(
            run_id=work.run_id,
            candidate_id=work.candidate_id,
            challenge_digest=work.manifest_digest,
            plan_artifact_digest=work.plan_artifact_digest,
            target_image_digest=lab.target_image_digest,
            replays=tuple(attempts),
            created_at=datetime.now(UTC),
        )
        return VerifierCompletionV1(
            candidate_id=work.candidate_id,
            verified=True,
            environment_digest=lab.target_image_digest,
            replay_results=tuple(attempts),
            proof=proof,
        )

    async def _controller_reset(self, lab_id: str) -> ControllerReset:
        """Apply a verifier-owned deadline to the controller reset capability."""

        try:
            return await asyncio.wait_for(
                self._controller.reset(lab_id),
                timeout=self._controller_timeout_seconds,
            )
        except TimeoutError as exc:
            raise VerificationProcessingError("lab_controller_timeout") from exc

    async def _controller_verify(
        self,
        *,
        reset: ControllerReset,
        candidate: str,
    ) -> ControllerProof | None:
        """Apply the same deadline to proof validation after target replay."""

        try:
            return await asyncio.wait_for(
                self._controller.verify(reset=reset, candidate=candidate),
                timeout=self._controller_timeout_seconds,
            )
        except TimeoutError as exc:
            raise VerificationProcessingError("lab_controller_timeout") from exc

    def _parse_and_bind_plan(self, work: M5VerificationWork, plan_bytes: bytes) -> ExploitPlanV1:
        """Reject an artifact substitution before any controller or target call."""

        if len(plan_bytes) > _MAX_PLAN_BYTES:
            raise VerificationProcessingError("verification_plan_too_large")
        if hashlib.sha256(plan_bytes).hexdigest() != work.plan_artifact_digest:
            raise VerificationProcessingError("verification_plan_artifact_digest_mismatch")
        try:
            parsed = json.loads(plan_bytes)
            plan = ExploitPlanV1.model_validate(parsed)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VerificationProcessingError("verification_plan_invalid") from exc
        if (
            plan.challenge_digest != work.manifest_digest
            or tuple(plan.evidence_refs) != work.evidence_refs
        ):
            raise VerificationProcessingError("verification_plan_binding_mismatch")
        return plan

    def _replay_target(
        self,
        lab: TrustedLab,
        plan: ExploitPlanV1,
        reset: ControllerReset,
    ) -> _TargetOutcome:
        """Replay one plan in a fresh cookie jar and reject redirects/external hosts."""

        jar = CookieJar()
        opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(jar), _NoRedirect())
        # Fetch a code-owned health path before the plan. It proves the target
        # profile and the fresh reset generation without trusting plan input.
        health_status, health_headers, _ = self._target_get(opener, lab.origin, "/health", {}, {})
        if (
            health_status != 200
            or health_headers.get("x-ctfmesh-target-digest") != lab.target_image_digest
        ):
            return _TargetOutcome(None, None, "target_profile_mismatch")
        health_generation = _generation(health_headers)
        if health_generation != reset.generation:
            return _TargetOutcome(None, health_generation, "target_reset_generation_mismatch")

        candidate: str | None = None
        observed_generation: int | None = health_generation
        for step in plan.steps:
            query = {key: _expand(value, plan.variables) for key, value in step.query.items()}
            headers = {key: _expand(value, plan.variables) for key, value in step.headers.items()}
            status, response_headers, body = self._target_get(
                opener, lab.origin, step.path, query, headers
            )
            observed_generation = _generation(response_headers)
            if not 200 <= status < 300:
                return _TargetOutcome(None, observed_generation, "target_status_rejected")
            if observed_generation != reset.generation:
                return _TargetOutcome(None, observed_generation, "target_reset_generation_mismatch")
            if step.capture is not None:
                pattern = step.capture["flag"].removeprefix("regex:")
                match = re.search(pattern, body)
                if match is None:
                    return _TargetOutcome(None, observed_generation, "target_flag_not_observed")
                candidate = match.group(0)
        return _TargetOutcome(candidate, observed_generation, None)

    def _target_get(
        self,
        opener: Any,
        origin: str,
        path: str,
        query: dict[str, str],
        headers: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        """Execute a target-relative GET without redirect, proxy, or URL joining."""

        # ``ExploitPlanV1`` validates this already; repeat the cheap check at
        # the network boundary so future parser changes cannot create an SSRF.
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            return 400, {}, ""
        url = f"{origin}{path}"
        if query:
            url = f"{url}?{urlencode(query, doseq=False, safe='%')}"
        # ``origin`` is code-owned and ``path`` was checked above against the
        # declarative contract, so this cannot select a file/custom scheme.
        request = Request(url, method="GET", headers=headers)  # noqa: S310
        try:
            with opener.open(request, timeout=self._request_timeout_seconds) as response:
                return (
                    response.status,
                    _headers(response.headers),
                    _read_bounded(response, _MAX_RESPONSE_BYTES).decode("utf-8", errors="replace"),
                )
        except HTTPError as exc:
            return (
                exc.code,
                _headers(exc.headers),
                _read_bounded(exc, _MAX_RESPONSE_BYTES).decode("utf-8", errors="replace"),
            )
        except (OSError, URLError) as exc:
            raise VerificationProcessingError("lab_target_unavailable") from exc


def read_candidate_plan(root: Path, digest: str) -> bytes:
    """Read one verified object path without accepting a caller-controlled file path."""

    if _SHA256.fullmatch(digest) is None:
        raise VerificationProcessingError("verification_plan_digest_invalid")
    store_root = root.resolve()
    object_path = store_root / "objects" / "sha256" / digest[:2] / digest[2:4] / digest
    try:
        payload = object_path.read_bytes()
    except OSError as exc:
        raise VerificationProcessingError("verification_plan_artifact_unavailable") from exc
    if len(payload) > _MAX_PLAN_BYTES or hashlib.sha256(payload).hexdigest() != digest:
        raise VerificationProcessingError("verification_plan_artifact_integrity_failed")
    return payload


def work_from_wire(value: Any) -> M5VerificationWork:
    """Parse only the small internal API shape needed by the verifier worker."""

    if not isinstance(value, dict) or set(value) != {"job", "candidate", "manifest_digest"}:
        raise VerificationProcessingError("verification_work_invalid")
    candidate = value.get("candidate")
    manifest_digest = value.get("manifest_digest")
    if not isinstance(candidate, dict) or not isinstance(manifest_digest, str):
        raise VerificationProcessingError("verification_work_invalid")
    required = {"id", "run_id", "plan_artifact_digest", "evidence_refs"}
    if set(candidate) != required or _SHA256.fullmatch(manifest_digest) is None:
        raise VerificationProcessingError("verification_work_invalid")
    evidence_refs = candidate["evidence_refs"]
    if (
        not isinstance(evidence_refs, list)
        or not evidence_refs
        or len(evidence_refs) > 32
        or any(
            not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None
            for item in evidence_refs
        )
        or len(evidence_refs) != len(set(evidence_refs))
    ):
        raise VerificationProcessingError("verification_work_invalid")
    scalar_values = (
        candidate["id"],
        candidate["run_id"],
        candidate["plan_artifact_digest"],
    )
    if (
        any(not isinstance(item, str) for item in scalar_values)
        or _SHA256.fullmatch(candidate["plan_artifact_digest"]) is None
    ):
        raise VerificationProcessingError("verification_work_invalid")
    if any(_IDENTIFIER.fullmatch(item) is None for item in (candidate["id"], candidate["run_id"])):
        raise VerificationProcessingError("verification_work_invalid")
    return M5VerificationWork(
        run_id=candidate["run_id"],
        candidate_id=candidate["id"],
        manifest_digest=manifest_digest,
        plan_artifact_digest=candidate["plan_artifact_digest"],
        evidence_refs=tuple(evidence_refs),
    )


def controller_proof_payload_from_replay(
    replay: VerificationReplayAttemptV1,
) -> dict[str, Any]:
    """Rebuild the exact controller-signed opaque payload from a stored replay.

    The raw target candidate never enters this record.  The controller lab ID
    and exact UTC timestamp are nevertheless required alongside the existing
    generation/reset/hash/proof ID, otherwise an auditor could not verify the
    persisted Ed25519 signature after the live controller response is gone.
    """

    fields = (
        replay.controller_lab_id,
        replay.controller_issued_at,
        replay.controller_proof_id,
        replay.flag_sha256,
        replay.controller_signature,
    )
    if not replay.passed or any(value is None for value in fields):
        raise VerificationProcessingError("controller_proof_replay_invalid")
    return {
        "lab_id": replay.controller_lab_id,
        "generation": replay.target_generation,
        "reset_id": replay.reset_id,
        "proof_id": replay.controller_proof_id,
        "flag_sha256": replay.flag_sha256,
        "issued_at": replay.controller_issued_at,
        "verified": True,
        "signature": replay.controller_signature,
    }


def _headers(value: Any) -> dict[str, str]:
    return {str(key).lower(): str(item) for key, item in value.items()}


def _generation(headers: dict[str, str]) -> int | None:
    value = headers.get("x-ctfmesh-generation")
    try:
        parsed = int(value) if value is not None else 0
    except ValueError:
        return None
    return parsed if parsed >= 1 else None


def _is_canonical_utc_timestamp(value: object) -> bool:
    """Accept only the `Z`-suffixed UTC text emitted and signed by controller."""

    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _expand(value: str, variables: dict[str, str]) -> str:
    """Resolve the only supported whole-value placeholder syntax."""

    if value.startswith("${") and value.endswith("}"):
        return variables[value[2:-1]]
    return value


def _read_bounded(response: Any, maximum: int) -> bytes:
    payload = response.read(maximum + 1)
    if len(payload) > maximum:
        raise VerificationProcessingError("target_response_too_large")
    return payload


def _json_mapping(payload: bytes, failure_code: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationProcessingError(failure_code) from exc
    if not isinstance(value, dict):
        raise VerificationProcessingError(failure_code)
    return value


__all__ = [
    "ControllerProof",
    "ControllerReset",
    "controller_proof_payload_from_replay",
    "LabControllerClient",
    "M5ReplayVerifier",
    "M5VerificationWork",
    "TECHNIQUE_LABS",
    "TRUSTED_LABS",
    "TrustedLab",
    "VerificationProcessingError",
    "read_candidate_plan",
    "work_from_wire",
]
