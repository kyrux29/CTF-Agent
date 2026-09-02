"""Bounded two-pass replay verifier for the M6.a exact remote-Web profile.

This deliberately supports the same small declarative, GET-only plan as M5.
It is not a generic Internet client: the control plane supplies one canonical
origin only after matching the complete code-owned M6 manifest shape; every
DNS answer must be public and the connection is pinned to a reviewed answer.
The raw candidate is returned only to the isolated worker for a short-lived
local reveal lease and never becomes part of the completion/proof records.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookiejar import CookieJar
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import uuid4

from ctfmesh_domain import (
    ExploitPlanV1,
    VerificationProofEnvelopeV1,
    VerificationReplayAttemptV1,
    VerifierCompletionV1,
    normalize_exact_host,
)

from .m5_replay import VerificationProcessingError, _read_bounded

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MAX_PLAN_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_DNS_RESULTS = 16
_REPLAY_COUNT = 2


@dataclass(frozen=True, slots=True)
class RemoteVerificationWork:
    """The sealed candidate inputs plus its exact public replay origin."""

    run_id: str
    candidate_id: str
    manifest_digest: str
    plan_artifact_digest: str
    evidence_refs: tuple[str, ...]
    origin: str


@dataclass(frozen=True, slots=True)
class RemoteReplayOutcome:
    """A durable secret-free completion and an ephemeral matching candidate."""

    completion: VerifierCompletionV1
    candidate: str | None


class _NoRedirect(HTTPRedirectHandler):
    """Keep every request bound to the original approved origin."""

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


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a validated IP while retaining the requested Host header."""

    def __init__(self, host: str, *, address: str, port: int, **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self._ctfmesh_address = address
        self._ctfmesh_port = port

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._ctfmesh_address, self._ctfmesh_port), self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS equivalent of :class:`_PinnedHTTPConnection` with correct SNI."""

    def __init__(
        self,
        host: str,
        *,
        address: str,
        port: int,
        tls_host: str,
        **kwargs: Any,
    ) -> None:
        context = ssl.create_default_context()
        super().__init__(host, context=context, **kwargs)
        self._ctfmesh_address = address
        self._ctfmesh_port = port
        self._ctfmesh_tls_host = tls_host
        self._ctfmesh_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._ctfmesh_address, self._ctfmesh_port), self.timeout
        )
        self.sock = self._ctfmesh_context.wrap_socket(
            raw_socket,
            server_hostname=self._ctfmesh_tls_host,
        )


class _PinnedHTTPHandler(HTTPHandler):
    """Inject a pinned HTTP connection into urllib's cookie-aware opener."""

    def __init__(self, *, address: str, port: int) -> None:
        super().__init__()
        self._address = address
        self._port = port

    def http_open(self, req: Request) -> Any:
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPConnection(
                host, address=self._address, port=self._port, **kwargs
            ),
            req,
        )


class _PinnedHTTPSHandler(HTTPSHandler):
    """Inject a pinned TLS connection into urllib's cookie-aware opener."""

    def __init__(self, *, address: str, port: int, tls_host: str) -> None:
        super().__init__()
        self._address = address
        self._port = port
        self._tls_host = tls_host

    def https_open(self, req: Request) -> Any:
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPSConnection(
                host,
                address=self._address,
                port=self._port,
                tls_host=self._tls_host,
                **kwargs,
            ),
            req,
        )


class RemoteReplayVerifier:
    """Replay one exact-origin plan twice with clean cookie jars and DNS pins."""

    def __init__(self, *, request_timeout_seconds: float = 5.0) -> None:
        if not 0.1 <= request_timeout_seconds <= 15:
            raise ValueError("remote_verifier_request_timeout_invalid")
        self._request_timeout_seconds = request_timeout_seconds

    async def verify(
        self,
        work: RemoteVerificationWork,
        plan_bytes: bytes,
    ) -> RemoteReplayOutcome:
        """Return only a proof-backed completion plus an in-memory flag candidate."""

        plan = _parse_and_bind_plan(work, plan_bytes)
        origin = _canonical_origin(work.origin)
        origin_digest = remote_origin_digest(origin)
        attempts: list[VerificationReplayAttemptV1] = []
        candidates: list[str] = []
        for index in range(1, _REPLAY_COUNT + 1):
            reset_id = f"remote-replay-{uuid4().hex}"
            outcome = await self._replay_once(origin, plan)
            if outcome.failure_code is not None or outcome.candidate is None:
                attempts.append(
                    VerificationReplayAttemptV1(
                        attempt=index,
                        reset_id=reset_id,
                        target_generation=1,
                        passed=False,
                        started_from_clean_reset=True,
                        failure_code=outcome.failure_code or "target_flag_not_observed",
                    )
                )
                continue
            candidates.append(outcome.candidate)
            attempts.append(
                VerificationReplayAttemptV1(
                    attempt=index,
                    reset_id=reset_id,
                    target_generation=1,
                    passed=True,
                    started_from_clean_reset=True,
                    flag_sha256=hashlib.sha256(outcome.candidate.encode("utf-8")).hexdigest(),
                    remote_response_sha256=outcome.response_sha256,
                    remote_origin_sha256=origin_digest,
                )
            )

        candidates_match = len(candidates) == _REPLAY_COUNT and hmac.compare_digest(
            candidates[0], candidates[1]
        )
        all_passed = len(attempts) == _REPLAY_COUNT and all(item.passed for item in attempts)
        if not all_passed or not candidates_match:
            # A target whose flag changes between fresh replays is intentionally
            # not a verified solve. Do not make either raw candidate available.
            return RemoteReplayOutcome(
                completion=VerifierCompletionV1(
                    candidate_id=work.candidate_id,
                    verified=False,
                    environment_digest=origin_digest,
                    replay_results=tuple(attempts),
                    failure_code="remote_replay_failed",
                ),
                candidate=None,
            )

        proof = VerificationProofEnvelopeV1(
            run_id=work.run_id,
            candidate_id=work.candidate_id,
            challenge_digest=work.manifest_digest,
            plan_artifact_digest=work.plan_artifact_digest,
            target_image_digest=origin_digest,
            replays=tuple(attempts),
            created_at=datetime.now(UTC),
        )
        return RemoteReplayOutcome(
            completion=VerifierCompletionV1(
                candidate_id=work.candidate_id,
                verified=True,
                environment_digest=origin_digest,
                replay_results=tuple(attempts),
                proof=proof,
            ),
            candidate=candidates[0],
        )

    async def _replay_once(self, origin: str, plan: ExploitPlanV1) -> _RemoteTargetOutcome:
        parsed = urlsplit(origin)
        assert parsed.hostname is not None  # enforced by _canonical_origin
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = await _resolve_public_addresses(parsed.hostname, port)
        return await asyncio.to_thread(
            _replay_target,
            origin,
            parsed.scheme,
            parsed.hostname,
            port,
            addresses[0],
            plan,
            self._request_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class _RemoteTargetOutcome:
    candidate: str | None
    response_sha256: str | None
    failure_code: str | None


def remote_work_from_wire(value: Any) -> RemoteVerificationWork:
    """Parse the remote-only work envelope without accepting arbitrary targets."""

    if not isinstance(value, dict) or set(value) != {
        "job",
        "candidate",
        "manifest_digest",
        "replay_target",
    }:
        raise VerificationProcessingError("remote_verification_work_invalid")
    candidate = value.get("candidate")
    manifest_digest = value.get("manifest_digest")
    replay_target = value.get("replay_target")
    if (
        not isinstance(candidate, dict)
        or not isinstance(manifest_digest, str)
        or _SHA256.fullmatch(manifest_digest) is None
        or replay_target is None
    ):
        raise VerificationProcessingError("remote_verification_work_invalid")
    if not isinstance(replay_target, dict) or replay_target.get("kind") != "exact_remote_origin_v1":
        raise VerificationProcessingError("remote_verification_work_invalid")
    if set(replay_target) != {"kind", "origin"} or not isinstance(replay_target.get("origin"), str):
        raise VerificationProcessingError("remote_verification_work_invalid")
    expected = {"id", "run_id", "plan_artifact_digest", "evidence_refs"}
    if set(candidate) != expected:
        raise VerificationProcessingError("remote_verification_work_invalid")
    evidence_refs = candidate["evidence_refs"]
    scalar_values = (candidate["id"], candidate["run_id"], candidate["plan_artifact_digest"])
    if (
        not isinstance(evidence_refs, list)
        or not evidence_refs
        or len(evidence_refs) > 32
        or len(evidence_refs) != len(set(evidence_refs))
        or any(
            not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None
            for item in evidence_refs
        )
        or any(not isinstance(item, str) for item in scalar_values)
        or _SHA256.fullmatch(candidate["plan_artifact_digest"]) is None
        or any(_IDENTIFIER.fullmatch(item) is None for item in scalar_values[:2])
    ):
        raise VerificationProcessingError("remote_verification_work_invalid")
    return RemoteVerificationWork(
        run_id=candidate["run_id"],
        candidate_id=candidate["id"],
        manifest_digest=manifest_digest,
        plan_artifact_digest=candidate["plan_artifact_digest"],
        evidence_refs=tuple(evidence_refs),
        origin=_canonical_origin(replay_target["origin"]),
    )


def remote_origin_digest(origin: str) -> str:
    """Return the same origin binding that the repository checks before solve."""

    return hashlib.sha256(f"ctfmesh.m6.remote-origin.v1:{origin}".encode()).hexdigest()


def _canonical_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise VerificationProcessingError("remote_replay_origin_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise VerificationProcessingError("remote_replay_origin_invalid")
    try:
        host = normalize_exact_host(parsed.hostname)
    except ValueError as exc:
        raise VerificationProcessingError("remote_replay_origin_invalid") from exc
    try:
        if not ipaddress.ip_address(host).is_global:
            raise VerificationProcessingError("remote_replay_private_address_denied")
    except ValueError:
        if host.endswith((".local", ".localhost", ".internal", ".test")):
            raise VerificationProcessingError("remote_replay_origin_invalid") from None
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    rendered_host = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme}://{rendered_host}:{effective_port}"
    if value != origin:
        raise VerificationProcessingError("remote_replay_origin_invalid")
    return origin


async def _resolve_public_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise VerificationProcessingError("remote_replay_dns_unavailable") from exc
    addresses: list[str] = []
    for _family, _socktype, _protocol, _canonical, address in records[:_MAX_DNS_RESULTS]:
        try:
            parsed = ipaddress.ip_address(address[0])
        except ValueError as exc:
            raise VerificationProcessingError("remote_replay_dns_invalid") from exc
        if not parsed.is_global:
            raise VerificationProcessingError("remote_replay_private_address_denied")
        if parsed.compressed not in addresses:
            addresses.append(parsed.compressed)
    if not addresses:
        raise VerificationProcessingError("remote_replay_dns_unavailable")
    return tuple(addresses)


def _parse_and_bind_plan(work: RemoteVerificationWork, plan_bytes: bytes) -> ExploitPlanV1:
    if len(plan_bytes) > _MAX_PLAN_BYTES:
        raise VerificationProcessingError("verification_plan_too_large")
    if hashlib.sha256(plan_bytes).hexdigest() != work.plan_artifact_digest:
        raise VerificationProcessingError("verification_plan_artifact_digest_mismatch")
    try:
        plan = ExploitPlanV1.model_validate(json.loads(plan_bytes))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise VerificationProcessingError("verification_plan_invalid") from exc
    if (
        plan.challenge_digest != work.manifest_digest
        or tuple(plan.evidence_refs) != work.evidence_refs
    ):
        raise VerificationProcessingError("verification_plan_binding_mismatch")
    return plan


def _replay_target(
    origin: str,
    scheme: str,
    host: str,
    port: int,
    address: str,
    plan: ExploitPlanV1,
    timeout_seconds: float,
) -> _RemoteTargetOutcome:
    """Use one pinned target address with one fresh cookie jar per replay."""

    handlers: list[Any] = [ProxyHandler({}), HTTPCookieProcessor(CookieJar()), _NoRedirect()]
    if scheme == "https":
        handlers.append(_PinnedHTTPSHandler(address=address, port=port, tls_host=host))
    else:
        handlers.append(_PinnedHTTPHandler(address=address, port=port))
    opener = build_opener(*handlers)
    candidate: str | None = None
    response_digest = hashlib.sha256()
    for step in plan.steps:
        query = {key: _expand(value, plan.variables) for key, value in step.query.items()}
        headers = {key: _expand(value, plan.variables) for key, value in step.headers.items()}
        url = f"{origin}{step.path}"
        if query:
            url = f"{url}?{urlencode(query, doseq=False, safe='%')}"
        request = Request(url, method="GET", headers=headers)  # noqa: S310 - origin is sealed.
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                status = response.status
                body = _read_bounded(response, _MAX_RESPONSE_BYTES)
        except HTTPError as exc:
            status = exc.code
            body = _read_bounded(exc, _MAX_RESPONSE_BYTES)
        except (OSError, URLError, http.client.HTTPException) as exc:
            raise VerificationProcessingError("remote_replay_target_unavailable") from exc
        response_digest.update(f"{status}:".encode("ascii"))
        response_digest.update(body)
        if not 200 <= status < 300:
            return _RemoteTargetOutcome(None, None, "target_status_rejected")
        if step.capture is not None:
            match = re.search(
                step.capture["flag"].removeprefix("regex:"), body.decode("utf-8", "replace")
            )
            if match is None:
                return _RemoteTargetOutcome(None, None, "target_flag_not_observed")
            candidate = match.group(0)
    return _RemoteTargetOutcome(candidate, response_digest.hexdigest(), None)


def _expand(value: str, variables: Mapping[str, str]) -> str:
    if value.startswith("${") and value.endswith("}"):
        return variables[value[2:-1]]
    return value


__all__ = [
    "RemoteReplayOutcome",
    "RemoteReplayVerifier",
    "RemoteVerificationWork",
    "remote_origin_digest",
    "remote_work_from_wire",
]
