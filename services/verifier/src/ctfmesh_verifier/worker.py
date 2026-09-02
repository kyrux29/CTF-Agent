"""Independent M5 verifier worker.

The worker has one purpose: lease a verifier job, read the immutable plan,
replay it against fixed local labs, and return a raw-flag-free conclusion.
It has no database connection, Pi session, provider key, source mount, shell,
or Docker API.  Any unavailable dependency leaves the candidate in
``VERIFYING`` through the control API's explicit failure path.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ctfmesh_domain import VerifierCompletionV1

from .m5_replay import (
    LabControllerClient,
    M5ReplayVerifier,
    VerificationProcessingError,
    _read_bounded,
    read_candidate_plan,
    work_from_wire,
)
from .remote_replay import RemoteReplayVerifier, remote_work_from_wire

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_:-]{0,159}$")
_MAX_CONTROL_RESPONSE_BYTES = 256 * 1024
_CONTROL_ORIGIN = "http://api:8000"


class VerifierWorkerConfigurationError(RuntimeError):
    """Stable startup failure that never embeds configured secrets."""


class VerifierControlError(RuntimeError):
    """A fail-closed control-plane client error safe to log as its code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _NoRedirect(HTTPRedirectHandler):
    """Reject redirects rather than allowing an API response to select a host."""

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
class VerifierWorkerConfig:
    """Reviewed M5 deployment settings with secret values omitted from repr."""

    verifier_id: str
    verifier_token: str = field(repr=False)
    controller_token: str | None = field(repr=False)
    controller_proof_public_key: bytes | None = field(repr=False)
    plan_artifact_root: Path
    poll_interval_seconds: float
    request_timeout_seconds: float
    control_base_url: str = _CONTROL_ORIGIN
    remote_replay_enabled: bool = False

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.verifier_id) is None:
            raise ValueError("verifier_worker_id_invalid")
        if not 16 <= len(self.verifier_token) <= 512:
            raise ValueError("verifier_worker_token_invalid")
        has_controller_token = self.controller_token is not None
        has_controller_key = self.controller_proof_public_key is not None
        if has_controller_token and not has_controller_key:
            raise ValueError("verifier_worker_controller_public_key_invalid")
        if has_controller_key and not has_controller_token:
            raise ValueError("verifier_worker_controller_token_invalid")
        if not self.remote_replay_enabled and not has_controller_token:
            raise ValueError("verifier_worker_controller_public_key_invalid")
        if self.controller_token is not None and not 16 <= len(self.controller_token) <= 512:
            raise ValueError("verifier_worker_controller_token_invalid")
        if (
            self.controller_proof_public_key is not None
            and len(self.controller_proof_public_key) != 32
        ):
            raise ValueError("verifier_worker_controller_public_key_invalid")
        if not self.plan_artifact_root.is_absolute():
            raise ValueError("verifier_worker_plan_artifact_root_not_absolute")
        if self.control_base_url != _CONTROL_ORIGIN:
            raise ValueError("verifier_worker_control_origin_not_allowed")
        if not 0.1 <= self.poll_interval_seconds <= 60:
            raise ValueError("verifier_worker_poll_interval_invalid")
        if not 0.1 <= self.request_timeout_seconds <= 15:
            raise ValueError("verifier_worker_request_timeout_invalid")


def load_verifier_worker_config(
    environment: dict[str, str] | None = None,
) -> VerifierWorkerConfig:
    """Parse only fixed container configuration and fail closed when absent."""

    values = os.environ if environment is None else environment
    verifier_id = values.get("CTFMESH_VERIFIER_ID", "independent-verifier").strip()
    verifier_token = values.get("CTFMESH_INTERNAL_VERIFIER_TOKEN", "")
    remote_replay_enabled = (
        values.get("CTFMESH_VERIFIER_REMOTE_REPLAY_ENABLED", "").lower() == "true"
    )
    controller_token = values.get("CTFMESH_LAB_CONTROLLER_TOKEN", "") or None
    public_key_hex = values.get("CTFMESH_LAB_CONTROLLER_PUBLIC_KEY", "")
    if public_key_hex:
        try:
            proof_public_key = bytes.fromhex(public_key_hex)
        except ValueError as exc:
            raise VerifierWorkerConfigurationError(
                "verifier_worker_controller_public_key_invalid"
            ) from exc
    else:
        proof_public_key = None
    root_text = values.get("CTFMESH_VERIFIER_PLAN_ARTIFACT_ROOT", "").strip()
    if not root_text:
        raise VerifierWorkerConfigurationError("verifier_worker_plan_artifact_root_missing")
    poll_milliseconds = _positive_milliseconds(
        values.get("CTFMESH_VERIFIER_POLL_MS", "750"),
        minimum=100,
        maximum=60_000,
        code="verifier_worker_poll_interval_invalid",
    )
    timeout_milliseconds = _positive_milliseconds(
        values.get("CTFMESH_VERIFIER_REQUEST_TIMEOUT_MS", "5000"),
        minimum=100,
        maximum=15_000,
        code="verifier_worker_request_timeout_invalid",
    )
    try:
        return VerifierWorkerConfig(
            verifier_id=verifier_id,
            verifier_token=verifier_token,
            controller_token=controller_token,
            controller_proof_public_key=proof_public_key,
            plan_artifact_root=Path(root_text),
            poll_interval_seconds=poll_milliseconds / 1000,
            request_timeout_seconds=timeout_milliseconds / 1000,
            control_base_url=values.get("CTFMESH_VERIFIER_CONTROL_BASE_URL", _CONTROL_ORIGIN),
            remote_replay_enabled=remote_replay_enabled,
        )
    except ValueError as exc:
        raise VerifierWorkerConfigurationError(str(exc)) from exc


def _positive_milliseconds(value: str, *, minimum: int, maximum: int, code: str) -> int:
    if not value.isdecimal():
        raise VerifierWorkerConfigurationError(code)
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise VerifierWorkerConfigurationError(code)
    return parsed


@dataclass(frozen=True, slots=True)
class VerifierLease:
    """Only the durable lease fields the worker needs after claiming a job."""

    job_id: str
    lease_version: int


@dataclass(frozen=True, slots=True)
class VerifierControlClient:
    """No-proxy client for the fixed internal control API origin."""

    verifier_id: str
    token: str = field(repr=False)
    base_url: str = _CONTROL_ORIGIN
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.verifier_id) is None:
            raise ValueError("verifier_worker_id_invalid")
        if not 16 <= len(self.token) <= 512:
            raise ValueError("verifier_worker_token_invalid")
        if self.base_url != _CONTROL_ORIGIN:
            raise ValueError("verifier_worker_control_origin_not_allowed")
        if not 0.1 <= self.timeout_seconds <= 15:
            raise ValueError("verifier_worker_request_timeout_invalid")

    async def claim(self) -> VerifierLease | None:
        """Lease a single M5 job, never a Pi or generic runtime job."""

        payload = await asyncio.to_thread(
            self._post,
            "/internal/verification-jobs/claim",
            {"verifier_id": self.verifier_id, "lease_seconds": 30},
        )
        if set(payload) != {"job"}:
            raise VerifierControlError("verifier_claim_response_invalid")
        raw_job = payload["job"]
        if raw_job is None:
            return None
        if not isinstance(raw_job, dict):
            raise VerifierControlError("verifier_claim_response_invalid")
        expected_keys = {
            "id",
            "run_id",
            "kind",
            "payload_ref",
            "payload_digest",
            "state",
            "lease_owner",
            "lease_version",
            "lease_expires_at",
            "attempts",
            "deadline_at",
            "created_at",
            "updated_at",
        }
        if set(raw_job) != expected_keys:
            raise VerifierControlError("verifier_claim_response_invalid")
        job_id = raw_job.get("id")
        lease_version = raw_job.get("lease_version")
        if (
            not isinstance(job_id, str)
            or _IDENTIFIER.fullmatch(job_id) is None
            or raw_job.get("kind") != "verify"
            or raw_job.get("state") != "leased"
            or raw_job.get("lease_owner") != self.verifier_id
            or not isinstance(lease_version, int)
            or isinstance(lease_version, bool)
            or lease_version < 1
        ):
            raise VerifierControlError("verifier_claim_response_invalid")
        return VerifierLease(job_id=job_id, lease_version=lease_version)

    async def work(self, lease: VerifierLease) -> dict[str, Any]:
        """Retrieve the minimal M5 work envelope for the exact active lease."""

        result = await asyncio.to_thread(
            self._post,
            f"/internal/verification-jobs/{lease.job_id}/work",
            self._lease_body(lease),
        )
        return result

    async def complete(self, lease: VerifierLease, completion: VerifierCompletionV1) -> None:
        """Submit the verifier's raw-flag-free conclusion once it is durable."""

        payload = {
            **self._lease_body(lease),
            "completion": completion.model_dump(mode="json", exclude_none=True),
        }
        result = await asyncio.to_thread(
            self._post,
            f"/internal/verification-jobs/{lease.job_id}/completion",
            payload,
        )
        if set(result) != {"verification", "candidate"}:
            raise VerifierControlError("verifier_completion_response_invalid")

    async def stage_remote_flag(
        self,
        lease: VerifierLease,
        *,
        candidate_id: str,
        flag: str,
    ) -> None:
        """Pass a verified remote flag to API process memory only once."""

        result = await asyncio.to_thread(
            self._post,
            f"/internal/verification-jobs/{lease.job_id}/remote-flag-lease",
            {**self._lease_body(lease), "candidate_id": candidate_id, "flag": flag},
        )
        if result != {"accepted": True}:
            raise VerifierControlError("verifier_remote_flag_lease_response_invalid")

    async def fail(self, lease: VerifierLease, *, reason: str) -> None:
        """Persist an availability failure without changing the run to solved/rejected."""

        if _FAILURE_CODE.fullmatch(reason) is None:
            raise ValueError("verifier_failure_code_invalid")
        result = await asyncio.to_thread(
            self._post,
            f"/internal/verification-jobs/{lease.job_id}/failure",
            {**self._lease_body(lease), "reason": reason},
        )
        if set(result) != {"job", "candidate"}:
            raise VerifierControlError("verifier_failure_response_invalid")

    def _lease_body(self, lease: VerifierLease) -> dict[str, object]:
        return {"verifier_id": self.verifier_id, "lease_version": lease.lease_version}

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, Any]:
        """Perform bounded JSON I/O without following proxy or redirect settings."""

        # The worker validates its sole API origin at startup and this method
        # receives only fixed internal paths; no URL is model-controlled.
        request = Request(  # noqa: S310
            f"{self.base_url}{path}",
            data=json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CTFMesh-Verifier-Token": self.token,
            },
        )
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                status = response.status
                body = _read_bounded(response, _MAX_CONTROL_RESPONSE_BYTES)
        except HTTPError as exc:
            status = exc.code
            body = _read_bounded(exc, _MAX_CONTROL_RESPONSE_BYTES)
        except (OSError, URLError) as exc:
            raise VerifierControlError("control_api_unavailable") from exc
        if status != 200:
            # Do not parse, return, or log an error detail: API errors could
            # include a user-controlled identifier or deployment metadata.
            raise VerifierControlError("control_api_request_rejected")
        try:
            result = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerifierControlError("control_api_response_invalid") from exc
        if not isinstance(result, dict):
            raise VerifierControlError("control_api_response_invalid")
        return result


async def run_verifier_worker(config: VerifierWorkerConfig, stop: asyncio.Event) -> None:
    """Process one M5 lease at a time with conservative ambiguity handling."""

    control = VerifierControlClient(
        verifier_id=config.verifier_id,
        token=config.verifier_token,
        base_url=config.control_base_url,
        timeout_seconds=config.request_timeout_seconds,
    )
    local_replay = None
    if config.controller_token is not None and config.controller_proof_public_key is not None:
        local_replay = M5ReplayVerifier(
            LabControllerClient(
                token=config.controller_token,
                proof_public_key=config.controller_proof_public_key,
                timeout_seconds=config.request_timeout_seconds,
            ),
            request_timeout_seconds=config.request_timeout_seconds,
            # Keep the outer async controller deadline aligned with the injected
            # client's transport deadline. A future LabController implementation
            # cannot silently wait longer than this verifier worker's reviewed
            # request budget.
            controller_timeout_seconds=config.request_timeout_seconds,
        )
    remote_replay = (
        RemoteReplayVerifier(request_timeout_seconds=config.request_timeout_seconds)
        if config.remote_replay_enabled
        else None
    )
    while not stop.is_set():
        try:
            lease = await control.claim()
        except VerifierControlError as exc:
            _log_code(exc.code)
            await _wait_or_stop(stop, config.poll_interval_seconds)
            continue
        if lease is None:
            await _wait_or_stop(stop, config.poll_interval_seconds)
            continue

        completion_started = False
        try:
            raw_work = await control.work(lease)
            if "replay_target" in raw_work:
                if remote_replay is None:
                    raise VerificationProcessingError("remote_replay_not_enabled")
                work = remote_work_from_wire(raw_work)
                plan_bytes = await asyncio.to_thread(
                    read_candidate_plan,
                    config.plan_artifact_root,
                    work.plan_artifact_digest,
                )
                remote_outcome = await remote_replay.verify(work, plan_bytes)
                completion = remote_outcome.completion
                if completion.verified:
                    if remote_outcome.candidate is None:
                        raise VerificationProcessingError("remote_replay_candidate_missing")
                    await control.stage_remote_flag(
                        lease,
                        candidate_id=work.candidate_id,
                        flag=remote_outcome.candidate,
                    )
            else:
                if local_replay is None:
                    raise VerificationProcessingError("local_replay_not_enabled")
                work = work_from_wire(raw_work)
                plan_bytes = await asyncio.to_thread(
                    read_candidate_plan,
                    config.plan_artifact_root,
                    work.plan_artifact_digest,
                )
                completion = await local_replay.verify(work, plan_bytes)
            completion_started = True
            await control.complete(lease, completion)
        except VerificationProcessingError as exc:
            await _record_pre_completion_failure(control, lease, exc.code, completion_started)
        except VerifierControlError as exc:
            # A completion call can have succeeded after the HTTP connection
            # broke. Do not overwrite that ambiguous terminal outcome with a
            # failure; the durable lease/retry path will resolve it safely.
            await _record_pre_completion_failure(control, lease, exc.code, completion_started)
        except (OSError, RuntimeError):
            await _record_pre_completion_failure(
                control,
                lease,
                "verifier_worker_iteration_failed",
                completion_started,
            )


async def _record_pre_completion_failure(
    control: VerifierControlClient,
    lease: VerifierLease,
    reason: str,
    completion_started: bool,
) -> None:
    """Store failures only while no ambiguous completion request was sent."""

    if completion_started:
        _log_code(reason)
        return
    try:
        await control.fail(lease, reason=reason)
    except (VerifierControlError, ValueError):
        # A lost lease/control outage is intentionally non-terminal. The run
        # stays VERIFYING and never becomes solved based on worker self-report.
        _log_code(reason)


async def _wait_or_stop(stop: asyncio.Event, timeout_seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=timeout_seconds)
    except TimeoutError:
        return


def _log_code(code: str) -> None:
    """Log only an allowlisted, secret-free operational code."""

    safe_code = code if _FAILURE_CODE.fullmatch(code) is not None else "verifier_worker_failed"
    print(f"[ctfmesh-verifier] {safe_code}", file=sys.stderr, flush=True)


def main() -> NoReturn:
    """Container entrypoint with normal signal-driven cancellation."""

    try:
        config = load_verifier_worker_config()
    except VerifierWorkerConfigurationError as exc:
        _log_code(str(exc))
        raise SystemExit(1) from None
    stop = asyncio.Event()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for received_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(received_signal, stop.set)
    try:
        loop.run_until_complete(run_verifier_worker(config, stop))
    finally:
        loop.close()
    raise SystemExit(0)


__all__ = [
    "VerifierControlClient",
    "VerifierControlError",
    "VerifierLease",
    "VerifierWorkerConfig",
    "VerifierWorkerConfigurationError",
    "load_verifier_worker_config",
    "main",
    "run_verifier_worker",
]
