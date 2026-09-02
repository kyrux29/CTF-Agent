"""Run one secret-safe M3 source/target authorization probe inside the API container.

This is not a solver and never submits a finding, candidate, or flag. It creates
its own diagnostic run, drives the same authenticated control API used by Pi,
checks source/HTTP evidence and idempotency, proves an undeclared alias is
denied, then cancels and disposes the diagnostic sessions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

_CONTROL_ORIGIN = "http://127.0.0.1:8000"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_:-]{0,159}$")
_RUNNER_ID = "m3-operator-probe"
_REQUEST_TIMEOUT_SECONDS = 15


class M3ProbeError(RuntimeError):
    """A stable error code whose text cannot contain response/source material."""

    def __init__(self, code: str) -> None:
        self.code = code if _SAFE_ERROR_CODE.fullmatch(code) else "m3_probe_failed"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class ProbeReport:
    """Only non-sensitive evidence metadata returned to the terminal."""

    run_id: str
    source_digest: str
    http_digest: str | None
    http_status: int | None
    denial_code: str | None
    cleanup_complete: bool


def _mapping(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise M3ProbeError(code)
    return value


def _identifier(value: str, label: str) -> str:
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(f"{label} must be a safe identifier")
    return value


def _challenge_id(value: str) -> str:
    return _identifier(value, "challenge ID")


def _target_alias(value: str) -> str:
    return _identifier(value, "target alias")


def _source_path(value: str) -> str:
    """Accept one concrete POSIX-relative file without resolving the host filesystem."""

    if not value or len(value) > 4_096 or value != value.strip() or "\\" in value:
        raise argparse.ArgumentTypeError("source path must be a POSIX-relative file")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise argparse.ArgumentTypeError("source path must stay inside the challenge root")
    return value


def _http_path(value: str) -> str:
    if (
        not value.startswith("/")
        or value.startswith("//")
        or len(value) > 4_096
        or "#" in value
        or "?" in value
    ):
        raise argparse.ArgumentTypeError("HTTP path must be a relative-origin path without query")
    return value


def _wait_seconds(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("wait seconds must be an integer") from exc
    if not 10 <= parsed <= 300:
        raise argparse.ArgumentTypeError("wait seconds must be between 10 and 300")
    return parsed


class ControlApi:
    """Minimal fixed-origin client; the runner token is never printable or persisted."""

    def __init__(self, runner_token: str) -> None:
        if len(runner_token) < 16 or len(runner_token) > 512:
            raise M3ProbeError("m3_probe_runner_token_invalid")
        self._runner_token = runner_token
        # Ignore ambient HTTP(S)_PROXY. The probe can contact only the API
        # process in its own container and is not a generic URL client.
        self._opener = build_opener(ProxyHandler({}))

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        internal: bool = False,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if method not in {"GET", "POST"} or not path.startswith("/") or path.startswith("//"):
            raise M3ProbeError("m3_probe_request_invalid")
        encoded = None
        headers = {"accept": "application/json"}
        if payload is not None:
            encoded = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
            headers["content-type"] = "application/json"
        if internal:
            headers["x-ctfmesh-runner-token"] = self._runner_token
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key
        request = Request(  # noqa: S310 - fixed loopback HTTP origin and validated path.
            f"{_CONTROL_ORIGIN}{path}",
            data=encoded,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                body = response.read(512 * 1024)
        except HTTPError as exc:
            # Parse only a stable server code. Never include an error body,
            # source observation, target body, or header in the exception.
            try:
                decoded = json.loads(exc.read(16 * 1024))
                detail = decoded.get("detail", {}) if isinstance(decoded, dict) else {}
                code = detail.get("code") if isinstance(detail, dict) else None
            except (OSError, ValueError):
                code = None
            safe_code = code if isinstance(code, str) and _SAFE_ERROR_CODE.fullmatch(code) else None
            raise M3ProbeError(safe_code or "m3_probe_control_rejected") from None
        except (OSError, URLError) as exc:
            raise M3ProbeError("m3_probe_control_unavailable") from exc
        try:
            return _mapping(json.loads(body), "m3_probe_response_invalid")
        except (UnicodeDecodeError, ValueError) as exc:
            raise M3ProbeError("m3_probe_response_invalid") from exc


def _manifest_configuration(
    challenge: Mapping[str, Any],
    *,
    require_http: bool,
) -> tuple[str, dict[str, int | float], frozenset[str], frozenset[str]]:
    manifest = _mapping(challenge.get("manifest"), "m3_probe_challenge_invalid")
    spec = _mapping(manifest.get("spec"), "m3_probe_challenge_invalid")
    mode = spec.get("mode")
    limits = _mapping(spec.get("limits"), "m3_probe_challenge_invalid")
    target = _mapping(spec.get("target"), "m3_probe_challenge_invalid")
    raw_tools = spec.get("tool_profile")
    raw_aliases = target.get("target_aliases", {})
    if (
        not isinstance(mode, str)
        or not isinstance(raw_tools, list)
        or not isinstance(raw_aliases, dict)
    ):
        raise M3ProbeError("m3_probe_challenge_invalid")
    tools = frozenset(item for item in raw_tools if isinstance(item, str))
    aliases = frozenset(key for key in raw_aliases if isinstance(key, str))
    required_tools = {"source.read"} | ({"http.request"} if require_http else set())
    if not required_tools.issubset(tools):
        raise M3ProbeError("m3_probe_tool_profile_incomplete")
    required_limits = {
        "wall_time_seconds": int,
        "max_tool_calls": int,
        "max_http_requests": int,
        "max_cost_usd": (int, float),
    }
    budget: dict[str, int | float] = {}
    for name, expected_type in required_limits.items():
        value = limits.get(name)
        if isinstance(value, bool) or not isinstance(value, expected_type):
            raise M3ProbeError("m3_probe_challenge_invalid")
        # ``expected_type`` is data-driven, so Pyright cannot infer the
        # narrowing performed by isinstance even though the runtime can.
        budget[name] = cast(int | float, value)
    if budget["max_tool_calls"] < (2 if require_http else 1):
        raise M3ProbeError("m3_probe_budget_too_small")
    if require_http and budget["max_http_requests"] < 1:
        raise M3ProbeError("m3_probe_budget_too_small")
    return mode, budget, tools, aliases


def _lease(job: Mapping[str, Any]) -> dict[str, object]:
    job_id = job.get("id")
    lease_version = job.get("lease_version")
    if not isinstance(job_id, str) or not isinstance(lease_version, int):
        raise M3ProbeError("m3_probe_job_invalid")
    return {"runner_id": _RUNNER_ID, "lease_version": lease_version}


def _job_id(job: Mapping[str, Any]) -> str:
    value = job.get("id")
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise M3ProbeError("m3_probe_job_invalid")
    return value


def _claim(
    api: ControlApi,
    run_id: str,
    *,
    expected_kind: str | None,
    deadline: float,
) -> dict[str, Any] | None:
    """Lease only this probe's run, never the global Pi queue."""

    while True:
        response = api.request(
            "POST",
            "/internal/agent-jobs/claim",
            {"runner_id": _RUNNER_ID, "lease_seconds": 120, "run_id": run_id},
            internal=True,
        )
        raw_job = response.get("job")
        if raw_job is not None:
            job = _mapping(raw_job, "m3_probe_job_invalid")
            if job.get("run_id") != run_id:
                raise M3ProbeError("m3_probe_run_scope_violation")
            if expected_kind is not None and job.get("kind") != expected_kind:
                raise M3ProbeError("m3_probe_job_order_invalid")
            return job
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.2)


def _bootstrap_session(
    api: ControlApi,
    run_id: str,
    *,
    deadline: float,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    start = _claim(api, run_id, expected_kind="start_session", deadline=deadline)
    if start is None:
        raise M3ProbeError("m3_probe_start_session_timeout")
    start_id = _job_id(start)
    start_lease = _lease(start)
    # Resolve the sealed envelope before reservation, matching Pi Runner's
    # actual protocol order even though the probe never constructs a model.
    api.request("POST", f"/internal/agent-jobs/{start_id}/work", start_lease, internal=True)
    reserved = api.request(
        "POST",
        f"/internal/agent-jobs/{start_id}/session-reservation",
        start_lease,
        internal=True,
    )
    session = _mapping(reserved.get("session"), "m3_probe_session_invalid")
    session_id = session.get("id")
    if not isinstance(session_id, str):
        raise M3ProbeError("m3_probe_session_invalid")
    api.request(
        "POST",
        f"/internal/agent-jobs/{start_id}/session-activation",
        {**start_lease, "session_id": session_id},
        internal=True,
    )
    turn = _claim(api, run_id, expected_kind="run_turn", deadline=deadline)
    if turn is None:
        raise M3ProbeError("m3_probe_turn_timeout")
    turn_work = api.request(
        "POST",
        f"/internal/agent-jobs/{_job_id(turn)}/work",
        _lease(turn),
        internal=True,
    )
    work_session = _mapping(turn_work.get("session"), "m3_probe_session_invalid")
    if work_session.get("id") != session_id:
        raise M3ProbeError("m3_probe_session_mismatch")
    return session_id, turn, turn_work


def _tool_request(
    api: ControlApi,
    turn: Mapping[str, Any],
    session_id: str,
    *,
    call_id: str,
    tool_name: str,
    arguments: Mapping[str, object],
) -> dict[str, Any]:
    return api.request(
        "POST",
        f"/internal/agent-jobs/{_job_id(turn)}/tool-requests",
        {
            **_lease(turn),
            "session_id": session_id,
            "call": {
                "schema_version": 1,
                "tool_call_id": call_id,
                "idempotency_key": call_id,
                "tool_name": tool_name,
                "tool_version": "1.0.0",
                "arguments": dict(arguments),
            },
        },
        internal=True,
    )


def _accepted_pair(
    first: Mapping[str, Any],
    duplicate: Mapping[str, Any],
    *,
    tool_name: str,
) -> tuple[str, dict[str, Any]]:
    """Assert one side effect and one immutable cache hit without reading output text."""

    if (
        first.get("accepted") is not True
        or first.get("cached") is not False
        or first.get("tool_name") != tool_name
        or duplicate.get("accepted") is not True
        or duplicate.get("cached") is not True
        or duplicate.get("invocation_id") != first.get("invocation_id")
    ):
        raise M3ProbeError("m3_probe_idempotency_failed")
    first_artifact = _mapping(first.get("artifact"), "m3_probe_artifact_invalid")
    duplicate_artifact = _mapping(duplicate.get("artifact"), "m3_probe_artifact_invalid")
    digest = first_artifact.get("digest")
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or duplicate_artifact.get("digest") != digest
        or duplicate_artifact.get("artifact_id") != first_artifact.get("artifact_id")
    ):
        raise M3ProbeError("m3_probe_artifact_invalid")
    return digest, _mapping(first.get("result"), "m3_probe_result_invalid")


def _unknown_alias(aliases: frozenset[str]) -> str:
    for suffix in range(1_000):
        candidate = f"m3-probe-outside-{suffix}"
        if candidate not in aliases:
            return candidate
    raise M3ProbeError("m3_probe_alias_space_exhausted")


def _complete_turn(api: ControlApi, turn: Mapping[str, Any], result_ref: str) -> None:
    api.request(
        "POST",
        f"/internal/agent-jobs/{_job_id(turn)}/turn-completion",
        {**_lease(turn), "result_ref": result_ref},
        internal=True,
    )


def _cleanup(api: ControlApi, run_id: str, *, deadline: float) -> bool:
    """Cancel only the generated run, then acknowledge its non-target teardown jobs."""

    try:
        api.request("POST", f"/v1/runs/{run_id}/cancel", {})
        while time.monotonic() < deadline:
            job = _claim(api, run_id, expected_kind=None, deadline=time.monotonic())
            if job is None:
                run = api.request("GET", f"/v1/runs/{run_id}")
                sessions = api.request("GET", f"/v1/runs/{run_id}/agent-sessions")
                items = sessions.get("items")
                return (
                    run.get("status") == "cancelled"
                    and isinstance(items, list)
                    and all(
                        isinstance(item, dict) and item.get("state") == "disposed" for item in items
                    )
                )
            kind = job.get("kind")
            if kind not in {"abort", "dispose"}:
                return False
            api.request(
                "POST",
                f"/internal/agent-jobs/{_job_id(job)}/{kind}-completion",
                _lease(job),
                internal=True,
            )
    except M3ProbeError:
        return False
    return False


def run_probe(
    api: ControlApi,
    *,
    challenge_id: str,
    source_path: str,
    target_alias: str | None,
    http_path: str,
    wait_seconds: int,
    progress: Callable[[str], None] | None = None,
) -> ProbeReport:
    """Drive the reviewed M3 boundaries and return only safe proof metadata."""

    emit = progress or (lambda _message: None)
    challenge = api.request("GET", f"/v1/challenges/{challenge_id}")
    mode, budget, _tools, aliases = _manifest_configuration(
        challenge, require_http=target_alias is not None
    )
    if target_alias is not None and target_alias not in aliases:
        raise M3ProbeError("m3_probe_target_alias_not_declared")

    run = api.request(
        "POST",
        "/v1/runs",
        {
            "challenge_id": challenge_id,
            "mode": mode,
            "provider": "m3-operator-probe",
            "budget": budget,
        },
        idempotency_key=f"m3-probe-{secrets.token_hex(16)}",
    )
    run_id = run.get("id")
    if not isinstance(run_id, str) or _SAFE_IDENTIFIER.fullmatch(run_id) is None:
        raise M3ProbeError("m3_probe_run_invalid")
    emit(f"diagnostic run created: {run_id}")
    deadline = time.monotonic() + wait_seconds
    cleanup_complete = False
    source_digest = ""
    http_digest: str | None = None
    http_status: int | None = None
    denial_code: str | None = None
    primary_error: M3ProbeError | None = None
    try:
        # Preflight changes the run to running and queues the first sealed Pi
        # session. Poll public state; never inspect the database directly.
        while True:
            state = api.request("GET", f"/v1/runs/{run_id}").get("status")
            if state == "running":
                break
            if state in {"failed", "cancelled", "budget_exhausted", "solved"}:
                raise M3ProbeError("m3_probe_preflight_failed")
            if time.monotonic() >= deadline:
                raise M3ProbeError("m3_probe_preflight_timeout")
            time.sleep(0.2)
        emit("deterministic preflight passed")

        master_session, master_turn, master_work = _bootstrap_session(
            api, run_id, deadline=deadline
        )
        del master_session
        context = _mapping(master_work.get("context_manifest"), "m3_probe_context_invalid")
        evidence = context.get("evidence_refs")
        if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], dict):
            raise M3ProbeError("m3_probe_context_invalid")
        evidence_id = evidence[0].get("observation_id")
        if not isinstance(evidence_id, str):
            raise M3ProbeError("m3_probe_context_invalid")
        api.request(
            "POST",
            f"/internal/agent-jobs/{_job_id(master_turn)}/task-delegations",
            {
                **_lease(master_turn),
                "delegation": {
                    "tool_call_id": "call-m3-probe-delegate",
                    "role": "falsifier",
                    "technique_id": "general.review",
                    "objective": "Validate the reviewed source and target boundaries only.",
                    "evidence_ids": [evidence_id],
                },
            },
            internal=True,
        )
        _complete_turn(api, master_turn, "agent:delegated")
        emit("bounded worker delegated through the kernel")

        session_id, worker_turn, _worker_work = _bootstrap_session(api, run_id, deadline=deadline)
        source_first = _tool_request(
            api,
            worker_turn,
            session_id,
            call_id="call-m3-probe-source-read",
            tool_name="source.read",
            arguments={"path": source_path, "max_output_bytes": 4_096},
        )
        source_duplicate = _tool_request(
            api,
            worker_turn,
            session_id,
            call_id="call-m3-probe-source-read",
            tool_name="source.read",
            arguments={"path": source_path, "max_output_bytes": 4_096},
        )
        source_digest, _source_result = _accepted_pair(
            source_first, source_duplicate, tool_name="source.read"
        )
        emit("source read and immutable cache replay passed")

        if target_alias is not None:
            http_first = _tool_request(
                api,
                worker_turn,
                session_id,
                call_id="call-m3-probe-http",
                tool_name="http.request",
                arguments={
                    "target_alias": target_alias,
                    "method": "GET",
                    "path": http_path,
                    "max_response_bytes": 16_384,
                },
            )
            http_duplicate = _tool_request(
                api,
                worker_turn,
                session_id,
                call_id="call-m3-probe-http",
                tool_name="http.request",
                arguments={
                    "target_alias": target_alias,
                    "method": "GET",
                    "path": http_path,
                    "max_response_bytes": 16_384,
                },
            )
            http_digest, http_result = _accepted_pair(
                http_first, http_duplicate, tool_name="http.request"
            )
            raw_status = http_result.get("status")
            if not isinstance(raw_status, int) or isinstance(raw_status, bool):
                raise M3ProbeError("m3_probe_http_result_invalid")
            http_status = raw_status
            emit("authorized HTTP observation and immutable cache replay passed")

            denied = _tool_request(
                api,
                worker_turn,
                session_id,
                call_id="call-m3-probe-denied-alias",
                tool_name="http.request",
                arguments={"target_alias": _unknown_alias(aliases), "method": "GET", "path": "/"},
            )
            raw_code = denied.get("code")
            if (
                denied.get("accepted") is not False
                or not isinstance(raw_code, str)
                or _SAFE_ERROR_CODE.fullmatch(raw_code) is None
            ):
                raise M3ProbeError("m3_probe_out_of_scope_not_denied")
            denial_code = raw_code
            emit("undeclared target alias was denied before dispatch")

        _complete_turn(api, worker_turn, "agent:inconclusive")
    except M3ProbeError as exc:
        primary_error = exc
    finally:
        cleanup_complete = _cleanup(api, run_id, deadline=max(deadline, time.monotonic() + 15))
    if primary_error is not None:
        raise primary_error
    if not cleanup_complete:
        raise M3ProbeError("m3_probe_cleanup_incomplete")
    return ProbeReport(
        run_id=run_id,
        source_digest=source_digest,
        http_digest=http_digest,
        http_status=http_status,
        denial_code=denial_code,
        cleanup_complete=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point intended for ``docker compose exec -T api`` only."""

    parser = argparse.ArgumentParser(
        description="Validate one authorized challenge through the M3 runtime boundaries."
    )
    parser.add_argument("--challenge-id", required=True, type=_challenge_id)
    parser.add_argument("--source-path", required=True, type=_source_path)
    parser.add_argument("--target-alias", type=_target_alias)
    parser.add_argument("--http-path", default="/", type=_http_path)
    parser.add_argument("--wait-seconds", default=90, type=_wait_seconds)
    args = parser.parse_args(argv)
    token = os.environ.get("CTFMESH_INTERNAL_RUNNER_TOKEN", "")
    try:
        report = run_probe(
            ControlApi(token),
            challenge_id=args.challenge_id,
            source_path=args.source_path,
            target_alias=args.target_alias,
            http_path=args.http_path,
            wait_seconds=args.wait_seconds,
            progress=lambda message: print(f"[m3-probe] {message}", flush=True),
        )
    except M3ProbeError as exc:
        print(f"M3 operator probe failed: {exc.code}.")
        return 1
    print(f"M3 source proof passed: sha256:{report.source_digest}.")
    if report.http_digest is not None:
        print(
            "M3 target proof passed: "
            f"status={report.http_status}, sha256:{report.http_digest}, "
            f"deny={report.denial_code}."
        )
    else:
        print("M3 source-only proof passed; target E2E was not requested.")
    print(f"Diagnostic run {report.run_id} was cancelled and its sessions were disposed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
