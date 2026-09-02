"""M5 declarative plan, replay, and controller-boundary regression tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from ctfmesh_domain import ExploitPlanDraftV1, VerificationReplayAttemptV1
from ctfmesh_verifier.m5_replay import (
    ControllerProof,
    ControllerReset,
    M5ReplayVerifier,
    M5VerificationWork,
    TrustedLab,
    VerificationProcessingError,
    work_from_wire,
)
from pydantic import ValidationError


def _draft(*, path: str = "/download") -> ExploitPlanDraftV1:
    return ExploitPlanDraftV1.model_validate(
        {
            "schema_version": "ctfmesh.exploit-plan.v1",
            "challenge_digest": "a" * 64,
            "technique_id": "web.path_traversal",
            "steps": [
                {
                    "op": "http.request",
                    "method": "GET",
                    "path": path,
                    "query": {"file": "../../run/ctfmesh/flag/flag"},
                    "capture": {"flag": r"regex:CTF\{[A-Za-z0-9_-]{1,128}\}"},
                }
            ],
            "assertions": ["capture.flag exists"],
            "evidence_refs": ["obs_m5_fixture"],
        }
    )


def _work(plan_artifact_digest: str) -> M5VerificationWork:
    return M5VerificationWork(
        run_id="run_m5_fixture",
        candidate_id="candidate_m5_fixture",
        manifest_digest="a" * 64,
        plan_artifact_digest=plan_artifact_digest,
        evidence_refs=("obs_m5_fixture",),
    )


def test_exploit_plan_is_kernel_digest_issued_and_rejects_execution_escape_hatches() -> None:
    """The Python contract allows only target-relative read-only replay steps."""

    issued = _draft().issue()
    decoded = json.loads(issued.canonical_bytes())
    assert decoded["digest"] == issued.digest
    assert issued.artifact_digest() == hashlib.sha256(issued.canonical_bytes()).hexdigest()

    bad_documents: list[dict[str, Any]] = [
        {
            "schema_version": "ctfmesh.exploit-plan.v1",
            "challenge_digest": "a" * 64,
            "technique_id": "web.path_traversal",
            "steps": [
                {
                    "op": "http.request",
                    "path": "/download",
                    "url": "https://outside.example/flag",
                    "capture": {"flag": r"regex:CTF\{[^}]+\}"},
                }
            ],
            "assertions": ["capture.flag exists"],
            "evidence_refs": ["obs_m5_fixture"],
        },
        {
            "schema_version": "ctfmesh.exploit-plan.v1",
            "challenge_digest": "a" * 64,
            "technique_id": "web.path_traversal",
            "steps": [
                {
                    "op": "shell.exec",
                    "path": "/download",
                    "capture": {"flag": r"regex:CTF\{[^}]+\}"},
                }
            ],
            "assertions": ["capture.flag exists"],
            "evidence_refs": ["obs_m5_fixture"],
        },
        {
            "schema_version": "ctfmesh.exploit-plan.v1",
            "challenge_digest": "a" * 64,
            "technique_id": "web.path_traversal",
            "steps": [
                {
                    "op": "http.request",
                    "path": "https://outside.example/flag",
                    "capture": {"flag": r"regex:CTF\{[^}]+\}"},
                }
            ],
            "assertions": ["capture.flag exists"],
            "evidence_refs": ["obs_m5_fixture"],
        },
        {
            "schema_version": "ctfmesh.exploit-plan.v1",
            "challenge_digest": "a" * 64,
            "technique_id": "web.path_traversal",
            "steps": [
                {
                    "op": "http.request",
                    "path": "/download",
                    "query": {"file": "${not_declared}"},
                    "capture": {"flag": r"regex:CTF\{[^}]+\}"},
                }
            ],
            "assertions": ["capture.flag exists"],
            "evidence_refs": ["obs_m5_fixture"],
        },
    ]
    for document in bad_documents:
        with pytest.raises(ValidationError):
            ExploitPlanDraftV1.model_validate(document)


def test_verifier_work_has_only_the_four_declared_candidate_inputs() -> None:
    """Target URL, transcript, raw candidate, and lab ID never cross this boundary."""

    value = {
        "job": {"opaque": "transport metadata"},
        "manifest_digest": "a" * 64,
        "candidate": {
            "id": "candidate_m5_fixture",
            "run_id": "run_m5_fixture",
            "plan_artifact_digest": "b" * 64,
            "evidence_refs": ["obs_m5_fixture"],
        },
    }
    parsed = work_from_wire(value)
    assert parsed.plan_artifact_digest == "b" * 64
    assert "target" not in json.dumps(parsed.__dict__ if hasattr(parsed, "__dict__") else value)

    value["candidate"] = {**value["candidate"], "target_url": "http://not-allowed"}
    with pytest.raises(VerificationProcessingError, match="verification_work_invalid"):
        work_from_wire(value)


def test_successful_replay_requires_every_controller_signed_field() -> None:
    """A standalone persisted signature needs its signed lab/timestamp context."""

    valid = {
        "attempt": 1,
        "reset_id": "reset_m5_fixture",
        "target_generation": 1,
        "passed": True,
        "started_from_clean_reset": True,
        "flag_sha256": "b" * 64,
        "controller_lab_id": "web-path-traversal",
        "controller_issued_at": "2026-08-29T00:00:01Z",
        "controller_proof_id": "proof_m5_fixture",
        "controller_signature": "c" * 128,
    }
    assert VerificationReplayAttemptV1.model_validate(valid).passed is True
    for malformed in (
        {key: value for key, value in valid.items() if key != "controller_lab_id"},
        {key: value for key, value in valid.items() if key != "controller_issued_at"},
        {**valid, "controller_issued_at": "2026-08-29T00:00:01+00:00"},
    ):
        with pytest.raises(ValidationError):
            VerificationReplayAttemptV1.model_validate(malformed)


class _FakeController:
    """Controller fake owns ephemeral flags but returns only proof metadata."""

    def __init__(self) -> None:
        self.generation = 0
        self.flag = ""

    async def reset(self, lab_id: str) -> ControllerReset:
        self.generation += 1
        self.flag = f"CTF{{fresh_generation_{self.generation}}}"
        return ControllerReset(
            lab_id=lab_id, generation=self.generation, reset_id=f"reset_{self.generation}"
        )

    async def verify(self, *, reset: ControllerReset, candidate: str) -> ControllerProof | None:
        if candidate != self.flag or reset.generation != self.generation:
            return None
        return ControllerProof(
            lab_id=reset.lab_id,
            generation=reset.generation,
            reset_id=reset.reset_id,
            proof_id=f"proof_{reset.generation}",
            flag_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
            issued_at=f"2026-08-29T00:00:0{reset.generation}Z",
            signature="c" * 128,
        )


class _HangingController:
    """A chaos fixture whose capability never resolves unless cancelled."""

    async def reset(self, lab_id: str) -> ControllerReset:
        del lab_id
        await asyncio.Event().wait()
        raise AssertionError("the controller timeout must cancel this coroutine")

    async def verify(self, *, reset: ControllerReset, candidate: str) -> ControllerProof | None:
        del reset, candidate
        await asyncio.Event().wait()
        raise AssertionError("the controller timeout must cancel this coroutine")


@contextmanager
def _fresh_target(controller: _FakeController) -> Iterator[tuple[str, list[str]]]:
    """Run a minimal target that proves jars are fresh between replay attempts."""

    seen_health_cookies: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *_args: object) -> None:
            del format, _args
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            parsed = urlsplit(self.path)
            generation = str(controller.generation)
            if parsed.path == "/health":
                seen_health_cookies.append(self.headers.get("Cookie", ""))
                payload = b'{"status":"ok"}'
                self.send_response(HTTPStatus.OK.value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Set-Cookie", f"attempt={generation}; Path=/")
                self.send_header("X-CTFMesh-Generation", generation)
                self.send_header("X-CTFMesh-Target-Digest", "d" * 64)
                self.end_headers()
                self.wfile.write(payload)
                return
            query = parse_qs(parsed.query)
            has_current_cookie = self.headers.get("Cookie") == f"attempt={generation}"
            if (
                parsed.path == "/download"
                and query.get("file") == ["../../run/ctfmesh/flag/flag"]
                and has_current_cookie
            ):
                payload = json.dumps({"content": controller.flag}).encode("utf-8")
                self.send_response(HTTPStatus.OK.value)
            else:
                payload = b'{"error":"not_found"}'
                self.send_response(HTTPStatus.NOT_FOUND.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-CTFMesh-Generation", generation)
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen_health_cookies
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.mark.asyncio
async def test_m5_replay_requires_two_fresh_resets_and_persists_no_raw_flag() -> None:
    """A successful candidate gets two independently reset, clean-jar proofs."""

    controller = _FakeController()
    plan = _draft().issue()
    with _fresh_target(controller) as (origin, health_cookies):
        verifier = M5ReplayVerifier(
            controller,
            labs={
                "web-path-traversal": TrustedLab(
                    id="web-path-traversal",
                    origin=origin,
                    target_image_digest="d" * 64,
                )
            },
        )
        completion = await verifier.verify(_work(plan.artifact_digest()), plan.canonical_bytes())

    assert completion.verified is True
    assert completion.proof is not None
    assert [attempt.reset_id for attempt in completion.replay_results] == ["reset_1", "reset_2"]
    assert [attempt.controller_lab_id for attempt in completion.replay_results] == [
        "web-path-traversal",
        "web-path-traversal",
    ]
    assert [attempt.controller_issued_at for attempt in completion.replay_results] == [
        "2026-08-29T00:00:01Z",
        "2026-08-29T00:00:02Z",
    ]
    assert all(
        attempt.passed and attempt.started_from_clean_reset for attempt in completion.replay_results
    )
    assert health_cookies == ["", ""]
    assert "fresh_generation" not in completion.model_dump_json()
    assert "CTF{" not in completion.model_dump_json()


@pytest.mark.asyncio
async def test_m5_replay_treats_target_unavailability_as_controlled_failure() -> None:
    """An unavailable target must not turn an otherwise valid candidate into a rejection."""

    controller = _FakeController()
    plan = _draft().issue()
    verifier = M5ReplayVerifier(
        controller,
        labs={
            "web-path-traversal": TrustedLab(
                id="web-path-traversal",
                origin="http://127.0.0.1:1",
                target_image_digest="d" * 64,
            )
        },
        request_timeout_seconds=0.1,
    )
    with pytest.raises(VerificationProcessingError, match="lab_target_unavailable"):
        await verifier.verify(_work(plan.artifact_digest()), plan.canonical_bytes())


@pytest.mark.asyncio
async def test_m5_replay_fails_closed_when_controller_reset_times_out() -> None:
    """A hung verifier dependency cannot produce a replay receipt or `SOLVED`."""

    plan = _draft().issue()
    verifier = M5ReplayVerifier(
        _HangingController(),
        controller_timeout_seconds=0.1,
        labs={
            "web-path-traversal": TrustedLab(
                id="web-path-traversal",
                origin="http://127.0.0.1:1",
                target_image_digest="d" * 64,
            )
        },
    )

    with pytest.raises(VerificationProcessingError, match="lab_controller_timeout"):
        await verifier.verify(_work(plan.artifact_digest()), plan.canonical_bytes())
