"""M6.a remote replay proof tests without opening an external socket."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from ctfmesh_domain import ExploitPlanV1
from ctfmesh_verifier import RemoteReplayVerifier, RemoteVerificationWork
from ctfmesh_verifier import remote_replay as remote_module
from ctfmesh_verifier.m5_replay import VerificationProcessingError


def _plan() -> ExploitPlanV1:
    return ExploitPlanV1.issue(
        challenge_digest="a" * 64,
        technique_id="web.path_traversal",
        variables={},
        steps=(
            {
                "op": "http.request",
                "path": "/flag",
                "capture": {"flag": r"regex:CTF\{[A-Za-z0-9_:-]+\}"},
            },
        ),
        assertions=("capture.flag exists",),
        evidence_refs=("observation-remote-proof",),
    )


def _work(plan: ExploitPlanV1) -> RemoteVerificationWork:
    return RemoteVerificationWork(
        run_id="run-remote-proof",
        candidate_id="candidate-remote-proof",
        manifest_digest=plan.challenge_digest,
        plan_artifact_digest=plan.artifact_digest(),
        evidence_refs=tuple(plan.evidence_refs),
        origin="https://challenge.example:443",
    )


@contextmanager
def _local_exact_origin_target() -> Iterator[tuple[str, list[str]]]:
    """Run a local transport fixture while the resolver remains monkeypatched."""

    cookie_headers: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *_args: object) -> None:
            del format, _args

        def do_GET(self) -> None:  # noqa: N802 - stdlib server hook.
            if self.path == "/start":
                cookie_headers.append(self.headers.get("Cookie", ""))
                payload = b"ready"
                self.send_response(HTTPStatus.OK)
                self.send_header("Set-Cookie", "remote-attempt=clean; Path=/")
            elif self.path == "/flag" and "remote-attempt=clean" in self.headers.get("Cookie", ""):
                payload = b"CTF{pinned_remote_replay}"
                self.send_response(HTTPStatus.OK)
            else:
                payload = b"not found"
                self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://challenge.example:{server.server_port}", cookie_headers
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.asyncio
async def test_remote_replay_requires_matching_fresh_candidates_and_keeps_raw_flag_ephemeral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two target observations can solve, but neither proof nor record has the flag."""

    plan = _plan()
    calls = 0

    async def replay_once(
        _self: RemoteReplayVerifier,
        _origin: str,
        _plan: ExploitPlanV1,
    ) -> remote_module._RemoteTargetOutcome:
        nonlocal calls
        calls += 1
        return remote_module._RemoteTargetOutcome(
            candidate="CTF{remote_verified}",
            response_sha256=hashlib.sha256(f"response-{calls}".encode()).hexdigest(),
            failure_code=None,
        )

    monkeypatch.setattr(RemoteReplayVerifier, "_replay_once", replay_once)
    outcome = await RemoteReplayVerifier().verify(_work(plan), plan.canonical_bytes())

    assert calls == 2
    assert outcome.completion.verified is True
    assert outcome.candidate == "CTF{remote_verified}"
    serialized = outcome.completion.model_dump_json()
    assert "CTF{remote_verified}" not in serialized
    assert outcome.completion.proof is not None
    assert all(item.remote_origin_sha256 for item in outcome.completion.replay_results)
    assert all(item.controller_signature is None for item in outcome.completion.replay_results)


@pytest.mark.asyncio
async def test_remote_replay_rejects_different_candidates_without_returning_either(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A remotely rotating value cannot become a one-time reveal lease."""

    plan = _plan()
    candidates = iter(("CTF{first}", "CTF{second}"))

    async def replay_once(
        _self: RemoteReplayVerifier,
        _origin: str,
        _plan: ExploitPlanV1,
    ) -> remote_module._RemoteTargetOutcome:
        candidate = next(candidates)
        return remote_module._RemoteTargetOutcome(
            candidate=candidate,
            response_sha256=hashlib.sha256(candidate.encode()).hexdigest(),
            failure_code=None,
        )

    monkeypatch.setattr(RemoteReplayVerifier, "_replay_once", replay_once)
    outcome = await RemoteReplayVerifier().verify(_work(plan), plan.canonical_bytes())

    assert outcome.completion.verified is False
    assert outcome.completion.failure_code == "remote_replay_failed"
    assert outcome.candidate is None


@pytest.mark.asyncio
async def test_remote_replay_pins_the_resolved_address_and_resets_each_cookie_jar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real HTTP adapter preserves Host/cookies without a direct DNS connection."""

    plan = ExploitPlanV1.issue(
        challenge_digest="a" * 64,
        technique_id="web.path_traversal",
        variables={},
        steps=(
            {"op": "http.request", "path": "/start"},
            {
                "op": "http.request",
                "path": "/flag",
                "capture": {"flag": r"regex:CTF\{[A-Za-z0-9_:-]+\}"},
            },
        ),
        assertions=("capture.flag exists",),
        evidence_refs=("observation-remote-proof",),
    )
    with _local_exact_origin_target() as (origin, cookie_headers):

        async def resolved(_host: str, _port: int) -> tuple[str, ...]:
            # The production resolver rejects loopback. This fixture replaces
            # it solely to assert the adapter connects to its pinned result.
            return ("127.0.0.1",)

        monkeypatch.setattr(remote_module, "_resolve_public_addresses", resolved)
        work = RemoteVerificationWork(
            run_id="run-remote-transport",
            candidate_id="candidate-remote-transport",
            manifest_digest=plan.challenge_digest,
            plan_artifact_digest=plan.artifact_digest(),
            evidence_refs=tuple(plan.evidence_refs),
            origin=origin,
        )
        outcome = await RemoteReplayVerifier().verify(work, plan.canonical_bytes())

    assert outcome.completion.verified is True
    assert outcome.candidate == "CTF{pinned_remote_replay}"
    assert cookie_headers == ["", ""]


def test_remote_work_rejects_noncanonical_or_extra_target_data() -> None:
    """The remote worker cannot be handed an arbitrary target request surface."""

    plan = _plan()
    wire = {
        "job": {},
        "candidate": {
            "id": "candidate-remote-proof",
            "run_id": "run-remote-proof",
            "plan_artifact_digest": plan.artifact_digest(),
            "evidence_refs": ["observation-remote-proof"],
        },
        "manifest_digest": plan.challenge_digest,
        "replay_target": {
            "kind": "exact_remote_origin_v1",
            "origin": "https://challenge.example:443/other",
        },
    }

    with pytest.raises(VerificationProcessingError, match="remote_replay_origin_invalid"):
        remote_module.remote_work_from_wire(wire)
