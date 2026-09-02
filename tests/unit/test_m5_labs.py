"""Behavioral checks for the three reset-driven M5 Web labs."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest
from ctfmesh_domain import ExploitPlanDraftV1
from ctfmesh_labs.server import make_handler
from ctfmesh_verifier.lab_controller import (
    ControllerConfig,
    LabControllerState,
    verify_controller_signature,
)
from ctfmesh_verifier.m5_replay import (
    ControllerProof,
    ControllerReset,
    M5ReplayVerifier,
    M5VerificationWork,
    TrustedLab,
    controller_proof_payload_from_replay,
)

_DIGESTS = {
    "web-path-traversal": "aa271474cd131f616b8363275f3fbb5fcea669d658f5f74c1e55476dd53d9a58",
    "web-authz-boundary": "59b5b0ad6c6154bdc743cbc197e8b4f0176a6abe466f1dda6cf476c55365a464",
    "web-sqli-basic": "11fcc90d8371fe8435b51756ab0659a18310c1faeebeb80dc6a72b8d276f0930",
}
_PRIVATE_KEY = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_MANIFEST_DIGEST = "a" * 64
_FLAG_PATTERN = r"regex:CTF\{[A-Za-z0-9_-]{1,128}\}"


@contextmanager
def _lab_server(lab_id: str, flag_dir: Path) -> Iterator[str]:
    """Serve one target exactly as its isolated Docker entrypoint would."""

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(lab_id=lab_id, flag_dir=flag_dir, image_digest=_DIGESTS[lab_id]),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _controller(root: Path) -> LabControllerState:
    return LabControllerState(
        ControllerConfig(
            root=root,
            token="controller-token-fixture-1234",
            signing_key=_PRIVATE_KEY,
        )
    )


class _ReplayController:
    """Adapt the synchronous local controller state to the async replay port.

    The adapter deliberately transfers only reset metadata and opaque proof
    fields. It makes the real target/controller/replay composition testable
    without making a test-only route that can return a raw flag.
    """

    def __init__(self, state: LabControllerState) -> None:
        self._state = state

    async def reset(self, lab_id: str) -> ControllerReset:
        reset = await asyncio.to_thread(self._state.reset, lab_id)
        return ControllerReset(
            lab_id=reset.lab_id,
            generation=reset.generation,
            reset_id=reset.reset_id,
        )

    async def verify(self, *, reset: ControllerReset, candidate: str) -> ControllerProof | None:
        proof = await asyncio.to_thread(
            self._state.verify,
            lab_id=reset.lab_id,
            generation=reset.generation,
            candidate=candidate,
        )
        if proof is None:
            return None
        serialized = proof.as_dict()
        issued_at = serialized["issued_at"]
        assert isinstance(issued_at, str)
        return ControllerProof(
            lab_id=proof.lab_id,
            generation=proof.generation,
            reset_id=proof.reset_id,
            proof_id=proof.proof_id,
            flag_sha256=proof.flag_sha256,
            issued_at=issued_at,
            signature=proof.signature,
        )


def _json_request(
    url: str, *, headers: dict[str, str] | None = None
) -> tuple[dict[str, object], dict[str, str]]:
    request = Request(url, headers=headers or {})  # noqa: S310 - loopback fixture origin only.
    with urlopen(request, timeout=2) as response:  # noqa: S310 - loopback fixture origin only.
        return json.loads(response.read()), {
            key.lower(): value for key, value in response.headers.items()
        }


@pytest.mark.parametrize(
    ("lab_id", "path", "headers"),
    [
        (
            "web-path-traversal",
            f"/download?{urlencode({'file': '../../run/ctfmesh/flag/flag'})}",
            {},
        ),
        ("web-authz-boundary", "/api/records/2", {"X-CTFMesh-User": "analyst"}),
        (
            "web-sqli-basic",
            f"/search?{urlencode({'name': "' or '1'='1"})}",
            {},
        ),
    ],
)
def test_each_m5_lab_reads_only_its_current_controller_flag(
    tmp_path: Path,
    lab_id: str,
    path: str,
    headers: dict[str, str],
) -> None:
    """All lab variants expose the per-reset flag only through their intended CTF path."""

    controller = _controller(tmp_path / "labs")
    reset = controller.reset(lab_id)
    flag_path = tmp_path / "labs" / lab_id / "flag"
    expected_flag = flag_path.read_text(encoding="utf-8").strip()
    with _lab_server(lab_id, flag_path.parent) as origin:
        health, health_headers = _json_request(f"{origin}/health")
        payload, response_headers = _json_request(f"{origin}{path}", headers=headers)

    assert health == {"status": "ok", "lab": lab_id}
    assert health_headers["x-ctfmesh-target-digest"] == _DIGESTS[lab_id]
    assert response_headers["x-ctfmesh-generation"] == str(reset.generation)
    assert expected_flag in json.dumps(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("lab_id", "technique_id", "path", "query", "headers"),
    [
        (
            "web-path-traversal",
            "web.path_traversal",
            "/download",
            {"file": "../../run/ctfmesh/flag/flag"},
            {},
        ),
        (
            "web-authz-boundary",
            "web.authz_boundary",
            "/api/records/2",
            {},
            {"x-ctfmesh-user": "analyst"},
        ),
        (
            "web-sqli-basic",
            "web.sqli_basic",
            "/search",
            {"name": "' or '1'='1"},
            {},
        ),
    ],
)
async def test_each_m5_lab_replays_a_canonical_safe_plan_twice(
    tmp_path: Path,
    lab_id: str,
    technique_id: str,
    path: str,
    query: dict[str, str],
    headers: dict[str, str],
) -> None:
    """Exercise each reviewed technique through target, reset, and proof ports.

    This guards the production seam that a contract-approved plan must also
    work against its code-owned target. In particular the authz fixture uses
    the required lowercase header spelling, matching the strict plan schema.
    """

    state = _controller(tmp_path / "labs")
    flag_dir = tmp_path / "labs" / lab_id
    plan = ExploitPlanDraftV1.model_validate(
        {
            "schema_version": "ctfmesh.exploit-plan.v1",
            "challenge_digest": _MANIFEST_DIGEST,
            "technique_id": technique_id,
            "steps": [
                {
                    "op": "http.request",
                    "method": "GET",
                    "path": path,
                    "query": query,
                    "headers": headers,
                    "capture": {"flag": _FLAG_PATTERN},
                }
            ],
            "assertions": ["capture.flag exists"],
            "evidence_refs": ["obs_m5_lab"],
        }
    ).issue()
    with _lab_server(lab_id, flag_dir) as origin:
        verifier = M5ReplayVerifier(
            _ReplayController(state),
            labs={
                lab_id: TrustedLab(
                    id=lab_id,
                    origin=origin,
                    target_image_digest=_DIGESTS[lab_id],
                )
            },
        )
        completion = await verifier.verify(
            M5VerificationWork(
                run_id="run_m5_lab",
                candidate_id=f"candidate_{lab_id}",
                manifest_digest=_MANIFEST_DIGEST,
                plan_artifact_digest=plan.artifact_digest(),
                evidence_refs=("obs_m5_lab",),
            ),
            plan.canonical_bytes(),
        )

    assert completion.verified is True
    assert len(completion.replay_results) == 2
    assert len({attempt.reset_id for attempt in completion.replay_results}) == 2
    assert all(
        verify_controller_signature(
            controller_proof_payload_from_replay(attempt), public_key=_PUBLIC_KEY
        )
        for attempt in completion.replay_results
    )
    assert "CTF{" not in completion.model_dump_json()
