"""Local M5 controller tests: random reset state and opaque signed proof only."""

from __future__ import annotations

import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from ctfmesh_domain import VerificationReplayAttemptV1
from ctfmesh_verifier.lab_controller import (
    ControllerConfig,
    LabControllerState,
    make_controller_handler,
    verify_controller_signature,
)
from ctfmesh_verifier.m5_replay import controller_proof_payload_from_replay

_PRIVATE_KEY = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def _config(root: Path) -> ControllerConfig:
    return ControllerConfig(
        root=root,
        token="controller-token-fixture-1234",
        signing_key=_PRIVATE_KEY,
    )


def test_controller_rotates_per_reset_and_never_returns_the_flag_in_public_metadata(
    tmp_path: Path,
) -> None:
    """Only target volumes contain the raw flag; reset/proof APIs stay opaque."""

    state = LabControllerState(_config(tmp_path / "labs"))
    first = state.reset("web-path-traversal")
    first_flag = (tmp_path / "labs" / "web-path-traversal" / "flag").read_text().strip()
    second = state.reset("web-path-traversal")
    second_flag = (tmp_path / "labs" / "web-path-traversal" / "flag").read_text().strip()

    assert first.generation == 1
    assert second.generation == 2
    assert first_flag != second_flag
    assert first_flag not in str(first.as_dict())
    assert second_flag not in str(second.as_dict())
    assert (
        state.verify(lab_id="web-path-traversal", generation=first.generation, candidate=first_flag)
        is None
    )

    proof = state.verify(
        lab_id="web-path-traversal", generation=second.generation, candidate=second_flag
    )
    assert proof is not None
    serialized = proof.as_dict()
    assert second_flag not in str(serialized)
    assert verify_controller_signature(serialized, public_key=_PUBLIC_KEY)
    assert not verify_controller_signature(
        {**serialized, "generation": second.generation + 1}, public_key=_PUBLIC_KEY
    )
    assert not verify_controller_signature(serialized, public_key=b"x" * 32)

    # Round-trip only non-secret signature context as a replay record. This is
    # the data that ends up in the immutable verification proof; it must remain
    # sufficient to validate the controller signature after the HTTP response
    # and raw candidate are gone.
    replay = VerificationReplayAttemptV1(
        attempt=1,
        reset_id=proof.reset_id,
        target_generation=proof.generation,
        passed=True,
        started_from_clean_reset=True,
        flag_sha256=proof.flag_sha256,
        controller_lab_id=proof.lab_id,
        controller_issued_at=serialized["issued_at"],
        controller_proof_id=proof.proof_id,
        controller_signature=proof.signature,
    )
    restored = VerificationReplayAttemptV1.model_validate_json(replay.model_dump_json())
    reconstructed = controller_proof_payload_from_replay(restored)
    assert second_flag not in str(reconstructed)
    assert verify_controller_signature(reconstructed, public_key=_PUBLIC_KEY)


def test_controller_http_rejects_reset_without_its_private_service_token(tmp_path: Path) -> None:
    """A caller without the controller credential cannot rotate a lab flag."""

    state = LabControllerState(_config(tmp_path / "labs"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_controller_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=1)
    try:
        connection.request(
            "POST",
            "/v1/labs/web-path-traversal/reset",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 401
        assert response.read() == b'{"code":"unauthorized"}'
        assert not (tmp_path / "labs" / "web-path-traversal" / "flag").exists()
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
