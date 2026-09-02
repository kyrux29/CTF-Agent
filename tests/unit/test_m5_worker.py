"""Fail-closed configuration checks for the isolated M5 verifier worker."""

from __future__ import annotations

import asyncio

import ctfmesh_verifier.worker as verifier_worker
import pytest
from ctfmesh_verifier.worker import (
    VerifierWorkerConfigurationError,
    load_verifier_worker_config,
)

_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def _environment() -> dict[str, str]:
    return {
        "CTFMESH_VERIFIER_ID": "independent-verifier",
        "CTFMESH_INTERNAL_VERIFIER_TOKEN": "verifier-token-fixture-1234",
        "CTFMESH_LAB_CONTROLLER_TOKEN": "controller-token-fixture-1234",
        "CTFMESH_LAB_CONTROLLER_PUBLIC_KEY": _PUBLIC_KEY,
        "CTFMESH_VERIFIER_PLAN_ARTIFACT_ROOT": "/data/artifacts/candidate-plans",
        "CTFMESH_VERIFIER_POLL_MS": "750",
        "CTFMESH_VERIFIER_REQUEST_TIMEOUT_MS": "5000",
        "CTFMESH_VERIFIER_CONTROL_BASE_URL": "http://api:8000",
    }


def test_verifier_worker_requires_fixed_control_origin_and_hides_credentials() -> None:
    config = load_verifier_worker_config(_environment())
    rendered = repr(config)
    assert "verifier-token-fixture-1234" not in rendered
    assert "controller-token-fixture-1234" not in rendered
    assert _PUBLIC_KEY not in rendered

    bad = _environment()
    bad["CTFMESH_VERIFIER_CONTROL_BASE_URL"] = "http://operator-controlled.example"
    with pytest.raises(VerifierWorkerConfigurationError, match="control_origin_not_allowed"):
        load_verifier_worker_config(bad)

    missing_public_key = _environment()
    missing_public_key.pop("CTFMESH_LAB_CONTROLLER_PUBLIC_KEY")
    with pytest.raises(VerifierWorkerConfigurationError, match="controller_public_key_invalid"):
        load_verifier_worker_config(missing_public_key)

    remote_only = _environment()
    remote_only.pop("CTFMESH_LAB_CONTROLLER_TOKEN")
    remote_only.pop("CTFMESH_LAB_CONTROLLER_PUBLIC_KEY")
    remote_only["CTFMESH_VERIFIER_ID"] = "remote-verifier"
    remote_only["CTFMESH_VERIFIER_REMOTE_REPLAY_ENABLED"] = "true"
    remote_config = load_verifier_worker_config(remote_only)
    assert remote_config.remote_replay_enabled is True
    assert remote_config.controller_token is None
    assert remote_config.controller_proof_public_key is None


@pytest.mark.asyncio
async def test_worker_aligns_outer_controller_deadline_with_transport_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A custom controller implementation cannot wait beyond worker configuration."""

    captured: dict[str, object] = {}

    class CaptureReplay:
        def __init__(self, _controller: object, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(verifier_worker, "M5ReplayVerifier", CaptureReplay)
    stop = asyncio.Event()
    stop.set()
    config = load_verifier_worker_config(_environment())

    await verifier_worker.run_verifier_worker(config, stop)

    assert captured["request_timeout_seconds"] == config.request_timeout_seconds
    assert captured["controller_timeout_seconds"] == config.request_timeout_seconds
