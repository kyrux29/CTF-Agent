"""P2's private flag-router HTTP boundary keeps candidate values transient."""

from __future__ import annotations

from dataclasses import dataclass

from ctfmesh_flag_router import FlagRouterSettings, create_flag_router_app
from fastapi.testclient import TestClient
from pydantic import SecretStr


@dataclass
class _Router:
    accepted: bool = True
    candidate: str | None = None

    async def submit(
        self,
        *,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        assert run_id == "run-power-p2"
        assert observation_artifact_id == f"sha256:{'a' * 64}"
        assert observation_sha256 == "a" * 64
        self.candidate = candidate
        return self.accepted


def test_flag_router_requires_its_own_solver_capability_and_never_echoes_candidate() -> None:
    """Neither a bad token nor a successful receipt serializes the raw flag."""

    solver_token = "s" * 32
    candidate = "CTF{transient_only}"
    router = _Router()
    app = create_flag_router_app(
        FlagRouterSettings(
            router_token=SecretStr(solver_token),
            control_api_token=SecretStr("c" * 32),
        ),
        router=router,  # type: ignore[arg-type] - narrow fixture protocol.
    )
    body = {
        "run_id": "run-power-p2",
        "candidate": candidate,
        "observation_artifact_id": f"sha256:{'a' * 64}",
        "observation_sha256": "a" * 64,
    }
    with TestClient(app) as client:
        denied = client.post("/v1/flags/submit", json=body)
        assert denied.status_code == 401
        assert candidate not in denied.text

        accepted = client.post(
            "/v1/flags/submit",
            json=body,
            headers={"X-CTFMesh-Flag-Router-Token": solver_token},
        )
    assert accepted.status_code == 200
    assert accepted.json() == {"accepted": True}
    assert candidate not in accepted.text
    assert router.candidate == candidate
