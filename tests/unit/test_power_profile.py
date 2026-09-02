"""P0 contract tests for the opt-in Power profile boundary."""

from __future__ import annotations

from pathlib import Path

import pytest
from ctfmesh_api.settings import Settings
from ctfmesh_sandboxd import PowerProfileDisabledError, SandboxdSettings, create_sandboxd_app
from fastapi.testclient import TestClient


def test_power_is_explicitly_disabled_in_shared_api_settings() -> None:
    """The schema defaults to opt-in and accepts only an explicit enablement."""

    # The developer's local `.env` can intentionally enable the Power profile.
    # Check the schema default directly, then make both deployment choices
    # explicit so this test never depends on that machine state.
    assert Settings.model_fields["power_enabled"].default is False
    assert Settings(power_enabled=False).power_enabled is False
    assert Settings(power_enabled=True).power_enabled is True


def test_sandboxd_requires_the_power_feature_flag() -> None:
    """A Docker-socket-owning service cannot start by accidental profile use."""

    with pytest.raises(PowerProfileDisabledError, match="power_profile_disabled"):
        create_sandboxd_app(SandboxdSettings(power_enabled=False))


def test_sandboxd_p0_is_health_only_when_explicitly_enabled() -> None:
    """P0 proves the boundary without exposing a premature exec endpoint."""

    app = create_sandboxd_app(SandboxdSettings(power_enabled=True))
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "profile": "power", "service": "sandboxd"}
        assert client.get("/workspaces").status_code == 404


def test_sandboxd_rejects_unreviewed_socket_or_bind_configuration() -> None:
    """P0 fixes the manager interface before P1 adds Docker actions."""

    with pytest.raises(ValueError, match="reviewed Docker socket path"):
        SandboxdSettings(power_enabled=True, docker_socket_path=Path("/tmp/docker.sock"))
    with pytest.raises(ValueError, match="reviewed container interface"):
        SandboxdSettings(power_enabled=True, bind_host="127.0.0.1")
