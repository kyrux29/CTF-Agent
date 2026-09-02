"""Static Compose proof for the isolated, opt-in Power P0 profile."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_SOCKET = "/var/run/docker.sock"


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _render(*, power: bool) -> dict[str, object]:
    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Power Compose configuration proof")
    environment = os.environ.copy()
    # The test proves topology only. Do not inherit an operator provider or
    # internal service credential into the rendered configuration process.
    for name in tuple(environment):
        if name.startswith("CTFMESH_") or name.endswith("_API_KEY"):
            environment.pop(name)
    arguments = [docker_binary, "compose", "--env-file", "/dev/null"]
    if power:
        arguments.extend(["--profile", "power"])
        environment["CTFMESH_POWER_ENABLED"] = "true"
    arguments.extend(["config", "--format", "json"])
    # nosec B603 - Docker binary is resolved once and all argv elements are fixed.
    completed = subprocess.run(  # noqa: S603
        arguments,
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    return _mapping(json.loads(completed.stdout))


def _socket_mounts(service: dict[str, object]) -> list[dict[str, object]]:
    raw_volumes = service.get("volumes")
    if raw_volumes is None:
        return []
    assert isinstance(raw_volumes, list)
    mounts = [_mapping(volume) for volume in raw_volumes]
    return [
        mount
        for mount in mounts
        if mount.get("source") == _DOCKER_SOCKET or mount.get("target") == _DOCKER_SOCKET
    ]


def _compose_declares_noncreating_socket_bind() -> bool:
    """Preserve the source-level bind invariant across Compose JSON versions."""

    document = _mapping(yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8")))
    sandboxd = _mapping(_mapping(document["services"])["sandboxd"])
    raw_volumes = sandboxd.get("volumes", [])
    assert isinstance(raw_volumes, list)
    mount = next(
        _mapping(volume)
        for volume in raw_volumes
        if isinstance(volume, dict)
        if volume.get("source") == _DOCKER_SOCKET and volume.get("target") == _DOCKER_SOCKET
    )
    return mount.get("type") == "bind" and _mapping(mount["bind"]).get("create_host_path") is False


@pytest.mark.integration
def test_default_compose_does_not_include_power_services_or_socket_mounts() -> None:
    """Power is opt-in; the normal local API/Web stack retains no Docker manager."""

    services = _mapping(_render(power=False)["services"])
    assert "sandboxd" not in services
    assert "power-workspace-image" not in services
    assert "flag-router" not in services
    assert "solver-runtime" not in services
    assert all(_socket_mounts(_mapping(service)) == [] for service in services.values())


@pytest.mark.integration
def test_power_compose_limits_the_socket_to_sandboxd_only() -> None:
    """P2 gives only the manager Docker authority; all helpers stay private."""

    services = _mapping(_render(power=True)["services"])
    sandboxd = _mapping(services["sandboxd"])
    workspace_image = _mapping(services["power-workspace-image"])
    flag_router = _mapping(services["flag-router"])
    pi_runner = _mapping(services["pi-runner-live"])

    socket_mounts = _socket_mounts(sandboxd)
    assert len(socket_mounts) == 1
    assert socket_mounts[0]["type"] == "bind"
    assert socket_mounts[0]["source"] == _DOCKER_SOCKET
    assert socket_mounts[0]["target"] == _DOCKER_SOCKET
    # Docker Compose v5 removes explicit default ``false`` from JSON output.
    # Check the source too, so that version normalization cannot weaken the
    # no-host-path-creation guarantee for the Docker socket bind.
    assert _mapping(socket_mounts[0]["bind"]).get("create_host_path") is not True
    assert _compose_declares_noncreating_socket_bind()
    assert sandboxd.get("privileged", False) is False
    assert sandboxd.get("network_mode") != "host"
    assert "ports" not in sandboxd
    assert sandboxd["read_only"] is True
    assert sandboxd["cap_drop"] == ["ALL"]
    assert sandboxd["user"] == "10001:10001"
    assert sandboxd["group_add"] == ["1000"]
    assert "no-new-privileges:true" in cast(list[str], sandboxd["security_opt"])
    assert _mapping(sandboxd["environment"])["CTFMESH_POWER_ENABLED"] == "true"
    # A raw tube is opened by this trusted manager only after the Power API
    # declares one exact endpoint. Generated workspaces still use no network.
    assert sandboxd["networks"] == {"control": None, "target-public": None}

    assert _socket_mounts(workspace_image) == []
    assert workspace_image.get("privileged", False) is False
    assert workspace_image["image"] == "ctfmesh-ctf-toolkit:0.1"
    assert _mapping(workspace_image["build"])["dockerfile"] == "images/ctf-toolkit/Dockerfile"
    assert workspace_image["network_mode"] == "none"
    assert _mapping(workspace_image["deploy"])["replicas"] == 0

    assert _socket_mounts(flag_router) == []
    assert flag_router.get("privileged", False) is False
    assert "ports" not in flag_router
    assert flag_router["read_only"] is True
    # Observation artifacts are owner-only. The router shares the writer's
    # non-root numeric identity but receives the volume read-only, so it can
    # independently verify a candidate without widening artifact permissions.
    assert flag_router["user"] == "10001:10001"
    assert flag_router["networks"] == {"control": None}
    assert flag_router["volumes"] == [
        {
            "type": "volume",
            "source": "artifact-data",
            "target": "/data/artifacts",
            "read_only": True,
            "volume": {},
        }
    ]

    # M-PI-2 removed the Python solver-runtime from production Power. The live
    # Pi harness receives short-lived credentials through its private broker,
    # never through Compose environment variables or a challenge mount.
    assert "solver-runtime" not in services
    assert _socket_mounts(pi_runner) == []
    assert pi_runner["restart"] == "unless-stopped"
    assert pi_runner.get("privileged", False) is False
    assert pi_runner["networks"] == {"control": None, "provider": None}
    runner_environment = _mapping(pi_runner["environment"])
    assert runner_environment["CTFMESH_PI_CREDENTIAL_BIND_PORT"] == "8090"
    assert {
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "DEEPSEEK_API_KEY",
    }.isdisjoint(runner_environment)
    assert all(
        _socket_mounts(_mapping(service)) == []
        for name, service in services.items()
        if name != "sandboxd"
    )
