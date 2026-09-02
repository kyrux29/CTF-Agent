"""Static Compose proof for the M3 source, target, and provider boundaries.

This test intentionally renders Compose rather than launching a model or a
target. It catches topology regressions in every Python test environment
without requiring an API key, a challenge bundle, or external network access.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_PROVIDER_KEYS = {"OPENAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY"}
_M5_FIXTURE_PRIVATE_KEY = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
_M5_FIXTURE_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
_M3_CONFIG_ENV = {
    "CTFMESH_INTERNAL_RUNNER_TOKEN": "internal-runner-token-fixture-1234",
    "CTFMESH_TOOL_GATEWAY_URL": "http://tool-gateway:8081",
    "CTFMESH_TOOL_GATEWAY_TOKEN": "tool-gateway-token-fixture-1234",
    "CTFMESH_SOURCE_SLOT_TOKEN": "source-slot-token-fixture-1234",
    "CTFMESH_SOURCE_SLOT_1_CHALLENGE_ID": "challenge-slot-one",
    "CTFMESH_SOURCE_SLOT_1_URL": "http://sandbox-source-1:8082",
    "CTFMESH_SOURCE_SLOT_2_CHALLENGE_ID": "challenge-slot-two",
    "CTFMESH_SOURCE_SLOT_2_URL": "http://sandbox-source-2:8082",
    "CTFMESH_PI_MODEL_PROVIDER": "openai",
    "CTFMESH_PI_MODEL_ID": "gpt-4.1",
}
_M5_CONFIG_ENV = {
    "CTFMESH_INTERNAL_VERIFIER_TOKEN": "verifier-token-fixture-1234",
    "CTFMESH_LAB_CONTROLLER_TOKEN": "controller-token-fixture-1234",
    "CTFMESH_LAB_CONTROLLER_PRIVATE_KEY": _M5_FIXTURE_PRIVATE_KEY,
    "CTFMESH_LAB_CONTROLLER_PUBLIC_KEY": _M5_FIXTURE_PUBLIC_KEY,
}
_M6_CONFIG_ENV = {
    "CTFMESH_INTERNAL_RUNNER_TOKEN": "internal-runner-token-fixture-1234",
    "CTFMESH_INTERNAL_VERIFIER_TOKEN": "verifier-token-fixture-1234",
    "CTFMESH_TOOL_GATEWAY_URL": "http://tool-gateway:8081",
    "CTFMESH_TOOL_GATEWAY_TOKEN": "tool-gateway-token-fixture-1234",
    "CTFMESH_SOURCE_SLOT_TOKEN": "source-slot-token-fixture-1234",
    "CTFMESH_SOURCE_SLOT_1_URL": "http://ui-source-slot-1:8082",
    "CTFMESH_SOURCE_SLOT_2_URL": "http://ui-source-slot-2:8082",
    "CTFMESH_SOURCE_SLOT_1_DYNAMIC_ASSIGNMENT": "true",
    "CTFMESH_SOURCE_SLOT_2_DYNAMIC_ASSIGNMENT": "true",
    "CTFMESH_TARGET_CAPABILITY_KEY": "target-capability-key-fixture-material-1234",
}


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _service_networks(service: dict[str, object]) -> set[str]:
    return set(_mapping(service.get("networks", {})))


def _service_environment(service: dict[str, object]) -> dict[str, object]:
    return _mapping(service.get("environment", {}))


def _service_volumes(service: dict[str, object]) -> list[dict[str, object]]:
    raw_volumes = service.get("volumes", [])
    assert isinstance(raw_volumes, list)
    return [_mapping(volume) for volume in raw_volumes]


@pytest.mark.integration
def test_web_port_override_stays_loopback_only() -> None:
    """Parallel local smoke projects may change the port, never the ingress host."""

    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Compose configuration proof")
    environment = os.environ.copy()
    for key in _PROVIDER_KEYS:
        environment.pop(key, None)
    environment["WEB_PORT"] = "5188"
    # nosec B603 / noqa: S603 - fixed, resolved Docker binary and literal argv.
    completed = subprocess.run(  # noqa: S603
        [docker_binary, "compose", "config", "--format", "json"],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    rendered = _mapping(json.loads(completed.stdout))
    web = _mapping(_mapping(rendered["services"])["web"])
    ports = web["ports"]
    assert isinstance(ports, list) and len(ports) == 1
    port = _mapping(ports[0])
    assert port == {
        "mode": "ingress",
        "host_ip": "127.0.0.1",
        "target": 8080,
        "published": "5188",
        "protocol": "tcp",
    }


@pytest.mark.integration
def test_default_compose_keeps_browser_triage_behind_the_internal_proxy() -> None:
    """The blank Web stack must never fall back to direct provider egress."""

    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Compose configuration proof")
    environment = os.environ.copy()
    for key in _PROVIDER_KEYS:
        environment.pop(key, None)
    # nosec B603 / noqa: S603 - fixed, resolved Docker binary and literal argv.
    completed = subprocess.run(  # noqa: S603
        [docker_binary, "compose", "config", "--format", "json"],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    # Do not include Compose stdout/stderr in assertions: an operator may have
    # supplied unrelated local values in the process environment.
    assert completed.returncode == 0
    rendered = _mapping(json.loads(completed.stdout))
    services = _mapping(rendered["services"])
    assert set(services) == {
        "api",
        "artifact-init",
        "source-slot-init",
        "postgres",
        "provider-proxy",
        "web",
    }

    api = _mapping(services["api"])
    proxy = _mapping(services["provider-proxy"])
    web = _mapping(services["web"])
    assert _service_networks(api) == {"control", "db", "frontend", "provider"}
    assert _service_networks(proxy) == {"provider", "provider-public"}
    assert _service_networks(web) == {"frontend", "ui-ingress"}
    assert _service_environment(api)["CTFMESH_PROVIDER_PROXY_URL"] == "http://provider-proxy:3128"
    assert _service_environment(proxy)["CTFMESH_PROVIDER_PROXY_IDLE_TIMEOUT_SECONDS"] == "86520"
    nginx_configuration = (_ROOT / "apps" / "web" / "nginx.conf").read_text(encoding="utf-8")
    assert "proxy_read_timeout 86520s;" in nginx_configuration
    assert _mapping(api["depends_on"])["provider-proxy"] == {
        "condition": "service_healthy",
        "required": True,
    }
    assert "ports" not in api


@pytest.mark.integration
def test_m3_compose_keeps_target_and_provider_paths_separate() -> None:
    """Only the proxy can reach the provider network; slots remain internal."""

    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Compose configuration proof")
    environment = os.environ.copy()
    for key in _PROVIDER_KEYS:
        environment.pop(key, None)
    environment.update(_M3_CONFIG_ENV)
    # nosec B603 / noqa: S603 - fixed, resolved Docker binary and literal argv.
    completed = subprocess.run(  # noqa: S603
        [
            docker_binary,
            "compose",
            "--profile",
            "m3",
            "config",
            "--format",
            "json",
        ],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    # Do not include Compose stdout/stderr in this assertion: a local operator
    # may have supplied credentials in a Compose environment outside this test.
    assert completed.returncode == 0
    rendered = _mapping(json.loads(completed.stdout))
    services = _mapping(rendered["services"])
    networks = _mapping(rendered["networks"])

    assert {
        "postgres",
        "artifact-init",
        "api",
        "web",
        "pi-session-init",
        "preflight-worker",
        "tool-gateway",
        "sandbox-source-1",
        "sandbox-source-2",
        "provider-proxy",
        "pi-runner-live",
    } <= set(services)
    # The aggregate M3 deployment must not start the M2 fixture runner: both
    # runners consume the same durable queue and would otherwise race for jobs.
    assert "pi-runner" not in services
    assert all(
        _mapping(networks[name]).get("internal") is True
        for name in ("frontend", "control", "db", "slot-1", "slot-2", "provider")
    )
    ui_ingress = _mapping(networks["ui-ingress"])
    assert ui_ingress.get("internal") is not True
    assert (
        _mapping(ui_ingress["driver_opts"])["com.docker.network.bridge.enable_ip_masquerade"]
        == "false"
    )
    assert _mapping(networks["provider-public"]).get("internal") is not True

    api = _mapping(services["api"])
    web = _mapping(services["web"])
    source_one = _mapping(services["sandbox-source-1"])
    source_two = _mapping(services["sandbox-source-2"])
    gateway = _mapping(services["tool-gateway"])
    live_runner = _mapping(services["pi-runner-live"])
    proxy = _mapping(services["provider-proxy"])

    assert _mapping(services["preflight-worker"])["command"] == ["ctfmesh-preflight-worker"]

    # Slot networks are internal and mutually separate. The Pi process cannot
    # resolve a target through either network, and no slot can reach provider
    # egress by itself.
    assert _service_networks(source_one) == {"slot-1"}
    assert _service_networks(source_two) == {"slot-2"}
    # The API can make only code-owned provider calls through the private
    # proxy. It never reaches the proxy's external bridge directly.
    assert _service_networks(api) == {"control", "db", "frontend", "provider"}
    assert _service_networks(web) == {"frontend", "ui-ingress"}
    assert "ports" not in api
    assert [
        name
        for name, raw_service in services.items()
        if "ui-ingress" in _service_networks(_mapping(raw_service))
    ] == ["web"]
    assert _service_networks(live_runner) == {"control", "provider"}
    assert _service_networks(live_runner).isdisjoint({"slot-1", "slot-2"})
    assert _service_networks(proxy) == {"provider", "provider-public"}
    assert [
        name
        for name, raw_service in services.items()
        if "provider-public" in _service_networks(_mapping(raw_service))
    ] == ["provider-proxy"]
    assert _service_environment(api)["CTFMESH_PROVIDER_PROXY_URL"] == "http://provider-proxy:3128"
    assert _service_networks(gateway) == {"control", "db", "slot-1", "slot-2"}
    assert gateway["user"] == "65532:10001"

    # Since M-PI-2, browser credentials arrive through the private, short-lived
    # lease broker. No Compose environment receives a provider key, including
    # the Pi process that keeps an accepted lease in memory only.
    for name in (
        "api",
        "tool-gateway",
        "sandbox-source-1",
        "sandbox-source-2",
        "provider-proxy",
        "pi-runner-live",
    ):
        assert _PROVIDER_KEYS.isdisjoint(_service_environment(_mapping(services[name])))
    assert _service_environment(live_runner)["CTFMESH_PI_CREDENTIAL_BIND_PORT"] == "8090"
    assert _service_environment(live_runner)["CTFMESH_PI_CREDENTIAL_MAX_TTL_SECONDS"] == "900"
    assert _service_environment(live_runner)["HTTPS_PROXY"] == "http://provider-proxy:3128"
    assert _service_environment(live_runner)["HTTP_PROXY"] == "http://provider-proxy:3128"
    assert _service_environment(live_runner)["NODE_OPTIONS"] == "--use-env-proxy"

    hardened = (source_one, source_two, gateway, live_runner, proxy)
    for service in hardened:
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in cast(list[str], service["security_opt"])
        assert service.get("privileged", False) is False
        assert "ports" not in service
        pids_limit = service.get("pids_limit")
        assert isinstance(pids_limit, int)
        assert pids_limit > 0
        for volume in _service_volumes(service):
            assert volume.get("source") != "/var/run/docker.sock"
            assert volume.get("target") != "/var/run/docker.sock"

    for source in (source_one, source_two):
        assert source["user"] == "65532:65532"
        challenge_mounts = [
            volume for volume in _service_volumes(source) if volume.get("target") == "/challenge"
        ]
        assert len(challenge_mounts) == 1
        assert challenge_mounts[0]["type"] == "bind"
        assert challenge_mounts[0]["read_only"] is True
        assert _mapping(challenge_mounts[0]["bind"])["create_host_path"] is False


@pytest.mark.integration
def test_m3_source_profile_can_probe_one_challenge_without_a_provider_key() -> None:
    """Both fixed slots may bind one first challenge while Pi live stays absent."""

    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Compose configuration proof")
    environment = os.environ.copy()
    for key in _PROVIDER_KEYS:
        environment.pop(key, None)
    environment.update(
        {
            "CTFMESH_INTERNAL_RUNNER_TOKEN": "internal-runner-token-fixture-1234",
            "CTFMESH_TOOL_GATEWAY_URL": "http://tool-gateway:8081",
            "CTFMESH_TOOL_GATEWAY_TOKEN": "tool-gateway-token-fixture-1234",
            "CTFMESH_SOURCE_SLOT_TOKEN": "source-slot-token-fixture-1234",
            "CTFMESH_SOURCE_SLOT_1_CHALLENGE_ID": "challenge-first-operator-case",
        }
    )
    completed = subprocess.run(  # noqa: S603
        [docker_binary, "compose", "--profile", "m3-source", "config", "--format", "json"],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    services = _mapping(_mapping(json.loads(completed.stdout))["services"])
    assert {
        "api",
        "preflight-worker",
        "tool-gateway",
        "sandbox-source-1",
        "sandbox-source-2",
    } <= set(services)
    assert "pi-runner-live" not in services
    assert _PROVIDER_KEYS.isdisjoint(_service_environment(_mapping(services["preflight-worker"])))
    for slot_name in ("sandbox-source-1", "sandbox-source-2"):
        slot = _mapping(services[slot_name])
        assert _service_environment(slot)["CTFMESH_SOURCE_SLOT_CHALLENGE_ID"] == (
            "challenge-first-operator-case"
        )
        challenge_mount = next(
            volume for volume in _service_volumes(slot) if volume.get("target") == "/challenge"
        )
        assert str(challenge_mount["source"]).endswith("/challenges/challenge-first-operator-case")


@pytest.mark.integration
def test_m5_compose_isolates_random_flag_labs_from_pi_and_controller_paths() -> None:
    """Verifier-only M5 labs get no provider, source, host, or Docker authority."""

    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Compose configuration proof")
    environment = os.environ.copy()
    for key in _PROVIDER_KEYS:
        environment.pop(key, None)
    environment.update(_M5_CONFIG_ENV)
    # nosec B603 / noqa: S603 - fixed, resolved Docker binary and literal argv.
    completed = subprocess.run(  # noqa: S603
        [docker_binary, "compose", "--profile", "m5", "config", "--format", "json"],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    rendered = _mapping(json.loads(completed.stdout))
    services = _mapping(rendered["services"])
    networks = _mapping(rendered["networks"])
    expected = {
        "postgres",
        "artifact-init",
        "source-slot-init",
        "api",
        "provider-proxy",
        "web",
        "lab-flag-init",
        "lab-controller",
        "lab-path-traversal",
        "lab-authz-boundary",
        "lab-sqli-basic",
        "verifier",
    }
    assert set(services) == expected
    assert "pi-runner" not in services
    assert "pi-runner-live" not in services
    assert "tool-gateway" not in services

    # The initializer must be restart-safe. Runtime controller files are owned
    # by UID 65532 in a 0750 volume, so recursively traversing them after the
    # first boot would require widening capabilities. It only needs to own the
    # three mount roots before the unprivileged services start.
    initializer = _mapping(services["lab-flag-init"])
    command = initializer["command"]
    assert isinstance(command, list) and len(command) == 3
    assert command[:2] == ["sh", "-ec"]
    assert isinstance(command[2], str)
    assert "chown -R" not in command[2]
    assert "chown 65532:65532" in command[2]
    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN", "FOWNER"]

    api = _mapping(services["api"])
    controller = _mapping(services["lab-controller"])
    verifier = _mapping(services["verifier"])
    targets = {
        "lab-path-traversal": ("verify-lab-path", "lab-path-traversal-flags"),
        "lab-authz-boundary": ("verify-lab-authz", "lab-authz-boundary-flags"),
        "lab-sqli-basic": ("verify-lab-sqli", "lab-sqli-basic-flags"),
    }
    assert _service_networks(api) == {"control", "db", "frontend", "provider"}
    assert _service_networks(controller) == {"verify-controller"}
    assert _service_networks(verifier) == {
        "control",
        "verify-controller",
        "verify-lab-path",
        "verify-lab-authz",
        "verify-lab-sqli",
    }
    assert _PROVIDER_KEYS.isdisjoint(_service_environment(verifier))
    assert "CTFMESH_LAB_CONTROLLER_PRIVATE_KEY" not in _service_environment(api)
    assert "CTFMESH_LAB_CONTROLLER_PUBLIC_KEY" not in _service_environment(api)
    assert _service_environment(verifier)["CTFMESH_VERIFIER_CONTROL_BASE_URL"] == "http://api:8000"
    assert "CTFMESH_LAB_CONTROLLER_PRIVATE_KEY" in _service_environment(controller)
    assert "CTFMESH_LAB_CONTROLLER_PUBLIC_KEY" not in _service_environment(controller)
    assert "CTFMESH_LAB_CONTROLLER_PRIVATE_KEY" not in _service_environment(verifier)
    assert "CTFMESH_LAB_CONTROLLER_PUBLIC_KEY" in _service_environment(verifier)
    for name in ("verify-controller", "verify-lab-path", "verify-lab-authz", "verify-lab-sqli"):
        assert _mapping(networks[name]).get("internal") is True

    hardened = (controller, verifier, *(_mapping(services[name]) for name in targets))
    for service in hardened:
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in cast(list[str], service["security_opt"])
        assert service.get("privileged", False) is False
        assert "ports" not in service
        for volume in _service_volumes(service):
            assert volume.get("source") != "/var/run/docker.sock"
            assert volume.get("target") != "/var/run/docker.sock"

    for name, (network, volume_name) in targets.items():
        target = _mapping(services[name])
        assert _service_networks(target) == {network}
        flag_mounts = [
            volume
            for volume in _service_volumes(target)
            if volume.get("target") == "/run/ctfmesh/flag"
        ]
        assert len(flag_mounts) == 1
        assert flag_mounts[0]["source"] == volume_name
        assert flag_mounts[0]["read_only"] is True
        environment = _service_environment(target)
        assert not {
            "CTFMESH_LAB_CONTROLLER_TOKEN",
            "CTFMESH_LAB_CONTROLLER_PRIVATE_KEY",
            "CTFMESH_LAB_CONTROLLER_PUBLIC_KEY",
            "CTFMESH_INTERNAL_VERIFIER_TOKEN",
        } & set(environment)


@pytest.mark.integration
def test_m6_compose_isolates_exact_instance_target_and_remote_verifier() -> None:
    """Only connector and verifier reach public targets; neither sees keys/source."""

    docker_binary = shutil.which("docker")
    if docker_binary is None:
        pytest.skip("Docker CLI is unavailable for Compose configuration proof")
    environment = os.environ.copy()
    for key in _PROVIDER_KEYS:
        environment.pop(key, None)
    environment.update(_M6_CONFIG_ENV)
    # nosec B603 / noqa: S603 - fixed, resolved Docker binary and literal argv.
    completed = subprocess.run(  # noqa: S603
        [docker_binary, "compose", "--profile", "m6-ui", "config", "--format", "json"],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    rendered = _mapping(json.loads(completed.stdout))
    services = _mapping(rendered["services"])
    networks = _mapping(rendered["networks"])
    remote_verifier = _mapping(services["remote-verifier"])
    connector = _mapping(services["target-connector"])
    source_slot = _mapping(services["ui-source-slot-1"])
    source_initializer = _mapping(services["source-slot-init"])

    assert _service_networks(remote_verifier) == {"control", "target-public"}
    assert _service_networks(connector) == {"slot-1", "slot-2", "target-public"}
    assert _service_networks(source_slot) == {"slot-1"}
    assert _mapping(networks["slot-1"]).get("internal") is True
    assert _mapping(networks["target-public"]).get("internal") is not True
    assert _PROVIDER_KEYS.isdisjoint(_service_environment(remote_verifier))
    assert _PROVIDER_KEYS.isdisjoint(_service_environment(connector))
    assert "CTFMESH_LAB_CONTROLLER_TOKEN" not in _service_environment(remote_verifier)
    assert _service_environment(remote_verifier)["CTFMESH_VERIFIER_REMOTE_REPLAY_ENABLED"] == "true"
    assert all(volume.get("target") != "/slot" for volume in _service_volumes(remote_verifier))
    for service in (remote_verifier, connector, source_slot):
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service.get("privileged", False) is False
        assert "ports" not in service

    # The initializer is the sole writable root process: named volumes need
    # ownership setup before the non-root API can atomically stage an archive.
    # It remains fully isolated from the network and retains only filesystem
    # ownership capabilities; it never receives a challenge, key, or socket.
    assert source_initializer["network_mode"] == "none"
    assert source_initializer.get("read_only") is not True
    assert source_initializer["cap_drop"] == ["ALL"]
    assert source_initializer["cap_add"] == ["CHOWN", "FOWNER"]
    initializer_command = source_initializer["command"]
    assert isinstance(initializer_command, list) and len(initializer_command) == 3
    assert "chown -R" not in initializer_command[2]
    assert "chown 10001:10001" in initializer_command[2]
    assert source_initializer.get("privileged", False) is False
    assert "ports" not in source_initializer
    assert all(
        volume.get("source") != "/var/run/docker.sock"
        and volume.get("target") != "/var/run/docker.sock"
        for volume in _service_volumes(source_initializer)
    )
