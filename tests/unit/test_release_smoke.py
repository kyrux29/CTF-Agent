"""Unit coverage for the isolated, credential-free release smoke helper."""

from __future__ import annotations

import importlib.util
import subprocess
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _load_release_smoke() -> ModuleType:
    """Load the host-side script without making ``support/`` a product package."""

    script_path = Path(__file__).resolve().parents[2] / "support" / "scripts" / "release_smoke.py"
    specification = importlib.util.spec_from_file_location("ctfmesh_release_smoke", script_path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


release_smoke: Any = _load_release_smoke()


def test_sanitized_environment_removes_provider_and_runtime_secrets() -> None:
    """The default smoke must not inherit a model key or an internal token."""

    environment = release_smoke._sanitized_environment(
        {
            "SAFE_DOCKER_CONFIG": "retained",
            "OPENAI_API_KEY": "must-not-cross",
            "GEMINI_API_KEY": "must-not-cross",
            "DEEPSEEK_API_KEY": "must-not-cross",
            "CTFMESH_INTERNAL_RUNNER_TOKEN": "must-not-cross",
            "CTFMESH_LAB_CONTROLLER_PRIVATE_KEY": "must-not-cross",
            "WEB_PORT": "untrusted-ambient-port",
        },
        web_port=5199,
    )

    assert environment == {"SAFE_DOCKER_CONFIG": "retained", "WEB_PORT": "5199"}


def test_release_smoke_runs_fixed_phases_then_removes_only_its_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful run has config/up/two health probes/down in this exact order."""

    commands: list[Sequence[str]] = []
    health_paths: list[str] = []

    def fake_run(arguments: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(arguments)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(release_smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(
        release_smoke,
        "_assert_healthy",
        lambda *, web_port, path: health_paths.append(f"{web_port}:{path}"),
    )
    monkeypatch.setattr(release_smoke.os, "environ", {"OPENAI_API_KEY": "ignored"})

    release_smoke.run_release_smoke(
        docker_binary="/usr/bin/docker",
        web_port=5199,
        project="ctfmesh-release-smoke-deadbeef",
    )

    assert commands == [
        [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            "ctfmesh-release-smoke-deadbeef",
            "config",
            "--quiet",
        ],
        [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            "ctfmesh-release-smoke-deadbeef",
            "up",
            "--detach",
            "--build",
            "--wait",
            "--wait-timeout",
            "180",
        ],
        [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            "ctfmesh-release-smoke-deadbeef",
            "down",
            "--volumes",
            "--remove-orphans",
        ],
    ]
    assert health_paths == ["5199:/v1/ready", "5199:/healthz"]


def test_release_smoke_tears_down_after_a_boot_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable stack cannot leave its generated project running."""

    commands: list[Sequence[str]] = []

    def fake_run(arguments: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(arguments)
        return subprocess.CompletedProcess(arguments, 1 if "up" in arguments else 0)

    monkeypatch.setattr(release_smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(release_smoke.os, "environ", {})

    with pytest.raises(release_smoke.ReleaseSmokeError, match="release_smoke_up_failed"):
        release_smoke.run_release_smoke(
            docker_binary="/usr/bin/docker",
            web_port=5199,
            project="ctfmesh-release-smoke-deadbeef",
        )

    assert [command[-1] for command in commands] == ["--quiet", "180", "--remove-orphans"]


def test_release_smoke_tears_down_after_an_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ctrl-C/SIGTERM's normalized interrupt path still removes the nonce project."""

    commands: list[Sequence[str]] = []

    def fake_run(arguments: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(arguments)
        if "up" in arguments:
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(release_smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(release_smoke.os, "environ", {})

    with pytest.raises(KeyboardInterrupt):
        release_smoke.run_release_smoke(
            docker_binary="/usr/bin/docker",
            web_port=5199,
            project="ctfmesh-release-smoke-deadbeef",
        )

    assert [command[-1] for command in commands] == ["--quiet", "180", "--remove-orphans"]


def test_health_url_is_locked_to_the_two_reviewed_loopback_probes() -> None:
    """The smoke helper is not an operator-selectable URL fetcher."""

    assert release_smoke._health_url(5175, "/v1/ready") == "http://127.0.0.1:5175/v1/ready"
    with pytest.raises(ValueError, match="release_smoke_health_path_invalid"):
        release_smoke._health_url(5175, "/outside")


def test_health_probe_accepts_nginx_bodyless_success_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Web health endpoint intentionally returns 204 rather than JSON/200."""

    class Response:
        status = 204

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_arguments: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b""

    class Opener:
        def open(self, _request: object, *, timeout: int) -> Response:
            assert timeout == 10
            return Response()

    monkeypatch.setattr(release_smoke, "build_opener", lambda *_handlers: Opener())

    release_smoke._assert_healthy(web_port=5175, path="/healthz")


def test_release_smoke_refuses_a_caller_selected_project_name() -> None:
    """The cleanup helper cannot be pointed at a normal operator stack."""

    with pytest.raises(release_smoke.ReleaseSmokeError, match="release_smoke_project_invalid"):
        release_smoke.run_release_smoke(
            docker_binary="/usr/bin/docker",
            web_port=5199,
            project="ctfmesh-smoke",
        )


def test_main_installs_and_restores_sigterm_cleanup_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The command-line entry point normalizes service-manager termination."""

    previous_handler = object()
    installed_handlers: list[object] = []
    monkeypatch.setattr(release_smoke.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(release_smoke, "_project_name", lambda: "ctfmesh-release-smoke-deadbeef")
    monkeypatch.setattr(release_smoke, "run_release_smoke", lambda **_kwargs: None)

    def fake_signal(_number: int, handler: object) -> object:
        installed_handlers.append(handler)
        return previous_handler

    monkeypatch.setattr(release_smoke.signal, "signal", fake_signal)

    assert release_smoke.main(["--web-port", "5199"]) == 0
    assert installed_handlers == [release_smoke._interrupt_for_cleanup, previous_handler]
