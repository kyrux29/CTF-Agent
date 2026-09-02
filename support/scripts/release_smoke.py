"""Run an isolated, credential-free Docker Compose release smoke.

The script owns a fresh Compose project name and always tears that project down.
It deliberately runs the blank default profile only: no operator challenge,
provider key, M3 source mount, M5 controller credential, or live model enters
the release smoke.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import signal
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import FrameType
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
_PROJECT_PREFIX = "ctfmesh-release-smoke-"
_PROJECT_NAME = re.compile(r"^ctfmesh-release-smoke-[0-9a-f]{8}$")
_PROVIDER_KEY_NAMES = frozenset({"OPENAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY"})
_COMPOSE_TIMEOUT_SECONDS = 600
_TEARDOWN_TIMEOUT_SECONDS = 120
_HEALTH_TIMEOUT_SECONDS = 10


class ReleaseSmokeError(RuntimeError):
    """A stable, secret-free phase error suitable for local terminal output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _interrupt_for_cleanup(_signum: int, _frame: FrameType | None) -> None:
    """Convert SIGTERM into normal interruption so ``run_release_smoke`` cleans up."""

    raise KeyboardInterrupt


def _web_port(value: str) -> int:
    """Accept an unprivileged loopback port for one temporary Web ingress."""

    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("web port must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("web port must be between 1024 and 65535")
    return port


def _project_name() -> str:
    """Generate rather than accept a project name, preventing accidental teardown."""

    return f"{_PROJECT_PREFIX}{secrets.token_hex(4)}"


def _validate_project_name(project: str) -> None:
    """Refuse a caller-selected Compose project outside this script's nonce form."""

    if _PROJECT_NAME.fullmatch(project) is None:
        raise ReleaseSmokeError("release_smoke_project_invalid")


def _sanitized_environment(
    source: Mapping[str, str],
    *,
    web_port: int,
) -> dict[str, str]:
    """Retain Docker configuration but remove every CTFMesh/provider credential."""

    environment = {
        name: value
        for name, value in source.items()
        if not name.startswith("CTFMESH_") and name not in _PROVIDER_KEY_NAMES
    }
    # The only Compose interpolation this smoke needs is a loopback-only Web
    # port. It is set after filtering so an ambient environment cannot replace
    # the selected test port or inject a stack credential.
    environment["WEB_PORT"] = str(web_port)
    return environment


def _compose_argv(docker_binary: str, project: str, *arguments: str) -> list[str]:
    """Build a fixed-argument Compose invocation without a shell interpreter."""

    return [docker_binary, "compose", "--project-name", project, *arguments]


def _run_compose(
    docker_binary: str,
    project: str,
    environment: Mapping[str, str],
    *,
    phase: str,
    arguments: Sequence[str],
    timeout_seconds: int,
) -> None:
    """Run Compose with bounded time and suppress potentially sensitive output."""

    try:
        # nosec B603 - Docker path comes from ``shutil.which`` and all remaining
        # argv entries are code-owned constants or a generated project name.
        completed = subprocess.run(  # noqa: S603
            _compose_argv(docker_binary, project, *arguments),
            cwd=ROOT,
            env=dict(environment),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseSmokeError(f"release_smoke_{phase}_unavailable") from exc
    if completed.returncode != 0:
        raise ReleaseSmokeError(f"release_smoke_{phase}_failed")


def _health_url(web_port: int, path: str) -> str:
    """Construct one code-owned loopback probe URL, never an operator URL."""

    if path not in {"/v1/ready", "/healthz"}:
        raise ValueError("release_smoke_health_path_invalid")
    return f"http://127.0.0.1:{web_port}{path}"


def _assert_healthy(*, web_port: int, path: str) -> None:
    """Probe health through loopback with no proxy and no response-body logging."""

    request = Request(_health_url(web_port, path), method="GET")  # noqa: S310 - fixed loopback URL.
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(request, timeout=_HEALTH_TIMEOUT_SECONDS) as response:
            # Nginx's deliberately bodyless `/healthz` is HTTP 204, while
            # API readiness is HTTP 200. Both are successful loopback probes.
            if not 200 <= response.status < 300:
                raise ReleaseSmokeError("release_smoke_health_failed")
            # Consume only a bounded amount so a misbehaving local service
            # cannot retain a connection indefinitely. The body is not output.
            response.read(4 * 1024)
    except ReleaseSmokeError:
        raise
    except (HTTPError, OSError, URLError) as exc:
        raise ReleaseSmokeError("release_smoke_health_unavailable") from exc


def run_release_smoke(*, docker_binary: str, web_port: int, project: str) -> None:
    """Run config, boot, readiness and teardown for an isolated blank project."""

    _validate_project_name(project)
    environment = _sanitized_environment(os.environ, web_port=web_port)
    failure: ReleaseSmokeError | None = None
    try:
        _run_compose(
            docker_binary,
            project,
            environment,
            phase="config",
            arguments=("config", "--quiet"),
            timeout_seconds=30,
        )
        _run_compose(
            docker_binary,
            project,
            environment,
            phase="up",
            arguments=("up", "--detach", "--build", "--wait", "--wait-timeout", "180"),
            timeout_seconds=_COMPOSE_TIMEOUT_SECONDS,
        )
        _assert_healthy(web_port=web_port, path="/v1/ready")
        _assert_healthy(web_port=web_port, path="/healthz")
    except ReleaseSmokeError as exc:
        failure = exc
    finally:
        # This has no user-provided project selector: it can tear down only the
        # fresh project generated by this script, including its temporary data.
        try:
            _run_compose(
                docker_binary,
                project,
                environment,
                phase="teardown",
                arguments=("down", "--volumes", "--remove-orphans"),
                timeout_seconds=_TEARDOWN_TIMEOUT_SECONDS,
            )
        except ReleaseSmokeError:
            if failure is None:
                raise
    if failure is not None:
        raise failure


def main(argv: Sequence[str] | None = None) -> int:
    """Provide a small terminal entry point without accepting secrets or targets."""

    parser = argparse.ArgumentParser(description="Run an isolated CTFMesh release smoke.")
    parser.add_argument(
        "--web-port",
        type=_web_port,
        default=5175,
        help="temporary loopback Web port (default: 5175)",
    )
    args = parser.parse_args(argv)
    docker_binary = shutil.which("docker")
    if docker_binary is None:
        print("Release smoke failed: Docker CLI is unavailable.")
        return 1

    # Ctrl-C already raises ``KeyboardInterrupt``. Convert service-manager
    # SIGTERM to the same control flow so the run function's ``finally`` block
    # gets a chance to remove its generated project as well.
    previous_sigterm_handler = signal.signal(signal.SIGTERM, _interrupt_for_cleanup)
    try:
        project = _project_name()
        print(f"Running isolated release smoke project {project} on 127.0.0.1:{args.web_port}.")
        try:
            run_release_smoke(docker_binary=docker_binary, web_port=args.web_port, project=project)
        except ReleaseSmokeError as exc:
            print(f"Release smoke failed: {exc.code}. Temporary project teardown was attempted.")
            return 1
        print("Release smoke passed; the temporary project and volumes were removed.")
        return 0
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm_handler)


if __name__ == "__main__":
    raise SystemExit(main())
