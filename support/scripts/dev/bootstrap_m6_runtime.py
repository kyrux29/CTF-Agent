"""Create the private Compose configuration required by the M6.a local runtime.

This utility creates only machine-to-machine credentials for the local Docker
services.  It deliberately has no field for an AI-provider key: provider keys
are entered in the browser's in-memory Settings vault for the selected run.
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[3]
DEFAULT_ENV_PATH: Final = ROOT / ".env"
_TOKEN_BYTES: Final = 32

# Keep these fixed origins beside their matching Compose services.  The API
# accepts only this reviewed internal topology; an archive/request cannot
# select an arbitrary gateway, credential broker, or source-slot endpoint.
_FIXED_M6_VALUES: Final = {
    "CTFMESH_TOOL_GATEWAY_URL": "http://tool-gateway:8081",
    "CTFMESH_SOURCE_SLOT_1_URL": "http://ui-source-slot-1:8082",
    "CTFMESH_SOURCE_SLOT_2_URL": "http://ui-source-slot-2:8082",
    "CTFMESH_SOURCE_SLOT_1_DYNAMIC_ASSIGNMENT": "true",
    "CTFMESH_SOURCE_SLOT_2_DYNAMIC_ASSIGNMENT": "true",
    "CTFMESH_PI_CREDENTIAL_BROKER_URL": "http://pi-runner-live:8090",
}
_TOKEN_NAMES: Final = (
    "CTFMESH_INTERNAL_RUNNER_TOKEN",
    "CTFMESH_INTERNAL_VERIFIER_TOKEN",
    "CTFMESH_TOOL_GATEWAY_TOKEN",
    "CTFMESH_SOURCE_SLOT_TOKEN",
    "CTFMESH_TARGET_CAPABILITY_KEY",
)


class BootstrapError(RuntimeError):
    """A stable, secret-free error that can be shown to an operator."""


def build_m6_environment() -> dict[str, str]:
    """Return the full M6 service configuration with independent random tokens."""

    values = dict(_FIXED_M6_VALUES)
    values.update({name: secrets.token_urlsafe(_TOKEN_BYTES) for name in _TOKEN_NAMES})
    return values


def render_environment(values: dict[str, str]) -> str:
    """Render only reviewed M6 service values; do not accept arbitrary entries."""

    expected_names = set(_FIXED_M6_VALUES) | set(_TOKEN_NAMES)
    if set(values) != expected_names or any(not value for value in values.values()):
        raise BootstrapError("m6_runtime_environment_invalid")
    lines = [
        "# Generated local M6 service configuration. This file is gitignored.",
        "# Do not add OpenAI, Gemini, DeepSeek, cookies, or flags here.",
    ]
    for name in (*_TOKEN_NAMES, *_FIXED_M6_VALUES):
        lines.append(f"{name}={values[name]}")
    return "\n".join(lines) + "\n"


def write_new_environment(path: Path) -> None:
    """Atomically create a user-private configuration without overwriting one."""

    if path != DEFAULT_ENV_PATH:
        raise BootstrapError("m6_runtime_environment_path_invalid")
    if path.exists():
        raise BootstrapError("m6_runtime_environment_exists")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise BootstrapError("m6_runtime_environment_create_failed") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(render_environment(build_m6_environment()))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise
    # A restrictive mode is also re-applied if the caller's umask is permissive.
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def main(argv: list[str] | None = None) -> int:
    """Create `.env` once, then let standard Docker Compose reuse it."""

    parser = argparse.ArgumentParser(description="Create private M6 Compose service settings.")
    parser.parse_args(argv)
    try:
        write_new_environment(DEFAULT_ENV_PATH)
    except BootstrapError as exc:
        print(f"M6 runtime bootstrap failed: {exc}.", file=sys.stderr)
        return 1
    print("M6 runtime configuration created at .env. Start with Docker Compose.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
