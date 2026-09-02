"""Append the private local capabilities required by the opt-in Power profile.

This utility intentionally manages only machine-to-machine Docker credentials.
Provider API keys remain browser input and are never written to ``.env``.
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
_POWER_ENABLED_NAME: Final = "CTFMESH_POWER_ENABLED"
_SOCKET_GID_NAME: Final = "CTFMESH_SANDBOXD_SOCKET_GID"
_DOCKER_SOCKET_PATH: Final = Path("/var/run/docker.sock")
_TOKEN_NAMES: Final = (
    "CTFMESH_SANDBOXD_TOKEN",
    "CTFMESH_FLAG_ROUTER_TOKEN",
    "CTFMESH_INTERNAL_FLAG_ROUTER_TOKEN",
    # This authenticates Pi Runner to the control API.  It is deliberately
    # distinct from model keys and the sandbox/flag-router capabilities.
    "CTFMESH_INTERNAL_RUNNER_TOKEN",
)
_CORE_POWER_NAMES: Final = (_POWER_ENABLED_NAME, *_TOKEN_NAMES)
_LEGACY_POWER_NAMES: Final = (
    _POWER_ENABLED_NAME,
    "CTFMESH_SANDBOXD_TOKEN",
    "CTFMESH_FLAG_ROUTER_TOKEN",
    "CTFMESH_INTERNAL_FLAG_ROUTER_TOKEN",
)


class BootstrapError(RuntimeError):
    """Stable local bootstrap failure which never prints a secret."""


def _docker_socket_gid() -> str:
    """Return the host socket group without reading a credential or its data."""

    try:
        gid = _DOCKER_SOCKET_PATH.stat().st_gid
    except OSError as exc:
        raise BootstrapError("power_runtime_socket_gid_unavailable") from exc
    if gid < 0:
        raise BootstrapError("power_runtime_socket_gid_invalid")
    return str(gid)


def build_power_environment() -> dict[str, str]:
    """Generate independent private capabilities for one local Power stack."""

    return {
        _POWER_ENABLED_NAME: "true",
        _SOCKET_GID_NAME: _docker_socket_gid(),
        **{name: secrets.token_urlsafe(_TOKEN_BYTES) for name in _TOKEN_NAMES},
    }


def render_power_environment(
    values: dict[str, str], *, omitted_names: frozenset[str] = frozenset()
) -> str:
    """Render reviewed variables without replacing an existing runner token."""

    expected = {*_CORE_POWER_NAMES, _SOCKET_GID_NAME} - set(omitted_names)
    if (
        set(values) != expected
        or values.get(_POWER_ENABLED_NAME) != "true"
        or not values.get(_SOCKET_GID_NAME, "").isdigit()
        or any(not values.get(name) for name in _TOKEN_NAMES if name not in omitted_names)
    ):
        raise BootstrapError("power_runtime_environment_invalid")
    lines = [
        "# Generated local Power service capabilities. This file is gitignored.",
        "# Do not add OpenAI, Gemini, DeepSeek, cookies, or flags here.",
        f"{_POWER_ENABLED_NAME}=true",
        f"{_SOCKET_GID_NAME}={values[_SOCKET_GID_NAME]}",
    ]
    lines.extend(f"{name}={values[name]}" for name in _TOKEN_NAMES if name in values)
    return "\n".join(lines) + "\n"


def _existing_power_names(path: Path) -> set[str]:
    """Read only variable names so a private file is never silently rotated."""

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BootstrapError("power_runtime_environment_unreadable") from exc
    names: set[str] = set()
    for line in source.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#") or "=" not in candidate:
            continue
        name, _ = candidate.split("=", maxsplit=1)
        if name in {*_CORE_POWER_NAMES, _SOCKET_GID_NAME}:
            names.add(name)
    return names


def append_power_environment(path: Path) -> None:
    """Create or append Power-only values without replacing an existing value."""

    if path != DEFAULT_ENV_PATH:
        raise BootstrapError("power_runtime_environment_path_invalid")
    existing: set[str] = set()
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as exc:
        raise BootstrapError("power_runtime_environment_unreadable") from exc

    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BootstrapError("power_runtime_environment_not_regular")
        existing = _existing_power_names(path)
        if set(_LEGACY_POWER_NAMES).intersection(existing):
            # P8 originally generated three Power service capabilities. M-PI-2
            # adds a distinct Pi Runner capability. Upgrade only this complete
            # legacy shape; existing values are never read or rotated.
            if set(_LEGACY_POWER_NAMES).issubset(existing):
                _append_missing_runtime_values(
                    path,
                    missing_names=({_SOCKET_GID_NAME, "CTFMESH_INTERNAL_RUNNER_TOKEN"} - existing),
                )
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                return
            raise BootstrapError("power_runtime_environment_already_configured")

    # The M6 profile may already own the generic runner capability. Preserve
    # it by name only; this process never reads or prints its secret value.
    omitted_names = frozenset({"CTFMESH_INTERNAL_RUNNER_TOKEN"}.intersection(existing))
    generated = build_power_environment()
    for name in omitted_names:
        generated.pop(name)
    rendered = render_power_environment(generated, omitted_names=omitted_names)
    flags = os.O_WRONLY | os.O_CREAT
    if metadata is None:
        flags |= os.O_EXCL
        prefix = ""
    else:
        flags |= os.O_APPEND
        prefix = "\n"
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | nofollow, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        raise BootstrapError("power_runtime_environment_write_failed") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(prefix + rendered)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        raise
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _append_missing_runtime_values(path: Path, *, missing_names: set[str]) -> None:
    """Add M-PI-2 upgrade values without reading existing capabilities."""

    accepted = {_SOCKET_GID_NAME, "CTFMESH_INTERNAL_RUNNER_TOKEN"}
    if not missing_names.issubset(accepted):
        raise BootstrapError("power_runtime_environment_invalid")
    if not missing_names:
        raise BootstrapError("power_runtime_environment_already_configured")
    values: dict[str, str] = {}
    if _SOCKET_GID_NAME in missing_names:
        values[_SOCKET_GID_NAME] = _docker_socket_gid()
    if "CTFMESH_INTERNAL_RUNNER_TOKEN" in missing_names:
        values["CTFMESH_INTERNAL_RUNNER_TOKEN"] = secrets.token_urlsafe(_TOKEN_BYTES)

    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BootstrapError("power_runtime_environment_write_failed") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("".join(f"{name}={value}\n" for name, value in values.items()))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        raise


def main(argv: list[str] | None = None) -> int:
    """Append the Power-only local configuration once."""

    parser = argparse.ArgumentParser(
        description="Add private Power Compose service capabilities to .env."
    )
    parser.parse_args(argv)
    try:
        append_power_environment(DEFAULT_ENV_PATH)
    except BootstrapError as exc:
        print(f"Power runtime bootstrap failed: {exc}.", file=sys.stderr)
        return 1
    print("Power runtime configuration added to .env. Start with Docker Compose.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
