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


def _existing_power_values(path: Path) -> dict[str, str]:
    """Read Power fields without emitting values or rotating configured capabilities."""

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BootstrapError("power_runtime_environment_unreadable") from exc
    values: dict[str, str] = {}
    known_names = {*_CORE_POWER_NAMES, _SOCKET_GID_NAME}
    for line in source.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#") or "=" not in candidate:
            continue
        name, value = candidate.split("=", maxsplit=1)
        if name in known_names:
            # Docker Compose uses the final assignment in a dotenv file. Keep
            # that same interpretation when a copied example contains blanks
            # and this bootstrap appends local Power capabilities below it.
            values[name] = value.strip()
    return values


def append_power_environment(path: Path) -> None:
    """Create or append Power-only values without replacing an existing value."""

    if path != DEFAULT_ENV_PATH:
        raise BootstrapError("power_runtime_environment_path_invalid")
    existing_values: dict[str, str] = {}
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as exc:
        raise BootstrapError("power_runtime_environment_unreadable") from exc

    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BootstrapError("power_runtime_environment_not_regular")
        existing_values = _existing_power_values(path)
        legacy_capabilities = frozenset(_LEGACY_POWER_NAMES) - {_POWER_ENABLED_NAME}
        configured_capabilities = {
            name for name in legacy_capabilities if existing_values.get(name, "")
        }
        if configured_capabilities:
            # P8 originally generated these three capabilities. Upgrade only a
            # complete existing Power configuration so a partially hand-written
            # credential set cannot be silently mixed with fresh values.
            if configured_capabilities == legacy_capabilities:
                missing_names = {
                    name
                    for name in (
                        _POWER_ENABLED_NAME,
                        _SOCKET_GID_NAME,
                        "CTFMESH_INTERNAL_RUNNER_TOKEN",
                    )
                    if not existing_values.get(name, "")
                }
                if existing_values.get(_POWER_ENABLED_NAME) != "true":
                    missing_names.add(_POWER_ENABLED_NAME)
                if not missing_names:
                    raise BootstrapError("power_runtime_environment_already_configured")
                _append_missing_runtime_values(path, missing_names=missing_names)
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                return
            raise BootstrapError("power_runtime_environment_already_configured")

        # A file with only ``CTFMESH_POWER_ENABLED=true`` is an explicit,
        # incomplete Power setup and remains a fail-closed error. In contrast,
        # blank Power fields are the standard copied ``.env.example`` template
        # and are safe for this command to complete.
        if existing_values.get(
            _POWER_ENABLED_NAME
        ) == "true" and not legacy_capabilities.intersection(existing_values):
            raise BootstrapError("power_runtime_environment_already_configured")

    # The M6 profile may already own the generic runner capability. Preserve
    # it by name only; this process never reads or prints its secret value.
    omitted_names = frozenset(
        {"CTFMESH_INTERNAL_RUNNER_TOKEN"}
        if existing_values.get("CTFMESH_INTERNAL_RUNNER_TOKEN", "")
        else set()
    )
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

    accepted = {_POWER_ENABLED_NAME, _SOCKET_GID_NAME, "CTFMESH_INTERNAL_RUNNER_TOKEN"}
    if not missing_names.issubset(accepted):
        raise BootstrapError("power_runtime_environment_invalid")
    if not missing_names:
        raise BootstrapError("power_runtime_environment_already_configured")
    values: dict[str, str] = {}
    if _POWER_ENABLED_NAME in missing_names:
        values[_POWER_ENABLED_NAME] = "true"
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
