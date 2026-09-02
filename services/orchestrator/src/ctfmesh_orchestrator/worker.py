"""Small deterministic preflight consumer used by the M2 smoke profile.

This process is intentionally separate from Pi Runner: it owns the trusted
kernel/database side of preflight and creates only sealed work. It does not run
a model, execute challenge code, or receive a target/challenge mount.
"""

from __future__ import annotations

import asyncio
import os
import re
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from ctfmesh_db import Database, Repository

from .run_engine import RunEngine, RunEngineError

_ASYNC_DATABASE_URL = re.compile(r"^(?:sqlite\+aiosqlite|postgresql\+asyncpg)://.+$")


class PreflightWorkerConfigurationError(RuntimeError):
    """A stable, secret-free startup configuration failure."""


@dataclass(frozen=True, slots=True)
class PreflightWorkerConfig:
    """Validated settings without a printable database URL representation."""

    database_url: str
    artifact_root: Path
    poll_interval_seconds: float

    def __repr__(self) -> str:
        return (
            "PreflightWorkerConfig("
            f"artifact_root={self.artifact_root!r}, "
            f"poll_interval_seconds={self.poll_interval_seconds!r})"
        )


def load_preflight_worker_config(
    environment: dict[str, str] | None = None,
) -> PreflightWorkerConfig:
    """Parse only trusted container configuration; do not log its secret DSN."""

    values = os.environ if environment is None else environment
    database_url = values.get("CTFMESH_DATABASE_URL", "").strip()
    if not _ASYNC_DATABASE_URL.fullmatch(database_url):
        raise PreflightWorkerConfigurationError("preflight_worker_database_url_invalid")
    root_text = values.get("CTFMESH_ARTIFACT_ROOT", "").strip()
    if not root_text:
        raise PreflightWorkerConfigurationError("preflight_worker_artifact_root_missing")
    artifact_root = Path(root_text)
    if not artifact_root.is_absolute():
        raise PreflightWorkerConfigurationError("preflight_worker_artifact_root_not_absolute")
    poll_text = values.get("CTFMESH_PREFLIGHT_POLL_MS", "750")
    if not poll_text.isdecimal():
        raise PreflightWorkerConfigurationError("preflight_worker_poll_interval_invalid")
    poll_milliseconds = int(poll_text)
    if not 100 <= poll_milliseconds <= 60_000:
        raise PreflightWorkerConfigurationError("preflight_worker_poll_interval_invalid")
    return PreflightWorkerConfig(
        database_url=database_url,
        artifact_root=artifact_root,
        poll_interval_seconds=poll_milliseconds / 1000,
    )


async def run_preflight_worker(config: PreflightWorkerConfig, stop: asyncio.Event) -> None:
    """Claim deterministic jobs until stopped; malformed work fails closed in the kernel."""

    database = Database(config.database_url)
    repository = Repository(database)
    engine = RunEngine(repository=repository, artifact_root=config.artifact_root)
    try:
        while not stop.is_set():
            try:
                completed = await engine.process_next_preflight(worker_id="preflight-worker")
            except RunEngineError as exc:
                # RunEngine has already persisted the secret-free failure code.
                # Do not print the caught exception's source/path details.
                print(f"[ctfmesh-preflight-worker] {exc.code}", file=sys.stderr, flush=True)
                completed = None
            except (OSError, RuntimeError):
                print(
                    "[ctfmesh-preflight-worker] preflight_worker_iteration_failed",
                    file=sys.stderr,
                    flush=True,
                )
                completed = None
            if completed is None:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=config.poll_interval_seconds)
                except TimeoutError:
                    pass
    finally:
        await database.close()


def main() -> NoReturn:
    """Container entry point with signal-driven cancellation."""

    try:
        config = load_preflight_worker_config()
    except PreflightWorkerConfigurationError as exc:
        print(f"[ctfmesh-preflight-worker] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc
    stop = asyncio.Event()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for received_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(received_signal, stop.set)
    try:
        loop.run_until_complete(run_preflight_worker(config, stop))
    finally:
        loop.close()
    raise SystemExit(0)


if __name__ == "__main__":
    # Compose invokes this module with ``python -m``. Keep the call at module
    # scope so a missing/invalid worker configuration fails closed instead of
    # silently exiting 0 before the durable preflight loop starts.
    main()
