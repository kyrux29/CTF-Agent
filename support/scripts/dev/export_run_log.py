#!/usr/bin/env python3
"""Export one Power run as a readable trace for local review.

A run's evidence is split across three places by design: the append-only event
ledger holds the ordered facts, the content-addressed store holds each full
observation, and Pi keeps its own transcript in the runner volume. Reading a
run therefore meant three separate queries and a container exec, which is why
reviewing a failure usually turned into archaeology.

This assembles the first two into one chronological file. It is a host-only
developer utility: it reads the local Compose database and artifact volume
directly and never contacts a provider or a target.

Raw observation bytes are included only with --with-output, because an
observation can contain a flag, and the same reason the reveal routes require
an explicit operator act applies to a file written to disk.

    python3 support/scripts/dev/export_run_log.py <run_id> [--with-output] [-o FILE]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess  # noqa: S404 - fixed local Compose commands, never model input
import sys
from pathlib import Path

# `psql -c` takes no bind parameters, so the identifier is validated instead of
# quoted. Run ids are opaque and generated, and this is the only value that
# reaches a query.
_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")
_ARTIFACT_DIGEST = re.compile(r"^[0-9a-f]{64}$")

_EVENTS_SQL_HEAD = (
    "SELECT json_agg(row_to_json(e) ORDER BY e.sequence) FROM ("
    "  SELECT sequence, created_at, event_type, payload FROM run_events "
)
_EVENTS_SQL_TAIL = ") e"


def _docker() -> str:
    resolved = shutil.which("docker")
    if resolved is None:
        raise SystemExit("docker is not on PATH; run this from the repository host")
    return resolved


def _psql(sql: str, **variables: str) -> str:
    """Run one read-only query through the Compose postgres service.

    Values are passed as psql variables and referenced as ``:'name'``, so the
    query text stays constant and nothing is interpolated into SQL.
    """

    assignments: list[str] = []
    for name, value in variables.items():
        assignments.extend(("-v", f"{name}={value}"))
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            _docker(),
            "compose",
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "ctfmesh",
            "-d",
            "ctfmesh",
            "-At",
            *assignments,
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"query failed: {completed.stderr.strip()[:400]}")
    return completed.stdout


def _artifact_bytes(artifact_id: str) -> str:
    """Read one observation from the local CAS through the api container."""

    digest = artifact_id.removeprefix("sha256:")
    if _ARTIFACT_DIGEST.fullmatch(digest) is None:
        return "(invalid artifact id)"
    path = f"/data/artifacts/objects/sha256/{digest[:2]}/{digest[2:4]}/{digest}"
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, validated digest
        [_docker(), "compose", "exec", "-T", "api", "cat", path],
        capture_output=True,
        text=False,
        check=False,
    )
    if completed.returncode != 0:
        return "(artifact unavailable)"
    return completed.stdout.decode("utf-8", errors="replace")


def _events(run_id: str) -> list[dict[str, object]]:
    if _RUN_ID.fullmatch(run_id) is None:
        raise SystemExit(f"not a run id: {run_id!r}")
    # `psql -c` performs no variable substitution, so the identifier is
    # interpolated. `_RUN_ID` above is the control: it admits only an opaque
    # generated id, and this is the sole value that reaches a query.
    where = f"WHERE run_id = '{run_id}'"
    query = _EVENTS_SQL_HEAD + where + _EVENTS_SQL_TAIL  # noqa: S608 - see _RUN_ID
    raw = _psql(query).strip()
    if not raw or raw == "\\N":
        raise SystemExit(f"no events for run {run_id}")
    parsed = json.loads(raw)
    return list(parsed or [])


def _render(events: list[dict[str, object]], *, with_output: bool) -> str:
    lines: list[str] = []
    for event in events:
        payload = event.get("payload") or {}
        if not isinstance(payload, dict):
            payload = {}
        kind = str(event.get("event_type"))
        when = str(event.get("created_at"))[:19]
        label = str(payload.get("label") or payload.get("racer") or "-")

        if kind == "power.pi.tool_transcript":
            lines.append(f"\n[{when}] {label}  {payload.get('tool')}")
            lines.append(f"  $ {payload.get('command')}")
            output = str(payload.get("output") or "")
            for line in output.splitlines()[:40]:
                lines.append(f"  | {line}")
        elif kind == "power.pi.activity":
            if payload.get("message_kind") != "response":
                continue
            lines.append(f"\n[{when}] {label}  REASONING")
            for line in str(payload.get("content") or "").splitlines():
                lines.append(f"  > {line}")
        elif kind == "power.command.observed" and with_output:
            artifact = payload.get("observation_artifact_id")
            if isinstance(artifact, str):
                lines.append(f"\n[{when}] {label}  FULL OBSERVATION {artifact}")
                for line in _artifact_bytes(artifact).splitlines()[:200]:
                    lines.append(f"  | {line}")
        elif kind in {"run.state.changed", "power.sessions.idle", "power.pi.session.failed"}:
            lines.append(f"\n[{when}] ** {kind}: {json.dumps(payload, ensure_ascii=False)}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument(
        "--with-output",
        action="store_true",
        help="include full observation bytes; an observation can contain a flag",
    )
    parser.add_argument("-o", "--out", type=Path, help="write to this file instead of stdout")
    args = parser.parse_args()

    events = _events(args.run_id)
    header = [
        f"# Power run {args.run_id}",
        f"# {len(events)} events"
        + ("" if args.with_output else "  (run with --with-output for full observations)"),
    ]
    body = "\n".join(header) + _render(events, with_output=args.with_output) + "\n"

    if args.out is None:
        sys.stdout.write(body)
    else:
        args.out.write_text(body, encoding="utf-8")
        print(f"wrote {args.out} ({len(body):,} bytes, {len(events)} events)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
