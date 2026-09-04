"""Deterministic, redacted Markdown handoff for a verified Power solve.

The write-up is deliberately rendered from durable, metadata-only receipts.
It never asks a provider for another turn after a solve and never reads an
artifact body.  This keeps the winning racer attributable without allowing a
candidate, raw flag, prompt, terminal output, or credential to enter a
downloaded handoff document.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any, Final

_RACER_LABELS: Final[frozenset[str]] = frozenset({"A", "B", "C"})
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_CATEGORY = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SAFE_TITLE_CHARS = re.compile(r"[^A-Za-z0-9 ._/-]+")
_SAFE_WHITESPACE = re.compile(r"\s+")
_MAX_TIMELINE_ITEMS: Final[int] = 24

_ACTION_SUMMARIES: Final[dict[str, str]] = {
    "ctf_artifact_read": "Re-read a retained sandbox observation.",
    "ctf_fs_list": "Listed the scoped challenge workspace.",
    "ctf_fs_read": "Read scoped challenge evidence.",
    "ctf_fs_write": "Prepared a retained local proof artifact.",
    "ctf_gdb_cmd": "Performed a bounded debugger interaction.",
    "ctf_gdb_read": "Read a bounded debugger result.",
    "ctf_gdb_start": "Started a scoped debugger session.",
    "ctf_pty_close": "Closed a scoped terminal session.",
    "ctf_pty_read": "Read a bounded terminal result.",
    "ctf_pty_send": "Sent a bounded terminal input.",
    "ctf_pty_start": "Started a scoped terminal session.",
    "ctf_shell_exec": "Ran a bounded sandbox analysis command.",
    "ctf_tube_connect": "Opened a manifest-scoped target connection.",
    "ctf_tube_recv": "Read a bounded target response.",
    "ctf_tube_send": "Sent a bounded target request.",
}


class PowerWriteupUnavailable(ValueError):
    """The run has no durable, checker-backed racer provenance."""


def render_power_writeup(
    *,
    run: Mapping[str, Any],
    challenge: Mapping[str, Any] | None,
    events: Iterable[Mapping[str, Any]],
) -> str:
    """Render an exportable Markdown handoff after an independent solve.

    The confirmation event is the only accepted winning-racer source.  It is
    appended only after flag-router accepts an observed candidate, so model
    prose and unreviewed candidates cannot create a write-up that looks like
    a verified solve.
    """

    if run.get("provider") != "power-swarm" or run.get("status") != "solved":
        raise PowerWriteupUnavailable("power_writeup_run_not_verified")

    event_rows = tuple(event for event in events if isinstance(event, Mapping))
    racer = _confirmed_racer(event_rows)
    if racer is None:
        raise PowerWriteupUnavailable("power_writeup_source_unavailable")

    title = _challenge_title(challenge)
    category = _challenge_category(challenge)
    run_id = _run_id(run.get("id"))
    solved_date = _solved_date(run.get("updated_at") or run.get("created_at"))
    timeline = _racer_timeline(event_rows, racer)

    lines = [
        "---",
        f'title: "{title}"',
        f"date: {solved_date}",
        f"category: {category}",
        f"source_racer: {racer}",
        f"run_id: {run_id}",
        "status: solved",
        "---",
        "",
        f"# {title}",
        "",
        "## Summary",
        "",
        (
            f"Power Racer {racer} produced the observed candidate that the "
            "independent verifier accepted."
        ),
        "The control plane then fenced every Power racer and marked this run solved.",
        "",
        "## Verified outcome",
        "",
        (
            "The result is checker-backed, not a model claim. The candidate "
            "and raw flag are intentionally excluded from this export."
        ),
        (
            "Use the explicit one-time local reveal in CTFMesh when the value "
            "is required for submission."
        ),
        "",
        "## Winning racer evidence timeline",
        "",
    ]
    if timeline:
        lines.extend(f"{index}. {entry}" for index, entry in enumerate(timeline, start=1))
    else:
        lines.append(
            "1. The durable confirmation links Racer "
            + racer
            + " to an independently accepted observation."
        )
    lines.extend(
        (
            "",
            "## Reproduction and handoff",
            "",
            (
                "Reproduce only inside the same authorized CTF scope. Start from "
                "the retained immutable observations for this run and independently "
                "verify each step before reuse."
            ),
            (
                "Do not treat this compact handoff as a substitute for the verifier "
                "or as authority to expand target scope."
            ),
            "",
            "## Sensitive values",
            "",
            (
                "This document contains no raw flag, candidate, command, terminal "
                "output, provider prompt, model response, credential, cookie, or "
                "target endpoint."
            ),
        )
    )
    return "\n".join(lines) + "\n"


def _confirmed_racer(events: Iterable[Mapping[str, Any]]) -> str | None:
    """Return the last fixed racer label from a router-backed confirmation."""

    racer: str | None = None
    for event in events:
        if event.get("type") != "power.candidate.review.confirmed":
            continue
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            continue
        label = payload.get("label")
        if isinstance(label, str) and label in _RACER_LABELS:
            racer = label
    return racer


def _racer_timeline(events: Iterable[Mapping[str, Any]], racer: str) -> tuple[str, ...]:
    """Use fixed action vocabulary so trace content cannot enter Markdown."""

    entries: list[str] = []
    for event in events:
        if event.get("type") != "power.command.observed":
            continue
        payload = event.get("payload")
        if not isinstance(payload, Mapping) or payload.get("label") != racer:
            continue
        action = payload.get("action_type")
        if not isinstance(action, str):
            continue
        summary = _ACTION_SUMMARIES.get(action)
        if summary is None:
            continue
        turn_count = payload.get("turn_count")
        if isinstance(turn_count, int) and not isinstance(turn_count, bool) and turn_count > 0:
            entries.append(f"Turn {turn_count}: {summary}")
        else:
            entries.append(summary)
    return tuple(entries[-_MAX_TIMELINE_ITEMS:])


def _challenge_title(challenge: Mapping[str, Any] | None) -> str:
    value = challenge.get("name") if challenge is not None else None
    if not isinstance(value, str):
        return "CTFMesh Power challenge"
    title = _SAFE_WHITESPACE.sub(" ", _SAFE_TITLE_CHARS.sub(" ", value)).strip()
    return title[:120] or "CTFMesh Power challenge"


def _challenge_category(challenge: Mapping[str, Any] | None) -> str:
    manifest = challenge.get("manifest") if challenge is not None else None
    metadata = manifest.get("metadata") if isinstance(manifest, Mapping) else None
    category = metadata.get("category") if isinstance(metadata, Mapping) else None
    if isinstance(category, str) and _SAFE_CATEGORY.fullmatch(category):
        return category
    return "misc"


def _run_id(value: Any) -> str:
    return value if isinstance(value, str) and _SAFE_RUN_ID.fullmatch(value) else "unknown"


def _solved_date(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    if parsed.tzinfo is None:
        return "unknown"
    return parsed.astimezone(UTC).date().isoformat()
