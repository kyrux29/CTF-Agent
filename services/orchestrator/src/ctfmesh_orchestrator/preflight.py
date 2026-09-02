"""Deterministic, read-only source preflight for the durable run kernel.

This module never extracts an archive, executes a file, invokes a model, or
opens the target network. A caller may supply only a control-plane-selected
source root; all operator-facing payloads are redacted and bounded before they
become immutable observation artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ctfmesh_domain import ChallengeManifest, PreflightObservationKind

MAX_PREFLIGHT_FILES = 512
MAX_PREFLIGHT_FILE_BYTES = 512 * 1024
MAX_SOURCE_SNIPPETS = 3
MAX_SNIPPET_CHARS = 800
MAX_ROUTE_HINTS = 64
MAX_DEPENDENCY_HINTS = 64

_TEXT_EXTENSIONS = frozenset(
    {".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}
)
_DEPENDENCY_FILENAMES = frozenset(
    {
        "Cargo.toml",
        "composer.json",
        "go.mod",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
    }
)
_ROUTE_PATTERNS = (
    re.compile(
        r"(?:@|\b)(?:app|router)\.(?:get|post|put|patch|delete|route)\(\s*[\"'](?P<route>/[^\"']*)",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+(?P<route>/[A-Za-z0-9_./?&=%{}:-]*)"),
)
_IMPORT_PATTERN = re.compile(r"""(?m)^\s*(?:from|import|require)\s*[\("']*([A-Za-z0-9_.-]+)""")
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)


class PreflightError(RuntimeError):
    """Stable, non-secret failure code for unsafe source materialization."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PreflightPayload:
    """A bounded JSON body to write as one immutable observation artifact."""

    kind: PreflightObservationKind
    summary: str
    payload: dict[str, Any]


def _redact_text(value: str) -> str:
    """Remove values that must not leave a trusted source mount as evidence text."""

    value = _RAW_FLAG.sub("[REDACTED_FLAG]", value)
    value = _BEARER.sub(r"\1[REDACTED]", value)
    return _SECRET_ASSIGNMENT.sub("[REDACTED_SECRET_ASSIGNMENT]", value)


def _safe_source_files(source_root: Path | None) -> tuple[tuple[str, Path], ...]:
    """Enumerate only regular non-symlink files under a control-plane root."""

    if source_root is None:
        return ()
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise PreflightError("preflight_source_root_missing") from exc
    if not root.is_dir():
        raise PreflightError("preflight_source_root_not_directory")

    selected: list[tuple[str, Path]] = []
    try:
        candidates = sorted(root.rglob("*"), key=lambda path: path.as_posix())
    except OSError as exc:
        raise PreflightError("preflight_source_enumeration_failed") from exc
    for candidate in candidates:
        if len(selected) >= MAX_PREFLIGHT_FILES:
            break
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=True)
            if root not in resolved.parents:
                raise PreflightError("preflight_source_path_escape")
            relative = resolved.relative_to(root).as_posix()
        except OSError as exc:
            raise PreflightError("preflight_source_enumeration_failed") from exc
        selected.append((relative, resolved))
    return tuple(selected)


def _read_bounded_text(path: Path) -> str | None:
    if path.suffix.lower() not in _TEXT_EXTENSIONS and path.name not in _DEPENDENCY_FILENAMES:
        return None
    try:
        with path.open("rb") as stream:
            payload = stream.read(MAX_PREFLIGHT_FILE_BYTES + 1)
    except OSError as exc:
        raise PreflightError("preflight_source_read_failed") from exc
    if b"\x00" in payload:
        return None
    return _redact_text(payload[:MAX_PREFLIGHT_FILE_BYTES].decode("utf-8", errors="replace"))


def _file_record(relative: str, path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
        with path.open("rb") as stream:
            payload = stream.read(MAX_PREFLIGHT_FILE_BYTES + 1)
    except OSError as exc:
        raise PreflightError("preflight_source_read_failed") from exc
    return {
        "path": relative,
        "size_bytes": stat.st_size,
        "extension": path.suffix.lower() or "[none]",
        "sample_sha256": hashlib.sha256(payload[:MAX_PREFLIGHT_FILE_BYTES]).hexdigest(),
        "truncated": len(payload) > MAX_PREFLIGHT_FILE_BYTES,
    }


def _route_hints(texts: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for relative, text in texts:
        for pattern in _ROUTE_PATTERNS:
            for match in pattern.finditer(text):
                route = match.group("route")[:240]
                key = (relative, route)
                if key in seen:
                    continue
                seen.add(key)
                hints.append({"file": relative, "route": route})
                if len(hints) >= MAX_ROUTE_HINTS:
                    return hints
    return hints


def _dependency_hints(texts: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for relative, text in texts:
        filename = Path(relative).name
        if filename in _DEPENDENCY_FILENAMES:
            signal = f"manifest:{filename}"
            if (relative, signal) not in seen:
                seen.add((relative, signal))
                hints.append({"file": relative, "signal": signal})
        for match in _IMPORT_PATTERN.finditer(text):
            signal = f"import:{match.group(1)[:120]}"
            if (relative, signal) in seen:
                continue
            seen.add((relative, signal))
            hints.append({"file": relative, "signal": signal})
            if len(hints) >= MAX_DEPENDENCY_HINTS:
                return hints
    return hints[:MAX_DEPENDENCY_HINTS]


class DeterministicPreflight:
    """Turn a manifest and optional trusted source root into evidence artifacts."""

    def inspect(
        self,
        *,
        challenge_digest: str,
        manifest: ChallengeManifest,
        source_root: Path | None = None,
    ) -> tuple[PreflightPayload, ...]:
        """Create stable, bounded, redacted observations without executing input."""

        if len(challenge_digest) != 64 or any(
            char not in "0123456789abcdef" for char in challenge_digest
        ):
            raise PreflightError("preflight_challenge_digest_invalid")
        declared_artifacts = [
            {"path": artifact.path, "role": artifact.role.value}
            for artifact in manifest.spec.artifacts
        ]
        source_files = _safe_source_files(source_root)
        records = [_file_record(relative, path) for relative, path in source_files]
        texts = [
            (relative, text)
            for relative, path in source_files
            if (text := _read_bounded_text(path)) is not None
        ]
        histogram = Counter(record["extension"] for record in records)
        routes = _route_hints(texts)
        dependencies = _dependency_hints(texts)
        snippets = [
            {"file": relative, "text": text[:MAX_SNIPPET_CHARS]}
            for relative, text in texts[:MAX_SOURCE_SNIPPETS]
        ]
        source_mode = "trusted_source_root" if source_root is not None else "manifest_only"
        return (
            PreflightPayload(
                kind=PreflightObservationKind.ARCHIVE_MANIFEST,
                summary=f"Declared {len(declared_artifacts)} challenge artifact(s).",
                payload={
                    "schema": "ctfmesh.preflight.archive-manifest/v1",
                    "challenge_digest": challenge_digest,
                    "declared_artifacts": declared_artifacts,
                },
            ),
            PreflightPayload(
                kind=PreflightObservationKind.FILE_INVENTORY,
                summary=f"Inventoried {len(records)} regular file(s) from {source_mode}.",
                payload={
                    "schema": "ctfmesh.preflight.file-inventory/v1",
                    "source_mode": source_mode,
                    "files": records,
                    "declared_only": source_root is None,
                },
            ),
            PreflightPayload(
                kind=PreflightObservationKind.EXTENSION_HISTOGRAM,
                summary=f"Observed {len(histogram)} file extension group(s).",
                payload={
                    "schema": "ctfmesh.preflight.extension-histogram/v1",
                    "extensions": [
                        {"extension": extension, "count": histogram[extension]}
                        for extension in sorted(histogram)
                    ],
                },
            ),
            PreflightPayload(
                kind=PreflightObservationKind.ROUTE_HEURISTIC,
                summary=f"Detected {len(routes)} route heuristic(s); none are execution claims.",
                payload={
                    "schema": "ctfmesh.preflight.route-heuristic/v1",
                    "routes": routes,
                },
            ),
            PreflightPayload(
                kind=PreflightObservationKind.DEPENDENCY_HEURISTIC,
                summary=f"Detected {len(dependencies)} dependency heuristic(s).",
                payload={
                    "schema": "ctfmesh.preflight.dependency-heuristic/v1",
                    "dependencies": dependencies,
                },
            ),
            PreflightPayload(
                kind=PreflightObservationKind.REDACTED_SOURCE_SNIPPETS,
                summary=f"Captured {len(snippets)} bounded redacted source snippet(s).",
                payload={
                    "schema": "ctfmesh.preflight.redacted-source-snippets/v1",
                    "snippets": snippets,
                },
            ),
        )


def canonical_preflight_bytes(payload: PreflightPayload) -> bytes:
    """Serialize an observation body deterministically before content-addressing it."""

    return json.dumps(
        payload.payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "DeterministicPreflight",
    "PreflightError",
    "PreflightPayload",
    "canonical_preflight_bytes",
]
