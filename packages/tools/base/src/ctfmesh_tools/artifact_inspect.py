"""Bounded, read-only inspection for opaque CTF challenge artifacts.

This module intentionally does not invoke external binaries, unpack archives, or
execute a parser supplied by a challenge.  It provides a small, deterministic
fingerprint that a category-specific skill or model can reason over safely.
"""

from __future__ import annotations

import hashlib
import math
import re
import stat
from collections import Counter
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field, field_validator

from ._compat import ToolRisk
from .contracts import ToolContractModel, ToolInvocationContext, ToolSpec
from .files import WorkspaceFileError, _resolve_path, _validate_relative_path

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER_TOKEN = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)


class ArtifactInspectInput(ToolContractModel):
    """A bounded request for static artifact metadata only."""

    path: str
    max_file_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_header_bytes: int = Field(default=64, ge=1, le=4096)
    max_strings: int = Field(default=64, ge=1, le=512)
    max_string_bytes: int = Field(default=256, ge=4, le=4096)

    _safe_path = field_validator("path")(_validate_relative_path)


class ArtifactInspectOutput(ToolContractModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    media_hint: str
    classification: Literal["text", "binary"]
    entropy_bits_per_byte: float = Field(ge=0, le=8)
    header_hex: str = Field(pattern=r"^[0-9a-f]*$")
    printable_strings: tuple[str, ...]
    strings_truncated: bool


class ArtifactInspectTool:
    """Fingerprint a regular workspace file without executing or unpacking it."""

    input_model: ClassVar[type[ArtifactInspectInput]] = ArtifactInspectInput
    output_model: ClassVar[type[ArtifactInspectOutput]] = ArtifactInspectOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="artifacts.inspect",
        version="1.0.0",
        description=(
            "Read bounded static metadata, magic bytes, entropy, and redacted printable strings "
            "from one regular challenge artifact. It never executes or unpacks the file."
        ),
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=ArtifactInspectInput,
        output_model=ArtifactInspectOutput,
        required_capabilities=("artifact.inspection",),
        default_timeout_seconds=10,
        max_output_bytes=512 * 1024,
    )

    def requested_url(self, request: ArtifactInspectInput) -> None:
        del request
        return None

    def requested_path(
        self,
        request: ArtifactInspectInput,
        context: ToolInvocationContext,
    ) -> str:
        del context
        return request.path

    async def invoke(
        self,
        request: ArtifactInspectInput,
        context: ToolInvocationContext,
    ) -> ArtifactInspectOutput:
        path = _resolve_path(context, request.path, expected="file")
        payload = self._read_regular_file(path, max_file_bytes=request.max_file_bytes)
        printable, truncated = _extract_printable_strings(
            payload,
            max_strings=request.max_strings,
            max_string_bytes=request.max_string_bytes,
        )
        return ArtifactInspectOutput(
            path=request.path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            media_hint=_media_hint(payload),
            classification="text" if _is_probably_text(payload) else "binary",
            entropy_bits_per_byte=round(_entropy(payload), 6),
            header_hex=_redacted_header_hex(payload, max_header_bytes=request.max_header_bytes),
            printable_strings=printable,
            strings_truncated=truncated,
        )

    @staticmethod
    def _read_regular_file(path: Path, *, max_file_bytes: int) -> bytes:
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise WorkspaceFileError("artifact cannot be inspected") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise WorkspaceFileError("special devices and non-regular files are denied")
        if metadata.st_size > max_file_bytes:
            raise WorkspaceFileError("artifact exceeds the configured byte limit")
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise WorkspaceFileError("artifact cannot be read") from exc
        if len(payload) > max_file_bytes:
            raise WorkspaceFileError("artifact exceeds the configured byte limit")
        return payload


def _media_hint(payload: bytes) -> str:
    signatures: tuple[tuple[bytes, str], ...] = (
        (b"\x7fELF", "application/x-elf"),
        (b"MZ", "application/vnd.microsoft.portable-executable"),
        (b"%PDF-", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b", "application/gzip"),
        (b"SQLite format 3\x00", "application/x-sqlite3"),
        (b"\xca\xfe\xba\xbe", "application/x-java-class"),
        (b"dex\n", "application/vnd.android.dex"),
        (b"\xd4\xc3\xb2\xa1", "application/vnd.tcpdump.pcap"),
        (b"\xa1\xb2\xc3\xd4", "application/vnd.tcpdump.pcap"),
        (b"\x4d\x3c\xb2\xa1", "application/vnd.tcpdump.pcap"),
        (b"\xa1\xb2\x3c\x4d", "application/vnd.tcpdump.pcap"),
    )
    for prefix, media_type in signatures:
        if payload.startswith(prefix):
            return media_type
    return "text/plain" if _is_probably_text(payload) else "application/octet-stream"


def _is_probably_text(payload: bytes) -> bool:
    if not payload:
        return True
    if b"\x00" in payload:
        return False
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(character.isprintable() or character.isspace() for character in decoded)
    return printable / max(1, len(decoded)) >= 0.9


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    length = len(payload)
    return -sum((count / length) * math.log2(count / length) for count in Counter(payload).values())


def _extract_printable_strings(
    payload: bytes,
    *,
    max_strings: int,
    max_string_bytes: int,
) -> tuple[tuple[str, ...], bool]:
    strings: list[str] = []
    truncated = False
    for match in _PRINTABLE_RUN.finditer(payload):
        if len(strings) >= max_strings:
            truncated = True
            break
        raw = match.group(0)[:max_string_bytes]
        if len(match.group(0)) > max_string_bytes:
            truncated = True
        strings.append(_redact_printable(raw.decode("ascii", errors="ignore")))
    return tuple(strings), truncated


def _redact_printable(value: str) -> str:
    value = _RAW_FLAG.sub("[REDACTED_FLAG]", value)
    value = _BEARER_TOKEN.sub(r"\1[REDACTED]", value)
    value = _OPENAI_KEY.sub("[REDACTED_API_KEY]", value)
    return _SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", value)


def _redacted_header_hex(payload: bytes, *, max_header_bytes: int) -> str:
    """Keep binary signature bytes while blanking secret runs crossing the header boundary."""

    safe_header = bytearray(payload[:max_header_bytes])
    for match in _PRINTABLE_RUN.finditer(payload):
        raw = match.group(0)
        value = raw.decode("ascii", errors="ignore")
        if _redact_printable(value) != value:
            start = max(0, match.start())
            end = min(max_header_bytes, match.end())
            if start < end:
                safe_header[start:end] = b"\x00" * (end - start)
    return bytes(safe_header).hex()


__all__ = [
    "ArtifactInspectInput",
    "ArtifactInspectOutput",
    "ArtifactInspectTool",
]
