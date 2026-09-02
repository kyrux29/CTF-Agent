"""Result normalization and redaction before tool evidence is persisted.

Slots may observe untrusted source bytes.  Their output never goes directly to
the database or Pi: this module creates a JSON-compatible, bounded record that
removes flags and common credential material first.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from pydantic import BaseModel

from .contracts import GatewayToolCall, HttpRequestCall, TransformApplyCall, validate_output

_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_GEMINI_KEY = re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|authorization|cookie|password|secret|token)\s*[:=]\s*[^\s,;]+"
)
_SECRET_KEY_MARKERS = frozenset(
    {"api_key", "apikey", "authorization", "cookie", "password", "secret", "token", "flag"}
)


class ToolOutputNormalizationError(ValueError):
    """Stable failure raised when a slot result cannot become safe evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def normalize_output(call: GatewayToolCall, output: BaseModel | object) -> BaseModel:
    """Redact output recursively, then enforce the original typed schema again."""

    if isinstance(output, BaseModel):
        raw: object = output.model_dump(mode="json")
    else:
        raw = output
    normalized = _redact_json(raw)
    if isinstance(call, TransformApplyCall):
        normalized = _repair_transform_metadata(normalized)
    if isinstance(call, HttpRequestCall):
        normalized = _repair_http_observation_metadata(normalized)
    try:
        return validate_output(call, normalized)
    except ValueError as exc:
        # Redaction must never make a malformed/unknown slot response look
        # acceptable. The gateway records only this code, not the error text.
        raise ToolOutputNormalizationError("tool_output_normalization_failed") from exc


def canonical_output_bytes(output: BaseModel) -> tuple[bytes, str]:
    """Return canonical artifact bytes and their content address."""

    try:
        encoded = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ToolOutputNormalizationError("tool_output_not_json") from exc
    return encoded, hashlib.sha256(encoded).hexdigest()


def observation_summary(call: GatewayToolCall) -> str:
    """Use a fixed summary so events never echo source/target-derived text."""

    return f"Normalized {call.tool_name} observation stored as immutable evidence."


def _redact_json(value: object, *, key: str | None = None) -> object:
    if key is not None and _is_secret_key(key):
        return "[REDACTED]"
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_json(child, key=str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, list | tuple):
        return [_redact_json(child) for child in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    # The declared tool output models should already contain JSON values. Do
    # not stringify an unexpected object because it could call attacker code.
    raise ToolOutputNormalizationError("tool_output_not_json")


def _is_secret_key(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    if normalized in _SECRET_KEY_MARKERS:
        return True
    # Keep harmless metadata such as ``cookie_count`` and ``token_digest``
    # typed, while still redacting common compound secret fields and response
    # headers such as ``set-cookie`` or ``x-api-key``.
    return normalized.endswith(
        (
            "_api_key",
            "_apikey",
            "_authorization",
            "_cookie",
            "_password",
            "_secret",
            "_token",
            "_flag",
        )
    )


def _redact_text(value: str) -> str:
    value = _RAW_FLAG.sub("[REDACTED_FLAG]", value)
    value = _BEARER.sub(r"\1[REDACTED]", value)
    value = _OPENAI_KEY.sub("[REDACTED_API_KEY]", value)
    value = _GEMINI_KEY.sub("[REDACTED_API_KEY]", value)
    return _SECRET_ASSIGNMENT.sub(r"\1=[REDACTED]", value)


def _repair_transform_metadata(value: object) -> object:
    """Make a redacted transform result self-consistent before validation.

    A transform's displayed text can lose a flag or credential during gateway
    normalization. Its digest and byte count must describe those safe bytes,
    not the pre-redaction value that is never persisted or returned to Pi.
    """

    if not isinstance(value, dict):
        raise ToolOutputNormalizationError("tool_output_not_json")
    output_text = value.get("output_text")
    if not isinstance(output_text, str):
        raise ToolOutputNormalizationError("tool_output_not_json")
    output_bytes = output_text.encode("utf-8")
    return {
        **value,
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "output_size_bytes": len(output_bytes),
    }


def _repair_http_observation_metadata(value: object) -> object:
    """Make displayed HTTP-body metadata match post-redaction evidence bytes."""

    if not isinstance(value, dict):
        raise ToolOutputNormalizationError("tool_output_not_json")
    body_text = value.get("body_text")
    if not isinstance(body_text, str):
        raise ToolOutputNormalizationError("tool_output_not_json")
    body = body_text.encode("utf-8")
    return {
        **value,
        "body_text_sha256": hashlib.sha256(body).hexdigest(),
        "body_text_size_bytes": len(body),
    }


__all__ = [
    "ToolOutputNormalizationError",
    "canonical_output_bytes",
    "normalize_output",
    "observation_summary",
]
