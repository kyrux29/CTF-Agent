"""Small, pure, allowlisted text transforms for the M3 fixed slots.

This catalog deliberately accepts text in and text out.  It does not execute
code, invoke a system utility, unpack an archive, read a path, or make a
network request.  Keeping the transform names closed and the byte limits
small makes the operation useful for common CTF encodings without creating an
arbitrary interpreter inside a sandbox slot.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import ClassVar, Literal
from urllib.parse import quote, unquote

from pydantic import Field, field_validator, model_validator

from ._compat import ToolRisk
from .contracts import ToolContractModel, ToolInputError, ToolInvocationContext, ToolSpec

_MAX_INPUT_BYTES = 32 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024
_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
type TransformName = Literal[
    "base64.decode_utf8",
    "base64.encode_utf8",
    "hex.decode_utf8",
    "hex.encode_utf8",
    "url.decode",
    "url.encode",
    "rot13",
]


class TransformApplyInput(ToolContractModel):
    """One pure transform selected from the reviewed M3 allowlist."""

    transform: TransformName
    input_text: str = Field(min_length=1, max_length=_MAX_INPUT_BYTES)
    max_output_bytes: int = Field(default=_MAX_OUTPUT_BYTES, ge=1, le=_MAX_OUTPUT_BYTES)

    @field_validator("input_text")
    @classmethod
    def _input_fits_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > _MAX_INPUT_BYTES:
            raise ValueError("transform_input_too_large")
        return value


class TransformApplyOutput(ToolContractModel):
    """A bounded, self-describing transform result.

    The output checksum is recalculated after gateway redaction before the
    result becomes evidence.  This model verifies the checksum at both the
    slot and gateway boundaries, so a slot cannot lie about its displayed
    bytes.
    """

    transform: TransformName
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_size_bytes: int = Field(ge=0, le=_MAX_INPUT_BYTES)
    output_text: str = Field(max_length=_MAX_OUTPUT_BYTES)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_size_bytes: int = Field(ge=0, le=_MAX_OUTPUT_BYTES)
    truncated: Literal[False] = False

    @field_validator("output_text")
    @classmethod
    def _output_fits_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise ValueError("transform_output_too_large")
        return value

    @model_validator(mode="after")
    def _output_metadata_matches_text(self) -> TransformApplyOutput:
        output = self.output_text.encode("utf-8")
        if self.output_size_bytes != len(output):
            raise ValueError("transform_output_size_mismatch")
        if self.output_sha256 != hashlib.sha256(output).hexdigest():
            raise ValueError("transform_output_digest_mismatch")
        return self


class TransformApplyTool:
    """Apply only deterministic text encodings and normalization transforms."""

    input_model: ClassVar[type[TransformApplyInput]] = TransformApplyInput
    output_model: ClassVar[type[TransformApplyOutput]] = TransformApplyOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="transform.apply",
        version="1.0.0",
        description="Apply one bounded, pure transform from the reviewed text allowlist.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=TransformApplyInput,
        output_model=TransformApplyOutput,
        required_capabilities=("transform.apply",),
        default_timeout_seconds=5,
        max_output_bytes=128 * 1024,
    )

    def requested_url(self, request: TransformApplyInput) -> None:
        del request
        return None

    def requested_path(
        self,
        request: TransformApplyInput,
        context: ToolInvocationContext,
    ) -> None:
        del request, context
        return None

    async def invoke(
        self,
        request: TransformApplyInput,
        context: ToolInvocationContext,
    ) -> TransformApplyOutput:
        """Transform already-bounded text without accessing the environment."""

        del context
        output_text = _apply_transform(request.transform, request.input_text)
        input_bytes = request.input_text.encode("utf-8")
        output_bytes = output_text.encode("utf-8")
        if len(output_bytes) > request.max_output_bytes:
            raise ToolInputError("transform_output_too_large")
        return TransformApplyOutput(
            transform=request.transform,
            input_sha256=hashlib.sha256(input_bytes).hexdigest(),
            input_size_bytes=len(input_bytes),
            output_text=output_text,
            output_sha256=hashlib.sha256(output_bytes).hexdigest(),
            output_size_bytes=len(output_bytes),
        )


def _apply_transform(transform: str, input_text: str) -> str:
    """Implement the closed transform set without a shell or plugin hook."""

    try:
        match transform:
            case "base64.decode_utf8":
                return base64.b64decode(input_text, validate=True).decode("utf-8")
            case "base64.encode_utf8":
                return base64.b64encode(input_text.encode("utf-8")).decode("ascii")
            case "hex.decode_utf8":
                if len(input_text) % 2 != 0 or any(
                    character not in "0123456789abcdefABCDEF" for character in input_text
                ):
                    raise ToolInputError("transform_hex_input_invalid")
                return bytes.fromhex(input_text).decode("utf-8")
            case "hex.encode_utf8":
                return input_text.encode("utf-8").hex()
            case "url.decode":
                return unquote(input_text, encoding="utf-8", errors="strict")
            case "url.encode":
                return quote(input_text, safe="", encoding="utf-8", errors="strict")
            case "rot13":
                return input_text.translate(_ROT13)
    except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError, ValueError) as exc:
        raise ToolInputError("transform_input_invalid") from exc
    # Pydantic's Literal is authoritative at the process boundary. This is a
    # defensive guard for future internal callers that bypass it accidentally.
    raise ToolInputError("transform_not_allowed")


__all__ = ["TransformApplyInput", "TransformApplyOutput", "TransformApplyTool"]
