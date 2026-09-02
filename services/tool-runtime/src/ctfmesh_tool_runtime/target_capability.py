"""Short-lived exact-request capabilities for the external target connector.

Only ToolGateway can mint these HMAC-protected envelopes. Source slots can
carry a capability to the connector but cannot change its method, absolute
URL, body, run, challenge, or expiry. The connector consumes each nonce before
opening its only external socket, making a retried ambiguous request fail
closed rather than issue a second target-side effect.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MAX_TOKEN_BYTES = 4096


class TargetCapabilityError(RuntimeError):
    """A stable failure code; capability values themselves never escape."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class TargetRequestCapability:
    """Decoded, connector-only claims for exactly one target request."""

    invocation_id: str
    run_id: str
    challenge_id: str
    method: str
    url_sha256: str
    body_sha256: str
    nonce: str
    expires_at: int


def request_digest(value: bytes | str) -> str:
    """Hash canonical bytes without retaining the potentially sensitive value."""

    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    if not value or len(value) > _MAX_TOKEN_BYTES or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise TargetCapabilityError("target_capability_invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeError) as exc:
        raise TargetCapabilityError("target_capability_invalid") from exc


class TargetCapabilitySigner:
    """Issue and verify compact HMAC envelopes on the private slot boundary."""

    def __init__(self, key: str) -> None:
        if not 32 <= len(key) <= 512:
            raise ValueError("target_capability_key_invalid")
        self._key = key.encode("utf-8")

    def issue(
        self,
        *,
        invocation_id: str,
        run_id: str,
        challenge_id: str,
        method: str,
        url: str,
        body: bytes,
        ttl_seconds: int,
    ) -> str:
        """Create a one-use capability whose expiry cannot exceed one minute."""

        if not 1 <= ttl_seconds <= 60:
            raise ValueError("target_capability_ttl_invalid")
        if not all(_IDENTIFIER.fullmatch(value) for value in (invocation_id, run_id, challenge_id)):
            raise ValueError("target_capability_identifier_invalid")
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("target_capability_method_invalid")
        payload = {
            "v": 1,
            "invocation_id": invocation_id,
            "run_id": run_id,
            "challenge_id": challenge_id,
            "method": method,
            "url_sha256": request_digest(url),
            "body_sha256": request_digest(body),
            "nonce": uuid4().hex,
            "expires_at": int(time.time()) + ttl_seconds,
        }
        encoded = _encode(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        signature = hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{encoded}.{signature}"

    def verify(self, token: str, *, now: int | None = None) -> TargetRequestCapability:
        """Verify syntax, signature and expiry without reflecting token content."""

        if not isinstance(token, str) or len(token) > _MAX_TOKEN_BYTES or token.count(".") != 1:
            raise TargetCapabilityError("target_capability_invalid")
        encoded, signature = token.split(".", maxsplit=1)
        if not re.fullmatch(r"[a-f0-9]{64}", signature):
            raise TargetCapabilityError("target_capability_invalid")
        expected = hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise TargetCapabilityError("target_capability_invalid")
        try:
            payload: Any = json.loads(_decode(encoded))
        except (TypeError, json.JSONDecodeError) as exc:
            raise TargetCapabilityError("target_capability_invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "v",
            "invocation_id",
            "run_id",
            "challenge_id",
            "method",
            "url_sha256",
            "body_sha256",
            "nonce",
            "expires_at",
        }:
            raise TargetCapabilityError("target_capability_invalid")
        values = (
            payload.get("invocation_id"),
            payload.get("run_id"),
            payload.get("challenge_id"),
            payload.get("nonce"),
        )
        if not all(isinstance(value, str) and _IDENTIFIER.fullmatch(value) for value in values):
            raise TargetCapabilityError("target_capability_invalid")
        method = payload.get("method")
        url_sha256 = payload.get("url_sha256")
        body_sha256 = payload.get("body_sha256")
        expires_at = payload.get("expires_at")
        if (
            method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
            or not isinstance(url_sha256, str)
            or _SHA256.fullmatch(url_sha256) is None
            or not isinstance(body_sha256, str)
            or _SHA256.fullmatch(body_sha256) is None
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
        ):
            raise TargetCapabilityError("target_capability_invalid")
        current = int(time.time()) if now is None else now
        if expires_at < current or expires_at > current + 61:
            raise TargetCapabilityError("target_capability_expired")
        return TargetRequestCapability(
            invocation_id=payload["invocation_id"],
            run_id=payload["run_id"],
            challenge_id=payload["challenge_id"],
            method=method,
            url_sha256=url_sha256,
            body_sha256=body_sha256,
            nonce=payload["nonce"],
            expires_at=expires_at,
        )


__all__ = [
    "TargetCapabilityError",
    "TargetCapabilitySigner",
    "TargetRequestCapability",
    "request_digest",
]
