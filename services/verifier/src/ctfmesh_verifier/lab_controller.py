"""Local M5 lab controller: random flag lifecycle and signed proof checks.

This process is intentionally small and isolated. It owns writable flag
volumes, but it never joins a worker network, has no Docker socket, and does
not expose a route that returns a flag. The verifier is the only caller that
can reset a lab or submit a fresh target-observed candidate for proof.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

LAB_IDS = frozenset({"web-path-traversal", "web-authz-boundary", "web-sqli-basic"})
_MAX_BODY_BYTES = 16 * 1024
_ED25519_KEY_BYTES = 32
_ED25519_SIGNATURE_HEX_LENGTH = 128
# The controller has no published Compose port and lives only on an internal
# bridge, so it must listen on the container interface for the verifier.
_CONTAINER_BIND_HOST = "0.0.0.0"  # noqa: S104
_ALLOWED_BIND_HOSTS = frozenset({_CONTAINER_BIND_HOST, "127.0.0.1"})


class LabControllerError(RuntimeError):
    """Stable, secret-free controller failure code."""


class LabControllerConfigurationError(LabControllerError):
    """Raised when a controller cannot start in a fail-closed configuration."""


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    """Static service configuration; secret fields are hidden from repr."""

    root: Path
    token: str = field(repr=False)
    signing_key: bytes = field(repr=False)
    bind_host: str = _CONTAINER_BIND_HOST
    bind_port: int = 8085

    def __post_init__(self) -> None:
        """Reject configurations that could expose or weaken the controller."""

        if not 16 <= len(self.token) <= 512:
            raise LabControllerConfigurationError("lab_controller_token_invalid")
        if len(self.signing_key) != _ED25519_KEY_BYTES:
            raise LabControllerConfigurationError("lab_controller_private_key_invalid")
        # Construct once during configuration validation. Ed25519 accepts all
        # 32-byte seeds, but this makes the key ownership explicit here rather
        # than falling through to a request-time signing failure.
        try:
            Ed25519PrivateKey.from_private_bytes(self.signing_key)
        except ValueError as exc:
            raise LabControllerConfigurationError("lab_controller_private_key_invalid") from exc
        if self.bind_host not in _ALLOWED_BIND_HOSTS:
            raise LabControllerConfigurationError("lab_controller_host_invalid")
        if not 1 <= self.bind_port <= 65_535:
            raise LabControllerConfigurationError("lab_controller_port_invalid")

    @classmethod
    def from_environment(cls) -> ControllerConfig:
        token = os.environ.get("CTFMESH_LAB_CONTROLLER_TOKEN", "")
        private_key_hex = os.environ.get("CTFMESH_LAB_CONTROLLER_PRIVATE_KEY", "")
        try:
            signing_key = bytes.fromhex(private_key_hex)
        except ValueError as exc:
            raise LabControllerConfigurationError("lab_controller_private_key_invalid") from exc
        root = Path(os.environ.get("CTFMESH_LAB_STATE_ROOT", "/data/labs"))
        port_text = os.environ.get("CTFMESH_LAB_CONTROLLER_PORT", "8085")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise LabControllerConfigurationError("lab_controller_port_invalid") from exc
        if not 1 <= port <= 65_535:
            raise LabControllerConfigurationError("lab_controller_port_invalid")
        return cls(
            root=root,
            token=token,
            signing_key=signing_key,
            bind_host=os.environ.get("CTFMESH_LAB_CONTROLLER_HOST", _CONTAINER_BIND_HOST),
            bind_port=port,
        )


@dataclass(frozen=True, slots=True)
class LabReset:
    """Public reset metadata that intentionally excludes the random flag."""

    lab_id: str
    generation: int
    reset_id: str
    issued_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "lab_id": self.lab_id,
            "generation": self.generation,
            "reset_id": self.reset_id,
            "issued_at": _iso(self.issued_at),
        }


@dataclass(frozen=True, slots=True)
class LabProof:
    """Controller-signed proof data with no raw candidate or raw flag."""

    lab_id: str
    generation: int
    reset_id: str
    proof_id: str
    flag_sha256: str
    issued_at: datetime
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "lab_id": self.lab_id,
            "generation": self.generation,
            "reset_id": self.reset_id,
            "proof_id": self.proof_id,
            "flag_sha256": self.flag_sha256,
            "issued_at": _iso(self.issued_at),
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "verified": True, "signature": self.signature}


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class LabControllerState:
    """Own the fixed lab-volume paths and atomically replace per-reset flags."""

    def __init__(self, config: ControllerConfig) -> None:
        self._config = config
        self._root = config.root.resolve()
        self._lock = threading.RLock()
        self._signer = Ed25519PrivateKey.from_private_bytes(config.signing_key)

    def is_authorized(self, supplied: str | None) -> bool:
        """Check the bounded controller token without exposing config internals."""

        if supplied is None or len(supplied) > 512:
            return False
        try:
            supplied_bytes = supplied.encode("utf-8")
            expected_bytes = self._config.token.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return hmac.compare_digest(supplied_bytes, expected_bytes)

    def reset(self, lab_id: str) -> LabReset:
        """Generate a unique flag and publish it atomically to one lab volume."""

        directory = self._lab_directory(lab_id)
        with self._lock:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                current_generation = int(self._read_required(directory / "generation"))
            except (FileNotFoundError, ValueError):
                current_generation = 0
            generation = current_generation + 1
            reset = LabReset(
                lab_id=lab_id,
                generation=generation,
                reset_id=f"reset_{secrets.token_hex(16)}",
                issued_at=datetime.now(UTC),
            )
            # The only raw flag handling happens in this controller memory and
            # its target-only volume. No response/event/log includes it.
            flag = f"CTF{{{secrets.token_urlsafe(24)}}}"
            self._atomic_write(directory / "flag", flag.encode("utf-8"), mode=0o444)
            self._atomic_write(
                directory / "generation", f"{generation}\n".encode("ascii"), mode=0o444
            )
            self._atomic_write(
                directory / "reset_id", f"{reset.reset_id}\n".encode("ascii"), mode=0o444
            )
            return reset

    def verify(self, *, lab_id: str, generation: int, candidate: str) -> LabProof | None:
        """Return a signed proof only when a fresh generation's flag matches."""

        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise LabControllerError("lab_generation_invalid")
        if not isinstance(candidate, str) or not candidate or len(candidate) > 1_024:
            raise LabControllerError("lab_candidate_invalid")
        directory = self._lab_directory(lab_id)
        with self._lock:
            try:
                current_generation = int(self._read_required(directory / "generation"))
                current_flag = self._read_required(directory / "flag")
                reset_id = self._read_required(directory / "reset_id")
            except (FileNotFoundError, ValueError) as exc:
                raise LabControllerError("lab_not_reset") from exc
            try:
                candidate_bytes = candidate.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise LabControllerError("lab_candidate_invalid") from exc
            if generation != current_generation or not hmac.compare_digest(
                candidate_bytes, current_flag.encode("utf-8")
            ):
                return None
            issued_at = datetime.now(UTC)
            flag_sha256 = hashlib.sha256(current_flag.encode("utf-8")).hexdigest()
            proof_material = f"{lab_id}:{generation}:{reset_id}:{flag_sha256}".encode()
            proof_id = f"proof_{hashlib.sha256(proof_material).hexdigest()[:32]}"
            unsigned = {
                "lab_id": lab_id,
                "generation": generation,
                "reset_id": reset_id,
                "proof_id": proof_id,
                "flag_sha256": flag_sha256,
                "issued_at": _iso(issued_at),
            }
            # The verifier receives only the matching public key, never this
            # seed. It therefore cannot manufacture an independent proof.
            signature = self._signer.sign(_canonical_bytes(unsigned)).hex()
            return LabProof(
                lab_id=lab_id,
                generation=generation,
                reset_id=reset_id,
                proof_id=proof_id,
                flag_sha256=flag_sha256,
                issued_at=issued_at,
                signature=signature,
            )

    def _lab_directory(self, lab_id: str) -> Path:
        if lab_id not in LAB_IDS:
            raise LabControllerError("lab_id_not_allowed")
        # ``lab_id`` came from the closed constant set above, never an HTTP
        # path segment. Resolve defensively so a future edit cannot escape the
        # volume root by accident.
        directory = (self._root / lab_id).resolve()
        if self._root not in directory.parents:
            raise LabControllerError("lab_directory_invalid")
        return directory

    @staticmethod
    def _read_required(path: Path) -> str:
        return path.read_text(encoding="utf-8").strip()

    @staticmethod
    def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".ctfmesh-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def verify_controller_signature(proof: dict[str, Any], *, public_key: bytes) -> bool:
    """Validate an opaque proof using the controller's public Ed25519 key."""

    expected_keys = {
        "lab_id",
        "generation",
        "reset_id",
        "proof_id",
        "flag_sha256",
        "issued_at",
        "verified",
        "signature",
    }
    if set(proof) != expected_keys or proof.get("verified") is not True:
        return False
    signature = proof.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != _ED25519_SIGNATURE_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in signature)
        or len(public_key) != _ED25519_KEY_BYTES
    ):
        return False
    unsigned = {key: value for key, value in proof.items() if key not in {"verified", "signature"}}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), _canonical_bytes(unsigned)
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _json_response(
    handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: dict[str, Any]
) -> None:
    body = _canonical_bytes(payload)
    handler.send_response(status.value)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def _request_json(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    raw_length = handler.headers.get("Content-Length")
    if raw_length is None or not raw_length.isascii() or not raw_length.isdecimal():
        return None
    length = int(raw_length)
    if length > _MAX_BODY_BYTES:
        return None
    try:
        value = json.loads(handler.rfile.read(length))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def make_controller_handler(state: LabControllerState) -> type[BaseHTTPRequestHandler]:
    """Create a handler bound to one controller state without global secrets."""

    class ControllerHandler(BaseHTTPRequestHandler):
        server_version = "CTFMeshLabController/1"

        def log_message(self, format: str, *_args: object) -> None:
            # Default BaseHTTPRequestHandler logging could expose a submitted
            # candidate flag in the request line or an exception context.
            del format, _args
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            if urlsplit(self.path).path == "/health":
                _json_response(self, HTTPStatus.OK, {"status": "ok", "service": "lab-controller"})
                return
            _json_response(self, HTTPStatus.NOT_FOUND, {"code": "not_found"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            supplied = self.headers.get("X-CTFMesh-Controller-Token")
            if not state.is_authorized(supplied):
                _json_response(self, HTTPStatus.UNAUTHORIZED, {"code": "unauthorized"})
                return
            parsed_path = urlsplit(self.path).path
            parts = tuple(unquote(part) for part in parsed_path.split("/") if part)
            if (
                len(parts) != 4
                or parts[:2] != ("v1", "labs")
                or parts[3] not in {"reset", "verify"}
            ):
                _json_response(self, HTTPStatus.NOT_FOUND, {"code": "not_found"})
                return
            body = _request_json(self)
            if body is None:
                _json_response(self, HTTPStatus.BAD_REQUEST, {"code": "invalid_json"})
                return
            lab_id, action = parts[2], parts[3]
            try:
                if action == "reset":
                    if body:
                        raise LabControllerError("reset_body_must_be_empty")
                    _json_response(self, HTTPStatus.OK, state.reset(lab_id).as_dict())
                    return
                if set(body) != {"generation", "candidate"}:
                    raise LabControllerError("verify_payload_invalid")
                proof = state.verify(
                    lab_id=lab_id,
                    generation=body["generation"],
                    candidate=body["candidate"],
                )
                if proof is None:
                    _json_response(self, HTTPStatus.UNPROCESSABLE_ENTITY, {"verified": False})
                    return
                _json_response(self, HTTPStatus.OK, proof.as_dict())
            except LabControllerError as exc:
                _json_response(self, HTTPStatus.UNPROCESSABLE_ENTITY, {"code": str(exc)})

    return ControllerHandler


def serve_controller(config: ControllerConfig) -> None:
    """Run the controller until Docker sends a normal process termination signal."""

    state = LabControllerState(config)
    server = ThreadingHTTPServer(
        (config.bind_host, config.bind_port), make_controller_handler(state)
    )
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.5)


def main() -> None:
    """Console entrypoint that prints only an allowlisted startup failure code."""

    try:
        serve_controller(ControllerConfig.from_environment())
    except LabControllerConfigurationError as exc:
        print(f"[ctfmesh-lab-controller] {exc}", flush=True)
        raise SystemExit(2) from None


__all__ = [
    "ControllerConfig",
    "LAB_IDS",
    "LabControllerConfigurationError",
    "LabControllerError",
    "LabControllerState",
    "LabProof",
    "LabReset",
    "main",
    "make_controller_handler",
    "serve_controller",
    "verify_controller_signature",
]
