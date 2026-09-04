"""Immutable SHA-256-addressed local artifact storage."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from ._compat import ActorRef, ArtifactRef


class ArtifactStoreError(RuntimeError):
    pass


class ArtifactTooLargeError(ArtifactStoreError):
    pass


class ArtifactIntegrityError(ArtifactStoreError):
    pass


class ArtifactNotFoundError(ArtifactStoreError):
    pass


class LocalArtifactStore:
    """A local development backend whose object paths are never user-controlled.

    Bytes are immutable and deduplicated by SHA-256. Provenance records are
    immutable sidecars, allowing the same content to be referenced by different
    runs without rewriting the underlying object.
    """

    def __init__(
        self,
        root: Path,
        *,
        max_artifact_bytes: int = 16 * 1024 * 1024,
        read_only: bool = False,
    ) -> None:
        if max_artifact_bytes <= 0:
            raise ValueError("max_artifact_bytes must be positive")
        if read_only:
            # Independent consumers such as Power's flag-router must be able
            # to inspect a shared immutable store without acquiring write
            # access just because the object/metadata fan-out is initially
            # empty. A missing object is still reported by ``get_bytes``.
            if not root.is_dir():
                raise ArtifactNotFoundError("artifact root does not exist")
        else:
            root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        self._objects = self._root / "objects" / "sha256"
        self._metadata = self._root / "metadata" / "sha256"
        if not read_only:
            self._objects.mkdir(parents=True, exist_ok=True)
            self._metadata.mkdir(parents=True, exist_ok=True)
        self._max_artifact_bytes = max_artifact_bytes

    @property
    def root(self) -> Path:
        return self._root

    async def put_bytes(
        self,
        data: bytes,
        *,
        run_id: str,
        mime_type: str,
        producer: ActorRef,
        classification: Literal["public", "internal", "secret", "flag"] = "internal",
        branch_id: str | None = None,
        task_id: str | None = None,
        tool_invocation_id: str | None = None,
    ) -> ArtifactRef:
        if len(data) > self._max_artifact_bytes:
            raise ArtifactTooLargeError("artifact exceeds configured byte limit")
        digest = hashlib.sha256(data).hexdigest()
        reference = ArtifactRef(
            id=f"sha256:{digest}",
            run_id=run_id,
            sha256=digest,
            size_bytes=len(data),
            mime_type=mime_type,
            producer=producer,
            created_at=datetime.now(UTC),
            branch_id=branch_id,
            task_id=task_id,
            tool_invocation_id=tool_invocation_id,
            classification=classification,
        )
        await asyncio.to_thread(self._write_blob, digest, data)
        await asyncio.to_thread(self._write_metadata, reference)
        return reference

    async def get_bytes(self, artifact: ArtifactRef | str) -> bytes:
        digest = self._digest_from_reference(artifact)
        return await asyncio.to_thread(self._read_verified_blob, digest)

    async def iter_metadata(self, artifact: ArtifactRef | str) -> tuple[ArtifactRef, ...]:
        digest = self._digest_from_reference(artifact)
        return await asyncio.to_thread(self._read_metadata, digest)

    async def list_for_run(self, run_id: str, *, limit: int = 500) -> tuple[ArtifactRef, ...]:
        """Return the provenance records one run produced, newest first.

        The store is addressed by content, so a run's own evidence can only be
        found by reading the provenance sidecars. Power seals its observations
        straight into this store and never writes a control-plane artifact
        row, which left every Power run's evidence unreachable through the
        console: the bytes were here and nothing listed them.

        The scan is bounded and the store is local to one operator, so a walk
        is honest here in a way it would not be against a remote object store.
        """

        if limit <= 0:
            raise ValueError("limit must be positive")
        return await asyncio.to_thread(self._scan_run_metadata, run_id, limit)

    async def contains(self, artifact: ArtifactRef | str) -> bool:
        digest = self._digest_from_reference(artifact)
        return await asyncio.to_thread(self._object_path(digest).is_file)

    def _object_path(self, digest: str) -> Path:
        self._validate_digest(digest)
        return self._objects / digest[:2] / digest[2:4] / digest

    def _metadata_dir(self, digest: str) -> Path:
        self._validate_digest(digest)
        return self._metadata / digest[:2] / digest[2:4] / digest

    @staticmethod
    def _validate_digest(digest: str) -> None:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ArtifactNotFoundError("invalid artifact digest")

    @classmethod
    def _digest_from_reference(cls, artifact: ArtifactRef | str) -> str:
        if isinstance(artifact, str):
            digest = artifact.removeprefix("sha256:")
        else:
            digest = artifact.sha256
        cls._validate_digest(digest)
        return digest

    def _write_blob(self, digest: str, data: bytes) -> None:
        destination = self._object_path(digest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if self._read_verified_blob(digest) != data:
                raise ArtifactIntegrityError("content address already contains different bytes")
            return
        self._link_immutable(destination, data)

    def _write_metadata(self, reference: ArtifactRef) -> None:
        payload = reference.model_dump_json(by_alias=True).encode("utf-8")
        record_digest = hashlib.sha256(payload).hexdigest()
        destination = self._metadata_dir(reference.sha256) / f"{record_digest}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            self._link_immutable(destination, payload)

    @staticmethod
    def _link_immutable(destination: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".ctfmesh-", dir=destination.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            try:
                os.link(temporary, destination)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    def _read_verified_blob(self, digest: str) -> bytes:
        path = self._object_path(digest)
        try:
            payload = path.read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactNotFoundError("artifact does not exist") from exc
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ArtifactIntegrityError("artifact bytes do not match their content address")
        return payload

    def _scan_run_metadata(self, run_id: str, limit: int) -> tuple[ArtifactRef, ...]:
        if not self._metadata.is_dir():
            return ()
        newest: dict[str, ArtifactRef] = {}
        for path in self._metadata.glob("*/*/*/*.json"):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                # One unreadable sidecar must not hide the rest of a run's
                # evidence; the record it describes stays absent from the list
                # and its bytes remain reachable by digest.
                continue
            if not isinstance(raw, dict) or raw.get("run_id") != run_id:
                continue
            try:
                record = ArtifactRef.model_validate(raw)
            except ValueError:
                continue
            # The store deduplicates bytes, so one digest can carry a
            # provenance sidecar per producing call. Two commands that both
            # printed nothing share the empty digest; listing that object
            # twenty times would bury the evidence worth looking at.
            existing = newest.get(record.id)
            if existing is None or record.created_at > existing.created_at:
                newest[record.id] = record
        records = sorted(
            newest.values(),
            key=lambda record: (record.created_at, record.id),
            reverse=True,
        )
        return tuple(records[:limit])

    def _read_metadata(self, digest: str) -> tuple[ArtifactRef, ...]:
        directory = self._metadata_dir(digest)
        if not directory.is_dir():
            return ()
        records: list[ArtifactRef] = []
        for path in sorted(directory.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                records.append(ArtifactRef.model_validate(raw))
            except (OSError, ValueError) as exc:
                raise ArtifactIntegrityError("artifact metadata is malformed") from exc
        return tuple(records)


__all__ = [
    "ArtifactIntegrityError",
    "ArtifactNotFoundError",
    "ArtifactStoreError",
    "ArtifactTooLargeError",
    "LocalArtifactStore",
]
