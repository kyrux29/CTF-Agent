"""Workspace lifecycle policy between the private RPC and Docker SDK adapter."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from ctfmesh_domain import ActorKind, ActorRef, ArtifactRef
from ctfmesh_tools.artifacts import LocalArtifactStore

from .contracts import (
    ArtifactReceipt,
    PtyReadReceipt,
    PtyReadRequest,
    PtyReceipt,
    PtySendRequest,
    TubeConnectRequest,
    TubeReceipt,
    TubeRecvReceipt,
    TubeRecvUntilRequest,
    TubeSendRequest,
    WorkspaceCreateRequest,
    WorkspaceDestroyReceipt,
    WorkspaceExecReceipt,
    WorkspaceExecRequest,
    WorkspacePtyStartRequest,
    WorkspaceReceipt,
)
from .engine import (
    DockerWorkspaceEngine,
    EngineExecResult,
    PtyChannel,
    WorkspaceEngine,
    WorkspaceEngineError,
)
from .intake import ArchiveIntakeLocator, IntakeMaterializationError
from .settings import SandboxdSettings


class WorkspaceServiceError(RuntimeError):
    """A stable code for private callers; no Docker or source diagnostics leak."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class _WorkspaceRecord:
    run_id: str
    archive_digest: str
    container_id: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    ptys: dict[str, PtyChannel] = field(default_factory=dict)
    tubes: dict[str, _TubeChannel] = field(default_factory=dict)
    tube_targets: frozenset[tuple[str, int]] = frozenset()


@dataclass(slots=True)
class _TubeChannel:
    """One raw TCP stream retained only inside the trusted workspace manager."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    host: str
    port: int
    buffered: bytearray = field(default_factory=bytearray)
    closed: bool = False

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise WorkspaceServiceError("tube_closed")
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError) as exc:
            self.closed = True
            raise WorkspaceServiceError("tube_send_failed") from exc

    async def recv_until(
        self,
        delimiter: bytes,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> tuple[bytes, bool, bool, bool]:
        """Return only observed bounded bytes; retain any post-delimiter tail."""

        payload = bytearray(self.buffered)
        self.buffered.clear()
        timed_out = False
        try:
            async with asyncio.timeout(timeout_seconds):
                while delimiter not in payload and len(payload) < max_bytes and not self.closed:
                    chunk = await self.reader.read(min(4096, max_bytes - len(payload)))
                    if not chunk:
                        self.closed = True
                        break
                    payload.extend(chunk)
        except TimeoutError:
            timed_out = True

        delimiter_index = payload.find(delimiter)
        matched = delimiter_index >= 0
        if matched:
            end = delimiter_index + len(delimiter)
            self.buffered.extend(payload[end:])
            payload = payload[:end]
        return bytes(payload), matched, timed_out, self.closed

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            return


class WorkspaceService:
    """Own P1's disposable workspace state and preserve manager-only authority."""

    def __init__(
        self,
        *,
        engine: WorkspaceEngine,
        intake_locator: ArchiveIntakeLocator,
        artifact_root: Path,
        output_limit_bytes: int,
        max_exec_timeout_seconds: int,
    ) -> None:
        self._engine = engine
        self._intake_locator = intake_locator
        self._artifact_root = artifact_root
        self._output_limit_bytes = output_limit_bytes
        self._max_exec_timeout_seconds = max_exec_timeout_seconds
        self._workspaces: dict[str, _WorkspaceRecord] = {}
        self._destroyed: set[str] = set()
        self._lifecycle_lock = asyncio.Lock()
        self._orphan_reap_complete = False
        self._artifact_store: LocalArtifactStore | None = None

    @classmethod
    def from_settings(cls, settings: SandboxdSettings) -> WorkspaceService:
        """Build deployment-owned collaborators without exposing their handles."""

        engine = DockerWorkspaceEngine(
            socket_path=str(settings.docker_socket_path),
            image=settings.workspace_image,
            memory_mb=settings.workspace_memory_mb,
            cpu_millis=settings.workspace_cpu_millis,
            pids=settings.workspace_pids,
            work_tmpfs_mb=settings.work_tmpfs_mb,
            tmp_tmpfs_mb=settings.tmp_tmpfs_mb,
        )
        return cls(
            engine=engine,
            intake_locator=ArchiveIntakeLocator(
                settings.artifact_root,
                max_bytes=settings.max_challenge_bytes,
            ),
            artifact_root=settings.artifact_root,
            output_limit_bytes=settings.output_limit_bytes,
            max_exec_timeout_seconds=settings.max_exec_timeout_seconds,
        )

    async def create(self, request: WorkspaceCreateRequest) -> WorkspaceReceipt:
        """Create a fresh inert container and copy a validated archive tree into it."""

        async with self._lifecycle_lock:
            await self._reap_orphans_once()
            try:
                archive = await asyncio.to_thread(
                    self._intake_locator.challenge_archive,
                    request.archive_digest,
                )
            except IntakeMaterializationError as exc:
                raise WorkspaceServiceError(exc.code) from exc

            workspace_id = f"ws_{uuid4().hex}"
            container_id: str | None = None
            try:
                container_id = await asyncio.to_thread(
                    self._engine.create_workspace,
                    workspace_id=workspace_id,
                    run_id=request.run_id,
                    archive_digest=archive.digest,
                )
                await asyncio.to_thread(self._engine.copy_challenge, container_id, archive.payload)
            except WorkspaceEngineError as exc:
                if container_id is not None:
                    await self._destroy_after_failed_create(container_id)
                raise WorkspaceServiceError(exc.code) from exc

            if container_id is None:
                raise WorkspaceServiceError("workspace_create_failed")

            self._workspaces[workspace_id] = _WorkspaceRecord(
                run_id=request.run_id,
                archive_digest=request.archive_digest,
                container_id=container_id,
                tube_targets=frozenset(
                    (target.host, target.port) for target in request.tube_targets
                ),
            )
            return WorkspaceReceipt(
                workspace_id=workspace_id,
                run_id=request.run_id,
                archive_digest=request.archive_digest,
            )

    async def exec(self, workspace_id: str, request: WorkspaceExecRequest) -> WorkspaceExecReceipt:
        """Run one bounded argv-only command and persist both observed streams."""

        record = await self._active_workspace(workspace_id)
        if request.timeout_seconds > self._max_exec_timeout_seconds:
            raise WorkspaceServiceError("exec_timeout_exceeds_workspace_limit")
        async with record.lock:
            result = await self._exec_engine(record, request)
            stdout_artifact, stderr_artifact = await self._store_observation(result, record.run_id)
        return WorkspaceExecReceipt(
            workspace_id=workspace_id,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            output_truncated=result.output_truncated,
            stdout=result.stdout.decode("utf-8", errors="replace"),
            stderr=result.stderr.decode("utf-8", errors="replace"),
            stdout_artifact=stdout_artifact,
            stderr_artifact=stderr_artifact,
        )

    async def pty_start(
        self,
        workspace_id: str,
        request: WorkspacePtyStartRequest,
    ) -> PtyReceipt:
        """Create an interactive Docker exec endpoint with the same timeout bounds."""

        record = await self._active_workspace(workspace_id)
        if request.timeout_seconds > self._max_exec_timeout_seconds:
            raise WorkspaceServiceError("pty_timeout_exceeds_workspace_limit")
        async with record.lock:
            try:
                channel = await asyncio.to_thread(
                    self._engine.pty_start,
                    record.container_id,
                    command=request.command,
                    timeout_seconds=request.timeout_seconds,
                    working_directory=request.working_directory,
                )
            except WorkspaceEngineError as exc:
                raise WorkspaceServiceError(exc.code) from exc
            pty_id = f"pty_{uuid4().hex}"
            record.ptys[pty_id] = channel
        return PtyReceipt(pty_id=pty_id, workspace_id=workspace_id, state="open")

    async def pty_send(self, workspace_id: str, pty_id: str, request: PtySendRequest) -> PtyReceipt:
        """Forward bounded terminal input only to a PTY belonging to this workspace."""

        record = await self._active_workspace(workspace_id)
        encoded = request.data.encode("utf-8")
        if len(encoded) > self._output_limit_bytes:
            raise WorkspaceServiceError("pty_input_too_large")
        async with record.lock:
            channel = self._pty(record, pty_id)
            try:
                await asyncio.to_thread(channel.send, encoded)
            except WorkspaceEngineError as exc:
                raise WorkspaceServiceError(exc.code) from exc
        return PtyReceipt(pty_id=pty_id, workspace_id=workspace_id, state="open")

    async def pty_read(
        self,
        workspace_id: str,
        pty_id: str,
        request: PtyReadRequest,
    ) -> PtyReadReceipt:
        """Return one short observation without buffering an unbounded terminal stream."""

        record = await self._active_workspace(workspace_id)
        async with record.lock:
            channel = self._pty(record, pty_id)
            try:
                payload = await asyncio.to_thread(channel.read, request.max_bytes, request.wait_ms)
            except WorkspaceEngineError as exc:
                raise WorkspaceServiceError(exc.code) from exc
            artifact = await self._store_bytes(payload, record.run_id)
        return PtyReadReceipt(
            pty_id=pty_id,
            data=payload.decode("utf-8", errors="replace"),
            closed=channel.closed,
            observation_artifact=artifact,
        )

    async def pty_close(self, workspace_id: str, pty_id: str) -> PtyReceipt:
        """Close a terminal stream idempotently; command timeout remains the backstop."""

        record = await self._active_workspace(workspace_id)
        async with record.lock:
            channel = record.ptys.pop(pty_id, None)
            if channel is not None:
                await asyncio.to_thread(channel.close)
        return PtyReceipt(pty_id=pty_id, workspace_id=workspace_id, state="closed")

    async def tube_connect(
        self,
        workspace_id: str,
        request: TubeConnectRequest,
    ) -> TubeReceipt:
        """Open one exact endpoint previously declared for this workspace only."""

        record = await self._active_workspace(workspace_id)
        target = (request.host, request.port)
        if target not in record.tube_targets:
            raise WorkspaceServiceError("tube_target_not_allowed")
        async with record.lock:
            try:
                async with asyncio.timeout(request.timeout_seconds):
                    reader, writer = await asyncio.open_connection(request.host, request.port)
            except (OSError, TimeoutError) as exc:
                raise WorkspaceServiceError("tube_connect_failed") from exc
            tube_id = f"tube_{uuid4().hex}"
            record.tubes[tube_id] = _TubeChannel(
                reader=reader,
                writer=writer,
                host=request.host,
                port=request.port,
            )
            artifact = await self._store_bytes(
                f"connected {request.host}:{request.port}\n".encode(), record.run_id
            )
        return TubeReceipt(
            tube_id=tube_id,
            workspace_id=workspace_id,
            host=request.host,
            port=request.port,
            state="open",
            observation_artifact=artifact,
        )

    async def tube_send(
        self,
        workspace_id: str,
        tube_id: str,
        request: TubeSendRequest,
    ) -> TubeReceipt:
        """Write base64-decoded bytes without allowing model data into a shell."""

        record = await self._active_workspace(workspace_id)
        payload = base64.b64decode(request.data_base64.encode("ascii"), validate=True)
        if len(payload) > self._output_limit_bytes:
            raise WorkspaceServiceError("tube_input_too_large")
        async with record.lock:
            tube = self._tube(record, tube_id)
            await tube.send(payload)
            state = "closed" if tube.closed else "open"
        return TubeReceipt(
            tube_id=tube_id,
            workspace_id=workspace_id,
            host=tube.host,
            port=tube.port,
            state=state,
        )

    async def tube_recv_until(
        self,
        workspace_id: str,
        tube_id: str,
        request: TubeRecvUntilRequest,
    ) -> TubeRecvReceipt:
        """Persist all TCP response bytes before returning their bounded decoding."""

        record = await self._active_workspace(workspace_id)
        delimiter = base64.b64decode(request.delimiter_base64.encode("ascii"), validate=True)
        if not delimiter:
            raise WorkspaceServiceError("tube_delimiter_invalid")
        async with record.lock:
            tube = self._tube(record, tube_id)
            payload, matched, timed_out, closed = await tube.recv_until(
                delimiter,
                max_bytes=request.max_bytes,
                timeout_seconds=request.timeout_seconds,
            )
            artifact = await self._store_bytes(payload, record.run_id)
        return TubeRecvReceipt(
            tube_id=tube_id,
            data=payload.decode("utf-8", errors="replace"),
            matched_delimiter=matched,
            closed=closed,
            timed_out=timed_out,
            output_truncated=len(payload) >= request.max_bytes and not matched,
            observation_artifact=artifact,
        )

    async def tube_close(self, workspace_id: str, tube_id: str) -> TubeReceipt:
        """Close a scoped TCP stream idempotently without crossing workspaces."""

        record = await self._active_workspace(workspace_id)
        async with record.lock:
            tube = record.tubes.pop(tube_id, None)
            if tube is not None:
                await tube.close()
        return TubeReceipt(
            tube_id=tube_id,
            workspace_id=workspace_id,
            host=tube.host if tube is not None else "closed",
            port=tube.port if tube is not None else 1,
            state="closed",
        )

    async def destroy(self, workspace_id: str) -> WorkspaceDestroyReceipt:
        """Force-remove only a manager-labelled workspace and close its PTYs first."""

        async with self._lifecycle_lock:
            record = self._workspaces.get(workspace_id)
            if record is None:
                return WorkspaceDestroyReceipt(
                    workspace_id=workspace_id,
                    already_destroyed=workspace_id in self._destroyed,
                )
            async with record.lock:
                for channel in record.ptys.values():
                    await asyncio.to_thread(channel.close)
                record.ptys.clear()
                for tube in record.tubes.values():
                    await tube.close()
                record.tubes.clear()
                try:
                    await asyncio.to_thread(self._engine.destroy_workspace, record.container_id)
                except WorkspaceEngineError as exc:
                    raise WorkspaceServiceError(exc.code) from exc
            self._workspaces.pop(workspace_id, None)
            self._destroyed.add(workspace_id)
        return WorkspaceDestroyReceipt(workspace_id=workspace_id, already_destroyed=False)

    async def _active_workspace(self, workspace_id: str) -> _WorkspaceRecord:
        async with self._lifecycle_lock:
            record = self._workspaces.get(workspace_id)
        if record is None:
            raise WorkspaceServiceError("workspace_not_found")
        return record

    async def _reap_orphans_once(self) -> None:
        if self._orphan_reap_complete:
            return
        try:
            await asyncio.to_thread(self._engine.reap_managed_workspaces)
        except WorkspaceEngineError as exc:
            raise WorkspaceServiceError(exc.code) from exc
        self._orphan_reap_complete = True

    async def _destroy_after_failed_create(self, container_id: str) -> None:
        try:
            await asyncio.to_thread(self._engine.destroy_workspace, container_id)
        except WorkspaceEngineError:
            # The initial create error is more useful to callers. Startup
            # reaping will target only this manager's label if cleanup failed.
            return

    async def _exec_engine(
        self,
        record: _WorkspaceRecord,
        request: WorkspaceExecRequest,
    ) -> EngineExecResult:
        try:
            return await asyncio.to_thread(
                self._engine.exec,
                record.container_id,
                command=request.command,
                timeout_seconds=request.timeout_seconds,
                working_directory=request.working_directory,
                output_limit_bytes=self._output_limit_bytes,
            )
        except WorkspaceEngineError as exc:
            raise WorkspaceServiceError(exc.code) from exc

    async def _store_observation(
        self,
        result: EngineExecResult,
        run_id: str,
    ) -> tuple[ArtifactReceipt, ArtifactReceipt]:
        return (
            await self._store_bytes(result.stdout, run_id),
            await self._store_bytes(result.stderr, run_id),
        )

    async def _store_bytes(self, payload: bytes, run_id: str) -> ArtifactReceipt:
        store = self._artifacts()
        producer = ActorRef(kind=ActorKind.TOOL, id="sandboxd")
        try:
            reference = await store.put_bytes(
                payload,
                run_id=run_id,
                mime_type="application/octet-stream",
                producer=producer,
                classification="secret",
            )
        except OSError as exc:
            raise WorkspaceServiceError("workspace_artifact_store_failed") from exc
        return _artifact_receipt(reference)

    def _artifacts(self) -> LocalArtifactStore:
        if self._artifact_store is None:
            self._artifact_store = LocalArtifactStore(
                self._artifact_root,
                max_artifact_bytes=self._output_limit_bytes,
            )
        return self._artifact_store

    @staticmethod
    def _pty(record: _WorkspaceRecord, pty_id: str) -> PtyChannel:
        channel = record.ptys.get(pty_id)
        if channel is None:
            raise WorkspaceServiceError("pty_not_found")
        return channel

    @staticmethod
    def _tube(record: _WorkspaceRecord, tube_id: str) -> _TubeChannel:
        tube = record.tubes.get(tube_id)
        if tube is None:
            raise WorkspaceServiceError("tube_not_found")
        return tube


def _artifact_receipt(reference: ArtifactRef) -> ArtifactReceipt:
    return ArtifactReceipt(
        id=reference.id,
        sha256=reference.sha256,
        size_bytes=reference.size_bytes,
    )


__all__ = ["WorkspaceService", "WorkspaceServiceError"]
