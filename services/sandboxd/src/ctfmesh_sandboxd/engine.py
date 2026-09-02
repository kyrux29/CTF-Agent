"""The only Docker SDK adapter used by Power workspaces.

The service process owns the Docker socket. This module never gives that
client, its socket, or host paths to a created workspace.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import docker
from docker.errors import DockerException, ImageNotFound, NotFound


class WorkspaceEngineError(RuntimeError):
    """Stable Docker-manager failure; daemon diagnostics stay server-side."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class EngineExecResult:
    """Raw, already bounded command bytes from an isolated workspace."""

    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_truncated: bool


class PtyChannel(Protocol):
    """A bounded raw terminal bridge owned by `sandboxd`, never the caller."""

    def send(self, data: bytes) -> None: ...

    def read(self, max_bytes: int, wait_ms: int) -> bytes: ...

    def close(self) -> None: ...

    @property
    def closed(self) -> bool: ...


class WorkspaceEngine(Protocol):
    """Small seam that lets lifecycle rules be tested without host Docker."""

    def reap_managed_workspaces(self) -> None: ...

    def create_workspace(
        self,
        *,
        workspace_id: str,
        run_id: str,
        archive_digest: str,
    ) -> str: ...

    def copy_challenge(self, container_id: str, archive: bytes) -> None: ...

    def exec(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
        output_limit_bytes: int,
    ) -> EngineExecResult: ...

    def pty_start(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> PtyChannel: ...

    def destroy_workspace(self, container_id: str) -> None: ...


class DockerPtyChannel:
    """Adapter for Docker's raw exec socket with a short, non-blocking read."""

    def __init__(self, raw_socket: object) -> None:
        self._raw_socket = raw_socket
        self._closed = False

    def send(self, data: bytes) -> None:
        if self._closed:
            raise WorkspaceEngineError("pty_closed")
        try:
            self._socket().sendall(data)
        except OSError as exc:
            self._closed = True
            raise WorkspaceEngineError("pty_send_failed") from exc

    def read(self, max_bytes: int, wait_ms: int) -> bytes:
        if self._closed:
            return b""
        connection = self._socket()
        try:
            connection.settimeout(wait_ms / 1_000)
            payload = connection.recv(max_bytes)
        except (BlockingIOError, TimeoutError):
            return b""
        except OSError as exc:
            self._closed = True
            raise WorkspaceEngineError("pty_read_failed") from exc
        if not payload:
            self._closed = True
        return payload

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._socket().close()
        except OSError:
            # Endpoint close is intentionally idempotent. The timeout wrapper
            # remains the backstop if a program does not exit on closed stdin.
            return

    @property
    def closed(self) -> bool:
        """Expose endpoint state without leaking the underlying socket."""

        return self._closed

    def _socket(self) -> socket.socket:
        # Docker SDK wraps the Unix socket in SocketIO on Linux. Keep the
        # fallback for SDK implementations that return a raw socket directly.
        candidate = getattr(self._raw_socket, "_sock", self._raw_socket)
        if not isinstance(candidate, socket.socket):
            raise WorkspaceEngineError("pty_socket_invalid")
        return candidate


class DockerWorkspaceEngine:
    """Create and control fixed-profile disposable Docker containers."""

    _LABEL_MANAGED = "ctfmesh.power.managed"

    def __init__(
        self,
        *,
        socket_path: str,
        image: str,
        memory_mb: int,
        cpu_millis: int,
        pids: int,
        work_tmpfs_mb: int,
        tmp_tmpfs_mb: int,
        client_factory: Callable[[], docker.DockerClient] | None = None,
    ) -> None:
        self._socket_path = socket_path
        self._image = image
        self._memory_mb = memory_mb
        self._cpu_millis = cpu_millis
        self._pids = pids
        self._work_tmpfs_mb = work_tmpfs_mb
        self._tmp_tmpfs_mb = tmp_tmpfs_mb
        self._client: docker.DockerClient | None = None
        self._client_factory = client_factory

    def reap_managed_workspaces(self) -> None:
        """Remove stale containers left after a manager restart before reuse."""

        try:
            client = self._docker()
            stale = client.containers.list(
                all=True,
                filters={"label": f"{self._LABEL_MANAGED}=true"},
            )
            for container in stale:
                container.remove(force=True)
            # A crash between volume creation and container startup can leave
            # only the Docker-managed challenge volume. Reap that exact label
            # too; it is never a host bind and belongs to no other service.
            for volume in client.volumes.list(
                filters={"label": f"{self._LABEL_MANAGED}=true"},
            ):
                volume.remove(force=True)
        except DockerException as exc:
            raise WorkspaceEngineError("docker_workspace_reap_failed") from exc

    def create_workspace(
        self,
        *,
        workspace_id: str,
        run_id: str,
        archive_digest: str,
    ) -> str:
        """Start an inert non-root container before copying the challenge tree."""

        try:
            client = self._docker()
            # Never let a workspace trigger an ambient image pull. Its image is
            # built by Compose and reviewed before the Power profile starts.
            client.images.get(self._image)
            labels = self._labels(workspace_id, run_id, archive_digest)
            challenge_volume = client.volumes.create(
                name=self._challenge_volume_name(workspace_id),
                labels=labels,
            )
            try:
                container = client.containers.run(
                    self._image,
                    command=["tail", "-f", "/dev/null"],
                    detach=True,
                    name=f"ctfmesh-power-{workspace_id}",
                    labels=labels,
                    user="1000:1000",
                    working_dir="/work",
                    read_only=True,
                    network_mode="none",
                    # `/challenge` is a daemon-managed volume, never a host
                    # bind. An inert init box fills it before any command can
                    # run in this read-only-rootfs workspace.
                    volumes={challenge_volume.name: {"bind": "/challenge", "mode": "rw"}},
                    tmpfs={
                        # Docker creates a tmpfs mount as root regardless of
                        # the image directory owner. Set the mount owner here
                        # so the fixed non-root solver can use its scratchpad.
                        "/work": self._work_tmpfs_options(self._work_tmpfs_mb),
                        # A conventional sticky temporary directory lets
                        # compilers and Python tools create their own files
                        # without granting write access to the root filesystem.
                        "/tmp": self._temporary_tmpfs_options(self._tmp_tmpfs_mb),  # noqa: S108 - jailed tmpfs.
                    },
                    cap_drop=["ALL"],
                    cap_add=["SYS_PTRACE"],
                    security_opt=["no-new-privileges:true"],
                    pids_limit=self._pids,
                    mem_limit=f"{self._memory_mb}m",
                    nano_cpus=self._cpu_millis * 1_000_000,
                    init=True,
                )
            except DockerException:
                challenge_volume.remove(force=True)
                raise
        except ImageNotFound as exc:
            raise WorkspaceEngineError("workspace_image_unavailable") from exc
        except DockerException as exc:
            raise WorkspaceEngineError("workspace_create_failed") from exc
        return str(container.id)

    def copy_challenge(self, container_id: str, archive: bytes) -> None:
        try:
            client = self._docker()
            workspace = client.containers.get(container_id)
            challenge_volume = self._challenge_volume_name_from_container(workspace)
            # Docker refuses `put_archive` against a read-only rootfs. A short
            # non-root init container sees only the fresh daemon-managed volume
            # and no network/socket/host mount; it is removed before return.
            initializer = client.containers.run(
                self._image,
                command=["tail", "-f", "/dev/null"],
                detach=True,
                name=f"ctfmesh-power-init-{container_id[:12]}",
                labels={self._LABEL_MANAGED: "true", "ctfmesh.power.init": "true"},
                user="1000:1000",
                network_mode="none",
                volumes={challenge_volume: {"bind": "/challenge", "mode": "rw"}},
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                pids_limit=32,
                mem_limit="128m",
                nano_cpus=250_000_000,
                init=True,
            )
            try:
                copied = initializer.put_archive("/challenge", archive)
            finally:
                initializer.remove(force=True)
        except (DockerException, OSError) as exc:
            raise WorkspaceEngineError("workspace_copy_failed") from exc
        if not copied:
            raise WorkspaceEngineError("workspace_copy_failed")

    def exec(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
        output_limit_bytes: int,
    ) -> EngineExecResult:
        """Run one command without a host shell and capture bounded streams."""

        try:
            api = self._docker().api
            response = api.exec_create(
                container_id,
                self._timeout_command(command, timeout_seconds),
                stdout=True,
                stderr=True,
                stdin=False,
                tty=False,
                user="1000:1000",
                workdir=working_directory,
            )
            exec_id = self._exec_id(response)
            stream = api.exec_start(exec_id, stream=True, demux=True)
            stdout = bytearray()
            stderr = bytearray()
            output_truncated = False
            for chunk in stream:
                standard_out, standard_error = self._demux(chunk)
                output_truncated |= _append_bounded(stdout, standard_out, output_limit_bytes)
                output_truncated |= _append_bounded(stderr, standard_error, output_limit_bytes)
            details = api.exec_inspect(exec_id)
        except DockerException as exc:
            raise WorkspaceEngineError("workspace_exec_failed") from exc
        exit_code = details.get("ExitCode")
        if not isinstance(exit_code, int):
            exit_code = None
        return EngineExecResult(
            exit_code=exit_code,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            timed_out=exit_code == 124,
            output_truncated=output_truncated,
        )

    def pty_start(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> PtyChannel:
        try:
            api = self._docker().api
            response = api.exec_create(
                container_id,
                self._timeout_command(command, timeout_seconds),
                stdout=True,
                stderr=True,
                stdin=True,
                tty=True,
                user="1000:1000",
                workdir=working_directory,
            )
            return DockerPtyChannel(api.exec_start(self._exec_id(response), socket=True, tty=True))
        except DockerException as exc:
            raise WorkspaceEngineError("pty_start_failed") from exc

    def destroy_workspace(self, container_id: str) -> None:
        try:
            container = self._docker().containers.get(container_id)
            challenge_volume = self._challenge_volume_name_from_container(container)
            container.remove(force=True)
            self._remove_challenge_volume(challenge_volume)
        except NotFound:
            return
        except DockerException as exc:
            raise WorkspaceEngineError("workspace_destroy_failed") from exc

    def _docker(self) -> docker.DockerClient:
        if self._client is None:
            self._client = (
                self._client_factory()
                if self._client_factory is not None
                else docker.DockerClient(
                    base_url=f"unix://{self._socket_path}",
                    version="auto",
                    timeout=135,
                )
            )
        return self._client

    @staticmethod
    def _timeout_command(command: tuple[str, ...], timeout_seconds: int) -> list[str]:
        # `timeout` runs *inside* the disposable workspace. Every dynamic value
        # remains an argv element after the static shell-free executable path.
        return ["/usr/bin/timeout", "-k", "2", str(timeout_seconds), *command]

    @staticmethod
    def _work_tmpfs_options(size_mb: int) -> str:
        """Return a private, writable scratch mount for the fixed solver UID."""

        return f"rw,nosuid,nodev,size={size_mb}m,uid=1000,gid=1000,mode=0700"

    @staticmethod
    def _temporary_tmpfs_options(size_mb: int) -> str:
        """Return an isolated sticky temp mount without executable files."""

        return f"rw,nosuid,nodev,noexec,size={size_mb}m,mode=1777"

    def _labels(self, workspace_id: str, run_id: str, archive_digest: str) -> dict[str, str]:
        return {
            self._LABEL_MANAGED: "true",
            "ctfmesh.power.workspace_id": workspace_id,
            "ctfmesh.power.run_id": run_id,
            "ctfmesh.power.archive_digest": archive_digest,
        }

    @staticmethod
    def _challenge_volume_name(workspace_id: str) -> str:
        return f"ctfmesh-power-challenge-{workspace_id}"

    @staticmethod
    def _challenge_volume_name_from_container(container: Any) -> str:
        container.reload()
        mounts = container.attrs.get("Mounts")
        if not isinstance(mounts, list):
            raise WorkspaceEngineError("workspace_mount_protocol_invalid")
        for mount in mounts:
            if (
                isinstance(mount, dict)
                and mount.get("Type") == "volume"
                and mount.get("Destination") == "/challenge"
                and isinstance(mount.get("Name"), str)
            ):
                return mount["Name"]
        raise WorkspaceEngineError("workspace_challenge_volume_missing")

    def _remove_challenge_volume(self, volume_name: str) -> None:
        try:
            self._docker().volumes.get(volume_name).remove(force=True)
        except NotFound:
            return
        except DockerException as exc:
            raise WorkspaceEngineError("workspace_volume_destroy_failed") from exc

    @staticmethod
    def _exec_id(response: Any) -> str:
        identifier = response.get("Id") if isinstance(response, dict) else None
        if not isinstance(identifier, str) or not identifier:
            raise WorkspaceEngineError("docker_exec_protocol_invalid")
        return identifier

    @staticmethod
    def _demux(chunk: Any) -> tuple[bytes, bytes]:
        if not isinstance(chunk, tuple) or len(chunk) != 2:
            raise WorkspaceEngineError("docker_exec_protocol_invalid")
        stdout, stderr = chunk
        if stdout is not None and not isinstance(stdout, bytes):
            raise WorkspaceEngineError("docker_exec_protocol_invalid")
        if stderr is not None and not isinstance(stderr, bytes):
            raise WorkspaceEngineError("docker_exec_protocol_invalid")
        return stdout or b"", stderr or b""


def _append_bounded(destination: bytearray, value: bytes, limit: int) -> bool:
    """Append at most `limit` bytes and report whether this stream was clipped."""

    remaining = limit - len(destination)
    if remaining <= 0:
        return bool(value)
    if len(value) <= remaining:
        destination.extend(value)
        return False
    destination.extend(value[:remaining])
    return True


__all__ = [
    "DockerWorkspaceEngine",
    "EngineExecResult",
    "PtyChannel",
    "WorkspaceEngine",
    "WorkspaceEngineError",
]
