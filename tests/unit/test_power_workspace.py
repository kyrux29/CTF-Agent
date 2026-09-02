"""P1 unit coverage for the private workspace lifecycle and denial boundary."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from base64 import b64encode
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from ctfmesh_sandboxd.app import create_sandboxd_app
from ctfmesh_sandboxd.contracts import (
    PtyReadRequest,
    PtySendRequest,
    TubeConnectRequest,
    TubeRecvUntilRequest,
    TubeSendRequest,
    TubeTarget,
    WorkspaceCreateRequest,
    WorkspaceExecRequest,
    WorkspacePtyStartRequest,
)
from ctfmesh_sandboxd.engine import DockerWorkspaceEngine, EngineExecResult, WorkspaceEngineError
from ctfmesh_sandboxd.intake import ArchiveIntakeLocator, IntakeMaterializationError
from ctfmesh_sandboxd.service import WorkspaceService, WorkspaceServiceError
from ctfmesh_sandboxd.settings import SandboxdSettings
from ctfmesh_tools.artifacts import LocalArtifactStore
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError


class _FakePty:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def send(self, data: bytes) -> None:
        if self.closed:
            raise WorkspaceEngineError("pty_closed")
        self.sent.append(data)

    def read(self, max_bytes: int, wait_ms: int) -> bytes:
        del wait_ms
        if self.closed:
            return b""
        return b"ctf> "[:max_bytes]

    def close(self) -> None:
        self.closed = True


class _FakeEngine:
    """Records manager intent without creating a real Docker container."""

    def __init__(self) -> None:
        self.reap_calls = 0
        self.created: dict[str, dict[str, str]] = {}
        self.copied_members: dict[str, tuple[str, ...]] = {}
        self.exec_calls: list[dict[str, object]] = []
        self.destroyed: list[str] = []
        self.ptys: list[_FakePty] = []

    def reap_managed_workspaces(self) -> None:
        self.reap_calls += 1

    def create_workspace(
        self,
        *,
        workspace_id: str,
        run_id: str,
        archive_digest: str,
    ) -> str:
        container_id = f"container-{workspace_id}"
        self.created[container_id] = {
            "workspace_id": workspace_id,
            "run_id": run_id,
            "archive_digest": archive_digest,
        }
        return container_id

    def copy_challenge(self, container_id: str, archive: bytes) -> None:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r") as source:
            self.copied_members[container_id] = tuple(member.name for member in source.getmembers())

    def exec(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
        output_limit_bytes: int,
    ) -> EngineExecResult:
        self.exec_calls.append(
            {
                "container_id": container_id,
                "command": command,
                "timeout_seconds": timeout_seconds,
                "working_directory": working_directory,
                "output_limit_bytes": output_limit_bytes,
            }
        )
        output = b"hi\n" if command == ("echo", "hi") else b"uid=1000(ctf) gid=1000(ctf)\n"
        return EngineExecResult(0, output, b"", False, False)

    def pty_start(
        self,
        container_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> _FakePty:
        del container_id, command, timeout_seconds, working_directory
        pty = _FakePty()
        self.ptys.append(pty)
        return pty

    def destroy_workspace(self, container_id: str) -> None:
        self.destroyed.append(container_id)
        self.created.pop(container_id, None)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _published_intake(root: Path, digest: str, files: dict[str, bytes]) -> None:
    intake = root / "archive-intakes" / f"intake_{digest[:32]}"
    workspace = intake / "workspace"
    workspace.mkdir(parents=True)
    for name, payload in files.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": digest}}),
        encoding="utf-8",
    )


def _service(root: Path) -> tuple[WorkspaceService, _FakeEngine]:
    engine = _FakeEngine()
    service = WorkspaceService(
        engine=engine,
        intake_locator=ArchiveIntakeLocator(root, max_bytes=1024 * 1024),
        artifact_root=root,
        output_limit_bytes=64 * 1024,
        max_exec_timeout_seconds=120,
    )
    return service, engine


@pytest.mark.asyncio
async def test_workspace_create_exec_artifacts_destroy_and_isolation(tmp_path: Path) -> None:
    """P1 copies each intake into an independent box and persists observed output."""

    first_digest = _digest("first")
    second_digest = _digest("second")
    _published_intake(tmp_path, first_digest, {"notes.txt": b"first"})
    _published_intake(tmp_path, second_digest, {"nested/input.bin": b"second"})
    service, engine = _service(tmp_path)

    first = await service.create(
        WorkspaceCreateRequest(run_id="run-first", archive_digest=first_digest)
    )
    second = await service.create(
        WorkspaceCreateRequest(run_id="run-second", archive_digest=second_digest)
    )
    assert first.workspace_id != second.workspace_id
    assert engine.reap_calls == 1

    first_result = await service.exec(
        first.workspace_id,
        WorkspaceExecRequest(command=("echo", "hi"), working_directory="/challenge"),
    )
    second_result = await service.exec(second.workspace_id, WorkspaceExecRequest(command=("id",)))
    assert first_result.stdout == "hi\n"
    assert second_result.stdout.startswith("uid=1000")
    assert engine.exec_calls[0]["container_id"] != engine.exec_calls[1]["container_id"]
    assert "notes.txt" in engine.copied_members[f"container-{first.workspace_id}"]
    assert "nested/input.bin" in engine.copied_members[f"container-{second.workspace_id}"]

    artifacts = LocalArtifactStore(tmp_path)
    assert await artifacts.get_bytes(first_result.stdout_artifact.id) == b"hi\n"
    assert first_result.stdout_artifact.sha256 == hashlib.sha256(b"hi\n").hexdigest()

    assert (await service.destroy(first.workspace_id)).already_destroyed is False
    assert (await service.destroy(first.workspace_id)).already_destroyed is True
    assert (await service.destroy(second.workspace_id)).already_destroyed is False
    assert not engine.created


@pytest.mark.asyncio
async def test_workspace_pty_is_bounded_and_belongs_to_its_workspace(tmp_path: Path) -> None:
    digest = _digest("pty")
    _published_intake(tmp_path, digest, {"README": b"interactive"})
    service, engine = _service(tmp_path)
    workspace = await service.create(
        WorkspaceCreateRequest(run_id="run-pty", archive_digest=digest)
    )

    pty = await service.pty_start(
        workspace.workspace_id,
        WorkspacePtyStartRequest(command=("sh",), working_directory="/work"),
    )
    await service.pty_send(workspace.workspace_id, pty.pty_id, PtySendRequest(data="help\n"))
    observed = await service.pty_read(
        workspace.workspace_id,
        pty.pty_id,
        PtyReadRequest(max_bytes=5),
    )
    assert engine.ptys[0].sent == [b"help\n"]
    assert observed.data == "ctf> "
    assert observed.closed is False
    artifacts = LocalArtifactStore(tmp_path)
    assert await artifacts.get_bytes(observed.observation_artifact.id) == b"ctf> "
    assert (await service.pty_close(workspace.workspace_id, pty.pty_id)).state == "closed"
    assert engine.ptys[0].closed is True
    await service.destroy(workspace.workspace_id)


@pytest.mark.asyncio
async def test_workspace_tube_is_exactly_scoped_and_persists_real_echo_bytes(
    tmp_path: Path,
) -> None:
    """P3's live tube rejects an undeclared endpoint and keeps its output as CAS evidence."""

    import asyncio

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        payload = await reader.readuntil(b"\n")
        writer.write(b"hello-p3:" + payload)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(echo, host="127.0.0.1", port=0)
    socket = server.sockets[0]
    assert socket is not None
    port = int(socket.getsockname()[1])
    digest = _digest("tube")
    _published_intake(tmp_path, digest, {"README": b"tube"})
    service, _engine = _service(tmp_path)
    workspace = await service.create(
        WorkspaceCreateRequest(
            run_id="run-tube",
            archive_digest=digest,
            tube_targets=(TubeTarget(host="127.0.0.1", port=port),),
        )
    )
    try:
        with pytest.raises(WorkspaceServiceError, match="tube_target_not_allowed"):
            await service.tube_connect(
                workspace.workspace_id,
                TubeConnectRequest(host="127.0.0.1", port=port + 1),
            )
        tube = await service.tube_connect(
            workspace.workspace_id, TubeConnectRequest(host="127.0.0.1", port=port)
        )
        await service.tube_send(
            workspace.workspace_id,
            tube.tube_id,
            TubeSendRequest(data_base64=b64encode(b"payload\n").decode("ascii")),
        )
        observed = await service.tube_recv_until(
            workspace.workspace_id,
            tube.tube_id,
            TubeRecvUntilRequest(delimiter_base64=b64encode(b"\n").decode("ascii")),
        )
        assert observed.data == "hello-p3:payload\n"
        assert observed.matched_delimiter is True
        artifacts = LocalArtifactStore(tmp_path)
        assert await artifacts.get_bytes(observed.observation_artifact.id) == b"hello-p3:payload\n"
        assert (await service.tube_close(workspace.workspace_id, tube.tube_id)).state == "closed"
    finally:
        await service.destroy(workspace.workspace_id)
        server.close()
        await server.wait_closed()


def test_workspace_contract_rejects_path_escape_and_unbounded_command() -> None:
    """No API path can select /etc, traversal, mounts, environment, or a host shell."""

    with pytest.raises(ValidationError, match="working_directory"):
        WorkspaceExecRequest(command=("cat", "/etc/shadow"), working_directory="/work/../etc")
    with pytest.raises(ValidationError, match="working_directory"):
        WorkspaceExecRequest(command=("id",), working_directory="/etc")
    with pytest.raises(ValidationError, match="argv elements"):
        WorkspaceExecRequest(command=("echo", "\x00"))


def test_archive_copy_rejects_a_link_in_the_validated_tree(tmp_path: Path) -> None:
    """A tampered intake cannot turn copy-in into a host file disclosure."""

    digest = _digest("linked")
    _published_intake(tmp_path, digest, {"safe.txt": b"safe"})
    workspace = tmp_path / "archive-intakes" / f"intake_{digest[:32]}" / "workspace"
    (workspace / "bad-link").symlink_to("/etc/shadow")
    locator = ArchiveIntakeLocator(tmp_path, max_bytes=1024 * 1024)
    with pytest.raises(IntakeMaterializationError, match="archive_workspace_entry_invalid"):
        locator.challenge_archive(digest)


def test_docker_engine_fixed_workspace_profile_has_no_host_mount_or_network() -> None:
    """The concrete adapter cannot accidentally create a solver with host authority."""

    calls: dict[str, Any] = {}

    class Images:
        @staticmethod
        def get(image: str) -> None:
            calls["image"] = image

    class Containers:
        @staticmethod
        def run(*args: object, **kwargs: object) -> SimpleNamespace:
            calls["run_args"] = args
            calls["run_kwargs"] = kwargs
            return SimpleNamespace(id="container-1")

    class Volume:
        name = "ctfmesh-power-challenge-ws_0123456789abcdef0123456789abcdef"

        @staticmethod
        def remove(*, force: bool) -> None:
            calls["volume_removed"] = force

    class Volumes:
        @staticmethod
        def create(*, name: str, labels: dict[str, str]) -> Volume:
            calls["volume_name"] = name
            calls["volume_labels"] = labels
            return Volume()

    fake_client = SimpleNamespace(images=Images(), containers=Containers(), volumes=Volumes())
    engine = DockerWorkspaceEngine(
        socket_path="/var/run/docker.sock",
        image="ctfmesh-ctf-toolkit:0.1",
        memory_mb=4096,
        cpu_millis=2000,
        pids=512,
        work_tmpfs_mb=1024,
        tmp_tmpfs_mb=128,
        client_factory=lambda: cast(Any, fake_client),
    )
    assert (
        engine.create_workspace(
            workspace_id="ws_0123456789abcdef0123456789abcdef",
            run_id="run-local",
            archive_digest="a" * 64,
        )
        == "container-1"
    )
    kwargs = cast(dict[str, object], calls["run_kwargs"])
    assert calls["image"] == "ctfmesh-ctf-toolkit:0.1"
    assert kwargs["user"] == "1000:1000"
    assert kwargs["read_only"] is True
    assert kwargs["network_mode"] == "none"
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["cap_add"] == ["SYS_PTRACE"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["volumes"] == {
        "ctfmesh-power-challenge-ws_0123456789abcdef0123456789abcdef": {
            "bind": "/challenge",
            "mode": "rw",
        }
    }
    assert kwargs["tmpfs"] == {
        "/work": "rw,nosuid,nodev,size=1024m,uid=1000,gid=1000,mode=0700",
        "/tmp": "rw,nosuid,nodev,noexec,size=128m,mode=1777",
    }
    assert calls["volume_name"] == "ctfmesh-power-challenge-ws_0123456789abcdef0123456789abcdef"
    assert "privileged" not in kwargs


def test_private_workspace_routes_require_a_distinct_capability(tmp_path: Path) -> None:
    """A service on the control bridge cannot use workspace RPC without its token."""

    digest = _digest("api")
    _published_intake(tmp_path, digest, {"file.txt": b"api"})
    manager, _engine = _service(tmp_path)
    token = "p" * 32
    app = create_sandboxd_app(
        SandboxdSettings(power_enabled=True, sandboxd_token=SecretStr(token)),
        workspace_service=manager,
    )
    with TestClient(app) as client:
        denied = client.post("/v1/workspaces", json={"run_id": "run-api", "archive_digest": digest})
        assert denied.status_code == 401
        assert denied.json() == {"detail": {"code": "sandboxd_capability_invalid"}}

        created = client.post(
            "/v1/workspaces",
            headers={"X-CTFMesh-Sandboxd-Token": token},
            json={"run_id": "run-api", "archive_digest": digest},
        )
        assert created.status_code == 201
        workspace_id = created.json()["workspace_id"]
        executed = client.post(
            f"/v1/workspaces/{workspace_id}/exec",
            headers={"X-CTFMesh-Sandboxd-Token": token},
            json={"command": ["echo", "hi"], "working_directory": "/challenge"},
        )
        assert executed.status_code == 200
        assert executed.json()["stdout"] == "hi\n"
        escaped = client.post(
            f"/v1/workspaces/{workspace_id}/exec",
            headers={"X-CTFMesh-Sandboxd-Token": token},
            json={"command": ["id"], "working_directory": "/etc"},
        )
        assert escaped.status_code == 422


def test_private_workspace_routes_fail_closed_without_a_capability(tmp_path: Path) -> None:
    """An enabled manager with no configured internal secret cannot create a box."""

    manager, _engine = _service(tmp_path)
    # A local Power `.env` may define the service credential for Docker.  Pass
    # `None` explicitly to exercise the fail-closed missing-capability branch.
    app = create_sandboxd_app(
        SandboxdSettings(power_enabled=True, sandboxd_token=None),
        workspace_service=manager,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/workspaces",
            json={"run_id": "run-no-token", "archive_digest": _digest("missing")},
        )
    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "sandboxd_capability_not_configured"}}
