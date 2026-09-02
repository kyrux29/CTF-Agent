"""Opt-in P3 proof: real GDB/PTY and a scoped TCP tube coexist with shell."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from base64 import b64encode
from pathlib import Path
from secrets import token_hex
from uuid import uuid4

import docker
import pytest
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
from ctfmesh_sandboxd.engine import DockerWorkspaceEngine
from ctfmesh_sandboxd.intake import ArchiveIntakeLocator
from ctfmesh_sandboxd.service import WorkspaceService, WorkspaceServiceError
from ctfmesh_tools import LocalArtifactStore
from docker.errors import DockerException

_ROOT = Path(__file__).resolve().parents[2]
_SOCKET = Path("/var/run/docker.sock")


def _enabled() -> bool:
    return os.environ.get("CTFMESH_RUN_POWER_DOCKER_SMOKE") == "1" and _SOCKET.exists()


def _plain_terminal(value: str) -> str:
    """GDB enables terminal colour even when Docker splits its raw socket output."""

    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_power_iat_gdb_pty_tube_and_shell_are_real_and_isolated(tmp_path: Path) -> None:
    """No model is involved: every assertion comes from a live tool observation."""

    if not _enabled():
        pytest.skip("set CTFMESH_RUN_POWER_DOCKER_SMOKE=1 with a Docker socket to run P3 smoke")
    flag = f"CTF{{p3_{token_hex(12)}}}"
    source_digest = hashlib.sha256(b"power-p3-iat").hexdigest()
    intake = tmp_path / "archive-intakes" / f"intake_{source_digest[:32]}"
    challenge = intake / "workspace"
    challenge.mkdir(parents=True)
    # The generated lab has no committed flag. The test alone knows the one
    # fixed input that makes this toy binary print its random flag.
    (challenge / "hello.c").write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "int main(void) {\n"
        "  char input[32] = {0};\n"
        "  fgets(input, sizeof input, stdin);\n"
        '  if (!strcmp(input, "open-sesame\\n")) {\n'
        f'    puts("{flag}");\n'
        "  } else {\n"
        '    puts("nope");\n'
        "  }\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    (challenge / "payload.txt").write_text("open-sesame\n", encoding="utf-8")
    (intake / "report.json").write_text(
        json.dumps({"archive": {"sha256": source_digest}}), encoding="utf-8"
    )

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\n")
        writer.write(b"echo:" + data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    # The regular opt-in test has a loopback fallback. The explicit Compose
    # smoke supplies this env var and exercises the same tube flow against
    # `tests/compose/power-tube-echo.yml` on its isolated bridge.
    echo_server: asyncio.base_events.Server | None = None
    external_echo_port = os.environ.get("CTFMESH_P3_TUBE_PORT")
    if external_echo_port is None:
        echo_server = await asyncio.start_server(echo, host="127.0.0.1", port=0)
        echo_socket = echo_server.sockets[0]
        assert echo_socket is not None
        echo_port = int(echo_socket.getsockname()[1])
    else:
        echo_port = int(external_echo_port)
    image = f"ctfmesh-power-workspace:p3-smoke-{uuid4().hex}"
    client = docker.DockerClient(base_url=f"unix://{_SOCKET}", version="auto", timeout=135)
    manager: WorkspaceService | None = None
    receipt = None

    async def read_until(pty_id: str, expected: str) -> str:
        """Docker may split a GDB banner/prompt across more than one PTY read."""

        chunks: list[str] = []
        for _ in range(4):
            observed = await manager.pty_read(  # type: ignore[union-attr]
                receipt.workspace_id,  # type: ignore[union-attr]
                pty_id,
                PtyReadRequest(wait_ms=2_000),
            )
            chunks.append(observed.data)
            combined = "".join(chunks)
            if expected in combined:
                return combined
        return "".join(chunks)

    try:
        client.images.build(
            path=str(_ROOT), dockerfile="images/power-workspace/Dockerfile", tag=image, rm=True
        )
        manager = WorkspaceService(
            engine=DockerWorkspaceEngine(
                socket_path=str(_SOCKET),
                image=image,
                memory_mb=256,
                cpu_millis=250,
                pids=128,
                work_tmpfs_mb=64,
                tmp_tmpfs_mb=16,
            ),
            intake_locator=ArchiveIntakeLocator(tmp_path, max_bytes=1024 * 1024),
            artifact_root=tmp_path,
            output_limit_bytes=64 * 1024,
            max_exec_timeout_seconds=120,
        )
        receipt = await manager.create(
            WorkspaceCreateRequest(
                run_id="power-p3-smoke",
                archive_digest=source_digest,
                tube_targets=(TubeTarget(host="127.0.0.1", port=echo_port),),
            )
        )
        compiled = await manager.exec(
            receipt.workspace_id,
            WorkspaceExecRequest(
                command=("gcc", "-g", "-O0", "/challenge/hello.c", "-o", "/challenge/hello"),
                working_directory="/challenge",
            ),
        )
        assert compiled.exit_code == 0

        gdb = await manager.pty_start(
            receipt.workspace_id,
            WorkspacePtyStartRequest(
                command=("gdb", "--quiet", "--nx", "/challenge/hello"),
                working_directory="/challenge",
            ),
        )
        banner = await read_until(gdb.pty_id, "(gdb)")
        assert "Reading symbols from" in _plain_terminal(banner)
        await manager.pty_send(
            receipt.workspace_id, gdb.pty_id, PtySendRequest(data="break main\n")
        )
        breakpoint = await read_until(gdb.pty_id, "Breakpoint 1")
        assert "Breakpoint 1" in _plain_terminal(breakpoint)
        await manager.pty_send(
            receipt.workspace_id,
            gdb.pty_id,
            PtySendRequest(data="run < /challenge/payload.txt\n"),
        )
        at_main = await read_until(gdb.pty_id, "Breakpoint 1, main")
        assert "Breakpoint 1, main" in _plain_terminal(at_main)
        await manager.pty_send(receipt.workspace_id, gdb.pty_id, PtySendRequest(data="continue\n"))
        continued = await read_until(gdb.pty_id, flag)
        assert flag in _plain_terminal(continued)

        # A second PTY and normal shell command can operate while GDB remains
        # paused: IAT sessions do not monopolize the workspace manager.
        python = await manager.pty_start(
            receipt.workspace_id,
            WorkspacePtyStartRequest(command=("python3", "-q")),
        )
        prompt = await manager.pty_read(
            receipt.workspace_id, python.pty_id, PtyReadRequest(wait_ms=2_000)
        )
        assert ">>>" in prompt.data
        shell = await manager.exec(
            receipt.workspace_id,
            WorkspaceExecRequest(command=("echo", "shell-alive")),
        )
        assert shell.stdout == "shell-alive\n"

        with pytest.raises(WorkspaceServiceError, match="tube_target_not_allowed"):
            await manager.tube_connect(
                receipt.workspace_id,
                TubeConnectRequest(host="127.0.0.1", port=echo_port + 1),
            )
        tube = await manager.tube_connect(
            receipt.workspace_id, TubeConnectRequest(host="127.0.0.1", port=echo_port)
        )
        await manager.tube_send(
            receipt.workspace_id,
            tube.tube_id,
            TubeSendRequest(data_base64=b64encode(b"live\n").decode("ascii")),
        )
        echoed = await manager.tube_recv_until(
            receipt.workspace_id,
            tube.tube_id,
            TubeRecvUntilRequest(delimiter_base64=b64encode(b"\n").decode("ascii")),
        )
        assert echoed.data == "echo:live\n"
        artifact_bytes = await LocalArtifactStore(tmp_path).get_bytes(
            echoed.observation_artifact.id
        )
        assert artifact_bytes == b"echo:live\n"
    except DockerException as exc:
        pytest.fail(f"Power P3 Docker smoke could not run: {type(exc).__name__}")
    finally:
        if manager is not None and receipt is not None:
            await manager.destroy(receipt.workspace_id)
        if echo_server is not None:
            echo_server.close()
            await echo_server.wait_closed()
        try:
            client.images.remove(image, force=True)
        except DockerException:
            pass
        client.close()
