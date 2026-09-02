from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from ctfmesh_cli.main import _build_readonly_mcp_server, app
from ctfmesh_domain import ChallengeManifest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.memory import create_connected_server_and_client_session
from typer.testing import CliRunner

runner = CliRunner()
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _manifest() -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "cli-mcp-lab", "category": "forensics"},
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "inputs/evidence.bin", "role": "attachment"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:\-]+\}"],
                    "source_policy": {
                        "allow_from_target_response": False,
                        "allow_from_target_filesystem": False,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 2,
                },
                "limits": {
                    "wall_time_seconds": 60,
                    "max_worker_turns": 2,
                    "max_tool_calls": 4,
                    "max_http_requests": 1,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1,
                    "max_artifact_bytes": 1024 * 1024,
                },
                "providers": {"preferred": "operator-choice"},
                "memory": {
                    "namespace": "cli-mcp-lab",
                    "cutoff": "2026-07-26T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": ["files.list", "artifacts.inspect"],
            },
        }
    )


@pytest.mark.asyncio
async def test_mcp_cli_materializes_only_declared_artifacts(tmp_path: Path) -> None:
    challenge_root = tmp_path / "challenge"
    inputs = challenge_root / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "evidence.bin").write_bytes(b"declared CTF{redact_me}")
    (challenge_root / "unlisted.txt").write_text("must not be exposed", encoding="utf-8")
    server = _build_readonly_mcp_server(
        manifest=_manifest(),
        challenge_root=challenge_root,
        workspace=tmp_path / "workspace",
    )

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        listed = await session.call_tool("files_list", {"path": ".", "recursive": True})
        inspected = await session.call_tool("artifacts_inspect", {"path": "inputs/evidence.bin"})

    assert listed.isError is False
    assert isinstance(listed.structuredContent, dict)
    result = listed.structuredContent["result"]
    assert isinstance(result, dict)
    entries = result["entries"]
    assert isinstance(entries, list)
    assert {entry["path"] for entry in entries} == {"inputs", "inputs/evidence.bin"}
    assert inspected.isError is False
    assert "CTF{redact_me}" not in str(inspected.structuredContent)


@pytest.mark.asyncio
async def test_mcp_cli_serves_the_readonly_gateway_over_real_stdio(tmp_path: Path) -> None:
    challenge_root = tmp_path / "challenge"
    inputs = challenge_root / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "evidence.bin").write_bytes(b"declared artifact")
    manifest_path = challenge_root / "challenge.yaml"
    manifest_path.write_text(
        json.dumps(
            _manifest().model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude_defaults=True,
            )
        ),
        encoding="utf-8",
    )
    cli_command = shutil.which("ctfmesh")
    assert cli_command is not None, "The test environment must expose the ctfmesh CLI on PATH."
    parameters = StdioServerParameters(
        command=cli_command,
        args=["mcp", "serve", str(manifest_path)],
        cwd=str(REPOSITORY_ROOT),
    )

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            response = await session.call_tool("files_list", {"path": "."})

    assert {tool.name for tool in tools.tools} == {"files_list", "artifacts_inspect"}
    assert response.isError is False


def test_mcp_cli_help_and_scope_rejection(tmp_path: Path) -> None:
    help_result = runner.invoke(app, ["mcp", "serve", "--help"])
    assert help_result.exit_code == 0, help_result.output
    assert "local stdio" in help_result.output.lower()

    manifest_path = tmp_path / "challenge.yaml"
    payload = _manifest().model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude_defaults=True,
    )
    payload["spec"]["tool_profile"] = ["files.list"]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    rejected = runner.invoke(app, ["mcp", "serve", str(manifest_path)])
    assert rejected.exit_code != 0
    assert "tool_profile" in rejected.output
