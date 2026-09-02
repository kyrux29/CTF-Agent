"""Typer CLI for authorized manifest validation, triage, MCP, and evaluation."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml
from ctfmesh_db import Database, Repository
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest
from ctfmesh_evaluation import (
    PairedTriageEvaluation,
    VerifiedSolveEvaluation,
    evaluate_paired_triage,
    evaluate_verified_solves,
)
from ctfmesh_mcp_gateway import create_readonly_mcp_server
from ctfmesh_orchestrator import (
    MAX_READONLY_ARTIFACT_BYTES,
    ReadonlyWorkspaceError,
    TriageBackend,
    TriageOrchestrator,
    TriageRunError,
    materialize_declared_artifacts,
    resolve_challenge_root,
)
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_provider_openai_responses import (
    HttpxResponsesTransport,
    OpenAIResponsesTriageClient,
)
from ctfmesh_tools import (
    ArtifactInspectTool,
    FilesListTool,
    ToolInvocationContext,
    ToolRegistry,
    ToolRuntime,
)
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="ctfmesh",
    help="Evidence-first runtime for authorized multi-category CTF labs.",
    no_args_is_help=True,
)
challenge_app = typer.Typer(help="Validate authorized challenge manifests.")
triage_app = typer.Typer(help="Run bounded, read-only AI triage over declared CTF artifacts.")
benchmark_app = typer.Typer(help="Evaluate reviewed CTF triage records without a provider call.")
mcp_app = typer.Typer(help="Serve manifest-scoped, read-only CTF artifacts over local stdio MCP.")
dev_app = typer.Typer(help="Inspect the local development profile.")
app.add_typer(challenge_app, name="challenge")
app.add_typer(triage_app, name="triage")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(mcp_app, name="mcp")
app.add_typer(dev_app, name="dev")
console = Console()
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_RESULT_BYTES = 1024 * 1024
_MCP_READONLY_TOOLS = frozenset({"artifacts.inspect", "files.list"})


def _read_bounded_text(path: Path, *, max_bytes: int) -> str:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"file exceeds {max_bytes} byte limit")
    return raw.decode("utf-8")


def _ensure_empty_output_root(output: Path) -> None:
    """Reject stale report output before a new triage pass starts."""

    if output.exists():
        if not output.is_dir():
            raise ValueError("export_root_not_directory")
        if any(output.iterdir()):
            raise ValueError("export_root_must_be_empty")
        return
    output.mkdir(parents=True, exist_ok=False)


def version_callback(value: bool) -> None:
    if value:
        console.print("ctfmesh 0.1.0")
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True),
    ] = None,
) -> None:
    """CTFMesh only targets challenges for which you have explicit authorization."""
    del version


@app.command()
def doctor(
    require_compose: Annotated[
        bool, typer.Option(help="Treat Docker Compose as a required dependency.")
    ] = False,
) -> None:
    """Report local capabilities without printing credentials."""
    checks = [
        ("Python 3.12+", sys.version_info >= (3, 12), sys.version.split()[0]),
        ("Codex CLI (optional)", shutil.which("codex") is not None, "optional worker smoke"),
        ("Docker", shutil.which("docker") is not None, "full-stack profile"),
        (
            "Rootless OCI sandbox",
            False,
            "not proven by this command; production execution fails closed",
        ),
    ]
    table = Table(title="CTFMesh doctor")
    table.add_column("Capability")
    table.add_column("State")
    table.add_column("Note")
    for label, available, note in checks:
        table.add_row(label, "available" if available else "unavailable", note)
    console.print(table)
    required_ok = checks[0][1] and (not require_compose or checks[2][1])
    if not required_ok:
        raise typer.Exit(code=1)


@dev_app.command("info")
def dev_info() -> None:
    """Explain the local trust profile."""
    console.print(
        "Profile: local single-operator control plane\n"
        "Input: operator-supplied manifest and declared artifacts only\n"
        "Execution: read-only triage proposals; no model action is executed\n"
        "Production sandbox: unavailable until rootless OCI/gVisor checks pass"
    )


@challenge_app.command("validate")
def validate_manifest(path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    """Validate a manifest and print exact scope or structured errors."""
    try:
        raw = yaml.safe_load(_read_bounded_text(path, max_bytes=_MAX_MANIFEST_BYTES))
        manifest = ChallengeManifest.model_validate(raw)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            payload: Any = {
                "valid": False,
                "errors": [
                    {"path": ".".join(map(str, item["loc"])), "message": item["msg"]}
                    for item in exc.errors(include_url=False)
                ],
            }
        elif isinstance(exc, OSError):
            payload = {
                "valid": False,
                "errors": [{"path": str(path), "message": "manifest file could not be read"}],
            }
        else:
            payload = {
                "valid": False,
                "errors": [
                    {
                        "path": str(path),
                        "message": f"manifest rejected ({type(exc).__name__})",
                    }
                ],
            }
        console.print_json(data=payload)
        raise typer.Exit(code=1) from exc
    console.print_json(
        data={
            "valid": True,
            "name": manifest.metadata.name,
            "category": manifest.metadata.category.value,
            "target_type": manifest.spec.target.type,
            "tool_profile": list(manifest.spec.tool_profile),
            "skill_profile": list(manifest.spec.skill_profile),
            "allowed_endpoints": [
                endpoint.model_dump(mode="json")
                for endpoint in manifest.spec.target.allowed_endpoints
            ],
        }
    )


def _load_manifest(path: Path) -> ChallengeManifest:
    try:
        raw = yaml.safe_load(_read_bounded_text(path, max_bytes=_MAX_MANIFEST_BYTES))
        return ChallengeManifest.model_validate(raw)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, ValidationError) as exc:
        raise typer.BadParameter(
            "manifest is invalid; run `ctfmesh challenge validate` first"
        ) from exc


def _build_readonly_mcp_server(
    *,
    manifest: ChallengeManifest,
    challenge_root: Path,
    workspace: Path,
) -> Any:
    """Build a stdio-only MCP server over a disposable manifest-scoped workspace.

    This is intentionally separate from AI triage: no provider, API key,
    network tool, code execution, or persistent run is involved.  The caller
    owns the temporary directory lifetime, so a disconnected MCP client loses
    access to the copied local artifacts immediately.
    """

    if manifest.spec.target.type != "artifact_bundle":
        raise ValueError("mcp_target_must_be_artifact_bundle")
    missing_tools = _MCP_READONLY_TOOLS - set(manifest.spec.tool_profile)
    if missing_tools:
        raise ValueError("mcp_tools_not_declared")
    resolved_root = resolve_challenge_root(challenge_root)
    materialize_declared_artifacts(resolved_root, workspace, manifest, oversize="reject")

    registry = ToolRegistry()
    registry.register(FilesListTool())
    registry.register(ArtifactInspectTool())
    limits = manifest.spec.limits
    context = ToolInvocationContext(
        run_id=f"mcp_{uuid.uuid4().hex}",
        actor=ActorRef(kind=ActorKind.WORKER, id="mcp-client"),
        mode=manifest.spec.mode,
        manifest=manifest,
        allowed_tools=tuple(sorted(_MCP_READONLY_TOOLS)),
        budget_remaining=BudgetRemaining(
            tool_calls=limits.max_tool_calls,
            http_requests=limits.max_http_requests,
            cost_usd=limits.max_cost_usd,
        ),
        approval_state=ApprovalState.NOT_REQUESTED,
        workspace_root=str(workspace.resolve()),
        capabilities=frozenset({"artifact.inspection", "workspace.read"}),
    )
    runtime = ToolRuntime(registry, PolicyDecisionPoint())
    return create_readonly_mcp_server(runtime, context)


def _mcp_configuration_message(code: str) -> str:
    messages = {
        "mcp_target_must_be_artifact_bundle": (
            "MCP only serves an artifact_bundle target; it never attaches to a remote or "
            "Docker target"
        ),
        "mcp_tools_not_declared": (
            "manifest tool_profile must explicitly include artifacts.inspect and files.list"
        ),
        "challenge_root_unavailable": "challenge root could not be resolved",
        "challenge_root_not_directory": "challenge root must be a directory",
        "declared_artifact_unavailable": "a declared artifact is unavailable",
        "declared_artifact_symlink_denied": "a declared artifact contains a denied symlink",
        "declared_artifact_not_regular_file": "a declared artifact is not a regular file",
        "readonly_workspace_unavailable": "the disposable read-only workspace could not be created",
        "declared_artifact_copy_failed": "a declared artifact could not be copied safely",
        "declared_artifact_exceeds_readonly_limit": (
            f"a declared artifact exceeds the {MAX_READONLY_ARTIFACT_BYTES // (1024 * 1024)} MiB "
            "read-only MCP limit"
        ),
    }
    return messages.get(code, "MCP workspace could not be prepared safely")


def _live_openai_api_key() -> str:
    """Read a key only at the trusted CLI boundary and never print it."""

    if os.environ.get("CTFMESH_LIVE_PROVIDERS_ENABLED", "").strip().lower() != "true":
        raise typer.BadParameter(
            "live provider calls are disabled; set CTFMESH_LIVE_PROVIDERS_ENABLED=true "
            "in the current shell after reviewing the declared scope"
        )
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key.strip():
        raise typer.BadParameter("OPENAI_API_KEY is required in the current shell")
    return api_key


async def _run_triage(
    *,
    manifest: ChallengeManifest,
    challenge_root: Path,
    output: Path,
    backend: TriageBackend,
    api_key: str,
    model: str,
    provider_name: str,
    timeout_seconds: float,
) -> tuple[str, str]:
    await asyncio.to_thread(_ensure_empty_output_root, output)
    with tempfile.TemporaryDirectory(prefix="ctfmesh-triage-", dir=output.parent) as temp_dir:
        runtime_root = Path(temp_dir)
        database = Database(f"sqlite+aiosqlite:///{(runtime_root / 'ctfmesh.db').resolve()}")
        await database.create_schema()
        try:
            repository = Repository(database)
            orchestrator = TriageOrchestrator(repository=repository, artifact_root=runtime_root)
            result = await orchestrator.run(
                manifest=manifest,
                challenge_root=challenge_root,
                backend=backend,
                api_key=api_key,
                model=model,
                provider_name=provider_name,
                timeout_seconds=timeout_seconds,
            )
            await orchestrator.export(result, output)
            return result.run_id, result.proposal_artifact_id
        finally:
            await database.close()


async def _run_live_triage(
    *,
    manifest: ChallengeManifest,
    challenge_root: Path,
    output: Path,
    api_key: str,
    model: str,
    timeout_seconds: float,
) -> tuple[str, str]:
    transport = HttpxResponsesTransport()
    try:
        return await _run_triage(
            manifest=manifest,
            challenge_root=challenge_root,
            output=output,
            backend=OpenAIResponsesTriageClient(transport),
            api_key=api_key,
            model=model,
            provider_name="openai-responses",
            timeout_seconds=timeout_seconds,
        )
    finally:
        await transport.aclose()


@triage_app.command("run")
def triage_run(
    manifest_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    model: Annotated[
        str,
        typer.Option("--model", help="Explicit model identifier chosen by the operator."),
    ],
    challenge_root: Annotated[
        Path | None,
        typer.Option(
            "--challenge-root",
            help=(
                "Directory containing the manifest's declared artifact paths "
                "(defaults to manifest's directory)."
            ),
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="New or empty directory for the safe triage report."),
    ] = Path(".artifacts/triage"),
    timeout_seconds: Annotated[
        float,
        typer.Option("--timeout-seconds", min=1, max=300, help="Bound for the one model request."),
    ] = 30.0,
) -> None:
    """Call a live model once for static proposals; never execute its next actions."""

    manifest = _load_manifest(manifest_path)
    api_key = _live_openai_api_key()
    resolved_challenge_root = (challenge_root or manifest_path.parent).resolve()
    try:
        run_id, proposal_artifact_id = asyncio.run(
            _run_live_triage(
                manifest=manifest,
                challenge_root=resolved_challenge_root,
                output=output.resolve(),
                api_key=api_key,
                model=model,
                timeout_seconds=timeout_seconds,
            )
        )
    except TriageRunError as exc:
        console.print(f"[bold red]Triage stopped[/bold red] · {exc.code}")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        if str(exc) in {"export_root_not_directory", "export_root_must_be_empty"}:
            raise typer.BadParameter(
                "must be a new or empty directory; choose a fresh --output path"
            ) from exc
        raise
    console.print(f"[bold green]Triage completed[/bold green] · {run_id}")
    console.print(f"Proposal artifact: {proposal_artifact_id}")
    console.print(f"Safe report: {output.resolve()}")
    console.print(
        "Status: completed proposals only · no action executed · no verification attempted"
    )


@mcp_app.command("serve")
def mcp_serve(
    manifest_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    challenge_root: Annotated[
        Path | None,
        typer.Option(
            "--challenge-root",
            help=(
                "Directory containing the manifest's declared artifact paths "
                "(defaults to the manifest's directory)."
            ),
        ),
    ] = None,
) -> None:
    """Host only declared artifacts through local stdio; no provider/API key is used.

    Do not add a banner or other standard output here: stdio is the MCP
    protocol channel.  Configuration errors occur before the protocol starts.
    """

    manifest = _load_manifest(manifest_path)
    resolved_challenge_root = challenge_root or manifest_path.parent
    with tempfile.TemporaryDirectory(prefix="ctfmesh-mcp-") as temp_dir:
        try:
            server = _build_readonly_mcp_server(
                manifest=manifest,
                challenge_root=resolved_challenge_root,
                workspace=Path(temp_dir) / "workspace",
            )
        except (ReadonlyWorkspaceError, ValueError) as exc:
            code = exc.code if isinstance(exc, ReadonlyWorkspaceError) else str(exc)
            raise typer.BadParameter(_mcp_configuration_message(code)) from exc
        server.run(transport="stdio")


@benchmark_app.command("triage-evaluate")
def benchmark_triage_evaluate(
    input_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="Reviewed paired-triage JSON fixture."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional new JSON report path."),
    ] = None,
) -> None:
    """Calculate baseline-vs-AI triage metrics from independently reviewed records."""

    try:
        raw = json.loads(_read_bounded_text(input_path, max_bytes=_MAX_RESULT_BYTES))
        evaluation = PairedTriageEvaluation.model_validate(raw)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        raise typer.BadParameter("input must be a valid paired-triage JSON fixture") from exc
    report = evaluate_paired_triage(evaluation).model_dump(mode="json")
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is not None:
        if output.exists():
            raise typer.BadParameter("--output must not already exist")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        console.print(f"Evaluation report: {output.resolve()}")
    else:
        console.print_json(data=report)


@benchmark_app.command("verified-solve-evaluate")
def benchmark_verified_solve_evaluate(
    input_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            help="Reviewed M6 A/B/C verified-solve JSON receipt matrix.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional new JSON report path."),
    ] = None,
) -> None:
    """Aggregate offline verified-solve evidence; never run a model or target.

    The command accepts only the strict M6 receipt schema. It reports raw
    counts and gate failures alongside rates, so no caller can hide a solved
    state without its independent two-reset verifier proof.
    """

    try:
        raw = json.loads(_read_bounded_text(input_path, max_bytes=_MAX_RESULT_BYTES))
        evaluation = VerifiedSolveEvaluation.model_validate(raw)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        raise typer.BadParameter("input must be a valid M6 verified-solve JSON matrix") from exc
    report = evaluate_verified_solves(evaluation).model_dump(mode="json")
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is not None:
        if output.exists():
            raise typer.BadParameter("--output must not already exist")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        console.print(f"Verified-solve evaluation report: {output.resolve()}")
    else:
        console.print_json(data=report)
