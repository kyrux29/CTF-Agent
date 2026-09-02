"""Fixed, typed source/HTTP-slot implementation for M3.

This module deliberately contains no subprocess, shell, archive extraction,
or generic HTTP endpoint. A slot owns a single reviewed source mount selected
by the gateway and, when production composition injects a transport, can make
only typed alias-bound HTTP observations through its private slot network.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

import httpx
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest, ContractModel, Identifier
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_tools import (
    ArtifactInspectTool,
    SourceListTool,
    SourceManifestTool,
    SourceReadTool,
    SourceSearchTool,
    ToolDeniedError,
    ToolInputError,
    ToolInvocationContext,
    ToolOutputError,
    ToolRegistry,
    ToolRequest,
    ToolRuntime,
    ToolRuntimeError,
    ToolTimeoutError,
    TransformApplyTool,
    WorkspaceAccessError,
)
from pydantic import BaseModel

from .contracts import GatewayToolCall, SourceSlotInvocation, SourceSlotResponse, validate_output
from .http_slot import FixedHttpRequestTool
from .target_connector import TargetConnectorError, TargetConnectorTransport

_MAX_ASSIGNMENT_BYTES = 8 * 1024
_INTAKE_ID_PATTERN = re.compile(r"^intake_[0-9a-f]{32}$")
_DYNAMIC_SLOT_IDS = frozenset({"source-slot-1", "source-slot-2"})


@dataclass(frozen=True, slots=True)
class SourceSlotBinding:
    """Trusted manifest declaration selecting one dynamically materialized slot.

    This is deliberately a small runtime projection rather than a second
    manifest contract.  The domain package remains the authority for the
    ``spec.source`` schema; the tool runtime merely refuses to use a dynamic
    mount unless both identifiers are present and well-formed.
    """

    slot_id: str
    intake_id: str


class SourceSlotAssignment(ContractModel):
    """Backend-written metadata adjacent to, never inside, challenge content."""

    schema_version: Literal[1] = 1
    slot_id: Literal["source-slot-1", "source-slot-2"]
    challenge_id: Identifier
    intake_id: Identifier


def source_slot_binding(manifest: ChallengeManifest) -> SourceSlotBinding | None:
    """Return a valid dynamic source binding, without trusting archive content.

    ``spec.source`` is optional so all existing, curated M3 manifests keep
    their fixed challenge-to-slot behavior.  Runtime validation stays here as
    a defense in depth boundary in case a stale or foreign manifest reaches a
    slot process.
    """

    source = getattr(manifest.spec, "source", None)
    if source is None:
        return None
    slot_id = getattr(source, "slot_id", None)
    intake_id = getattr(source, "intake_id", None)
    if not isinstance(slot_id, str) or not isinstance(intake_id, str):
        return None
    if (
        not slot_id
        or not intake_id
        or slot_id not in _DYNAMIC_SLOT_IDS
        or _INTAKE_ID_PATTERN.fullmatch(intake_id) is None
    ):
        return None
    return SourceSlotBinding(slot_id=slot_id, intake_id=intake_id)


class SourceSlotError(RuntimeError):
    """Secret-free slot failure returned to the gateway, never raw exception text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SourceSlotClient(Protocol):
    """Narrow interface the gateway can later back with HTTP RPC."""

    slot_id: str

    # A fixed slot is mounted with source for exactly one curated challenge.
    # A dynamic slot instead has no configured challenge ID and gets a
    # backend-written assignment file outside its read-only archive mount.
    @property
    def challenge_id(self) -> str | None: ...

    def supports(self, call: GatewayToolCall) -> bool: ...

    def workspace_root(self) -> Path: ...

    async def invoke(self, invocation: SourceSlotInvocation) -> SourceSlotResponse: ...


class InProcessSourceSlot:
    """A fixed source mount adapter used by the local M3 vertical slice.

    The class satisfies the same ``SourceSlotClient`` protocol planned for the
    network RPC client.  Tests can therefore exercise the full gateway flow
    without starting a container or giving the gateway a host shell.
    """

    _BASE_SUPPORTED_TOOLS = frozenset(
        {
            "source.list",
            "source.read",
            "source.search",
            "source.manifest",
            "artifacts.inspect",
            "transform.apply",
        }
    )

    def __init__(
        self,
        *,
        slot_id: str,
        challenge_id: str | None,
        source_root: Path,
        assignment_path: Path | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not slot_id or any(character.isspace() for character in slot_id):
            raise ValueError("source_slot_id_invalid")
        if assignment_path is None and (
            not challenge_id or any(character.isspace() for character in challenge_id)
        ):
            raise ValueError("source_slot_challenge_id_invalid")
        if assignment_path is not None and challenge_id is not None:
            raise ValueError("source_slot_assignment_mode_invalid")
        if not source_root.is_absolute():
            raise ValueError("source_slot_root_invalid")

        dynamic_assignment = assignment_path is not None
        if dynamic_assignment:
            # A dynamic container starts before any archive has been assigned.
            # Therefore its source directory may not exist yet; every
            # invocation resolves it afresh after checking assignment metadata.
            root = source_root.resolve(strict=False)
            assert assignment_path is not None  # Narrowed by ``dynamic_assignment``.
            if not assignment_path.is_absolute():
                raise ValueError("source_slot_assignment_path_invalid")
            try:
                assignment_metadata = assignment_path.lstat()
            except FileNotFoundError:
                # Materialization happens after the long-lived slot starts.
                assignment_metadata = None
            except OSError as exc:
                raise ValueError("source_slot_assignment_path_invalid") from exc
            if assignment_metadata is not None and stat.S_ISLNK(assignment_metadata.st_mode):
                raise ValueError("source_slot_assignment_path_invalid")
            # Resolve only the configured parent. Resolving the final file
            # would silently follow a pre-existing symlink before the later
            # ``O_NOFOLLOW`` invocation-time check can protect it.
            configured_assignment = (
                assignment_path.parent.resolve(strict=False) / assignment_path.name
            )
            if configured_assignment.is_relative_to(root):
                raise ValueError("source_slot_assignment_path_inside_source_root")
            self._assignment_path: Path | None = configured_assignment
        else:
            try:
                root = source_root.resolve(strict=True)
            except OSError as exc:
                raise ValueError("source_slot_root_unavailable") from exc
            if not root.is_dir():
                raise ValueError("source_slot_root_not_directory")
            self._assignment_path = None
        self.slot_id = slot_id
        self.challenge_id = challenge_id
        self.dynamic_assignment = dynamic_assignment
        self._source_root = root
        self._http_transport = http_transport
        self._http_tool = (
            FixedHttpRequestTool(http_transport) if http_transport is not None else None
        )
        self._supported_tools = set(self._BASE_SUPPORTED_TOOLS)
        if self._http_tool is not None:
            self._supported_tools.add("http.request")
        registry = ToolRegistry()
        registry.register(SourceListTool())
        registry.register(SourceReadTool())
        registry.register(SourceSearchTool())
        registry.register(SourceManifestTool())
        registry.register(ArtifactInspectTool())
        registry.register(TransformApplyTool())
        if self._http_tool is not None:
            registry.register(self._http_tool)
        # The slot repeats schema/policy validation before a handler receives
        # data. Gateway persistence is authoritative for budgets and retries;
        # this local runtime is a second capability boundary for filesystem I/O.
        self._runtime = ToolRuntime(registry, PolicyDecisionPoint(), max_concurrency=1)

    def supports(self, call: GatewayToolCall) -> bool:
        return call.tool_name in self._supported_tools

    def workspace_root(self) -> Path:
        """Return a trusted configured mount, never a path supplied by Pi."""

        return self._source_root

    async def invoke(self, invocation: SourceSlotInvocation) -> SourceSlotResponse:
        """Execute one call through the typed runtime and return a typed envelope."""

        call = invocation.call
        if not self.supports(call):
            raise SourceSlotError("source_slot_tool_unavailable")
        authority = invocation.authority
        source_root = self._source_root
        if self.dynamic_assignment:
            source_root = self._dynamic_source_root()
            binding = source_slot_binding(authority.challenge_manifest)
            if binding is None:
                raise SourceSlotError("source_slot_binding_unavailable")
            assignment = self._read_assignment()
            if assignment.slot_id != self.slot_id:
                raise SourceSlotError("source_slot_assignment_mismatch")
            if (
                binding.slot_id != self.slot_id
                or binding.intake_id != assignment.intake_id
                or authority.challenge_id != assignment.challenge_id
            ):
                raise SourceSlotError("source_slot_assignment_mismatch")
        elif authority.challenge_id != self.challenge_id:
            raise SourceSlotError("source_slot_challenge_mismatch")
        if call.tool_name not in authority.context_manifest.allowed_tool_ids:
            raise SourceSlotError("source_slot_tool_not_allowed")
        # This tiny budget exists solely so the slot's second policy check can
        # validate the request shape. The gateway's transaction has already
        # reserved the real run budget before this code executes.
        budget = BudgetRemaining(
            tool_calls=1,
            http_requests=1 if call.tool_name == "http.request" else 0,
            cost_usd=0.0,
        )
        capabilities = {"source.read"}
        if call.tool_name == "artifacts.inspect":
            capabilities.add("artifact.inspection")
        if call.tool_name == "transform.apply":
            capabilities.add("transform.apply")
        if call.tool_name == "http.request":
            capabilities.add("target_http")
        context = ToolInvocationContext(
            run_id=authority.run_id,
            actor=ActorRef(kind=ActorKind.TOOL, id=self.slot_id),
            mode=authority.challenge_manifest.spec.mode,
            manifest=authority.challenge_manifest,
            allowed_tools=(call.tool_name,),
            budget_remaining=budget,
            approval_state=ApprovalState.NOT_REQUESTED,
            workspace_root=str(source_root),
            branch_id=authority.branch_id,
            task_id=authority.task_id,
            capabilities=frozenset(capabilities),
        )
        request = ToolRequest(
            tool=call.tool_name,
            version=call.tool_version,
            arguments=call.arguments.model_dump(mode="json"),
            idempotency_key=call.idempotency_key,
            invocation_id=invocation.invocation_id,
        )
        capability_context = None
        connector_transport = self._http_transport
        if call.tool_name == "http.request" and isinstance(
            connector_transport, TargetConnectorTransport
        ):
            if invocation.target_capability is None:
                raise SourceSlotError("target_capability_unavailable")
            try:
                capability_context = connector_transport.bind_capability(
                    invocation.target_capability
                )
            except TargetConnectorError as exc:
                raise SourceSlotError(exc.code) from exc
        try:
            result = await self._runtime.invoke(request, context)
        except ToolDeniedError as exc:
            raise SourceSlotError("source_slot_policy_denied") from exc
        except ToolInputError as exc:
            raise SourceSlotError("source_slot_input_invalid") from exc
        except ToolTimeoutError as exc:
            raise SourceSlotError("source_slot_timeout") from exc
        except (ToolOutputError, WorkspaceAccessError, ToolRuntimeError) as exc:
            raise SourceSlotError("source_slot_execution_failed") from exc
        except Exception as exc:  # pragma: no cover - last-line secret boundary.
            raise SourceSlotError("source_slot_execution_failed") from exc
        finally:
            if capability_context is not None:
                # ``capability_context`` can exist only after the explicit
                # TargetConnectorTransport narrowing above. Repeat it here so
                # static type checking and future transport refactors cannot
                # accidentally invoke a connector-only reset on another
                # HTTPX transport.
                if isinstance(connector_transport, TargetConnectorTransport):
                    connector_transport.reset_capability(capability_context)
        if result.output is None:
            raise SourceSlotError("source_slot_output_unavailable")
        output = validate_output(call, result.output)
        return SourceSlotResponse(
            invocation_id=invocation.invocation_id,
            tool_name=call.tool_name,
            tool_version=call.tool_version,
            output=output.model_dump(mode="json"),
        )

    def _dynamic_source_root(self) -> Path:
        """Resolve the configured dynamic mount without following a replacement link."""

        try:
            metadata = self._source_root.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise OSError("source root is not a directory")
            root = self._source_root.resolve(strict=True)
        except OSError as exc:
            raise SourceSlotError("source_slot_source_unavailable") from exc
        assignment_path = self._assignment_path
        if assignment_path is None:  # pragma: no cover - constructor invariant.
            raise SourceSlotError("source_slot_assignment_unavailable")
        # Recheck after materialization in case a bad mount layout would make
        # the assignment file readable from untrusted archive content.
        if assignment_path.is_relative_to(root):
            raise SourceSlotError("source_slot_assignment_unavailable")
        return root

    def _read_assignment(self) -> SourceSlotAssignment:
        """Read one small backend-written assignment with symlink/write checks.

        The file is deliberately opened for every request, so reassignment of
        a fixed slot cannot leave a stale in-process binding behind.  It is
        never searched for below ``/slot/challenge`` and no error text from
        its JSON is allowed across the source-slot boundary.
        """

        assignment_path = self._assignment_path
        if assignment_path is None:  # pragma: no cover - constructor invariant.
            raise SourceSlotError("source_slot_assignment_unavailable")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(assignment_path, flags)
        except OSError as exc:
            raise SourceSlotError("source_slot_assignment_unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or metadata.st_size > _MAX_ASSIGNMENT_BYTES
            ):
                raise SourceSlotError("source_slot_assignment_unavailable")
            body = bytearray()
            while len(body) <= _MAX_ASSIGNMENT_BYTES:
                chunk = os.read(descriptor, _MAX_ASSIGNMENT_BYTES + 1 - len(body))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) > _MAX_ASSIGNMENT_BYTES:
                raise SourceSlotError("source_slot_assignment_unavailable")
        except OSError as exc:
            raise SourceSlotError("source_slot_assignment_unavailable") from exc
        finally:
            os.close(descriptor)
        try:
            return SourceSlotAssignment.model_validate(json.loads(body))
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise SourceSlotError("source_slot_assignment_unavailable") from exc

    async def aclose(self) -> None:
        """Release slot-local HTTP session state when the service stops."""

        if self._http_tool is not None:
            await self._http_tool.aclose()


def parse_slot_output(call: GatewayToolCall, response: SourceSlotResponse) -> BaseModel:
    """Verify a slot cannot swap invocation/tool identity or output schema."""

    if response.tool_name != call.tool_name or response.tool_version != call.tool_version:
        raise SourceSlotError("source_slot_response_mismatch")
    try:
        return validate_output(call, response.output)
    except ValueError as exc:
        raise SourceSlotError("source_slot_output_invalid") from exc


__all__ = [
    "InProcessSourceSlot",
    "SourceSlotAssignment",
    "SourceSlotBinding",
    "SourceSlotClient",
    "SourceSlotError",
    "parse_slot_output",
    "source_slot_binding",
]
