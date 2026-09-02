"""Bounded source-observation tools used by the M3 tool gateway.

The generic ``files.*`` tools remain useful for local, operator-owned MCP
sessions.  Workers must instead use this ``source.*`` catalog, which makes
the capability visible in the sealed task manifest and gives the gateway a
stable production-facing name.  These tools never execute, unpack, or modify
challenge material.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import ClassVar

from pydantic import Field

from ._compat import ToolRisk
from .contracts import ToolContractModel, ToolInvocationContext, ToolSpec
from .files import (
    FilesListInput,
    FilesListOutput,
    FilesListTool,
    FilesReadInput,
    FilesReadOutput,
    FilesSearchInput,
    FilesSearchOutput,
    FilesSearchTool,
    _read_bounded_line_range,
    _workspace_root,
)

_MANIFEST_FILENAMES = frozenset(
    {
        "cargo.toml",
        "composer.json",
        "dockerfile",
        "gemfile",
        "go.mod",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)
_FRAMEWORK_MARKERS: tuple[tuple[str, str], ...] = (
    ("manage.py", "django"),
    ("next.config.js", "nextjs"),
    ("next.config.mjs", "nextjs"),
    ("nuxt.config.ts", "nuxt"),
    ("vite.config.ts", "vite"),
    ("vite.config.js", "vite"),
    ("wsgi.py", "wsgi"),
    ("asgi.py", "asgi"),
    ("app.py", "python-app"),
    ("main.py", "python-app"),
    ("main.go", "go-app"),
)
_ROUTE_PATH_MARKERS = frozenset({"api", "controllers", "handlers", "routes", "views"})


class SourceReadInput(FilesReadInput):
    """A source reader with the M3-mandated 32 KiB response ceiling."""

    max_file_bytes: int = Field(default=4 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_output_bytes: int = Field(default=32 * 1024, ge=1, le=32 * 1024)


class SourceManifestInput(ToolContractModel):
    """No caller-controlled paths are accepted for the whole-source summary."""


class SourceManifestOutput(ToolContractModel):
    """Deterministic metadata only; source content is deliberately absent."""

    file_count: int = Field(ge=0)
    manifest_paths: tuple[str, ...]
    framework_hints: tuple[str, ...]
    route_path_hints: tuple[str, ...]
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool


class SourceListTool(FilesListTool):
    """Production alias for bounded source-directory listings."""

    input_model: ClassVar[type[FilesListInput]] = FilesListInput
    output_model: ClassVar[type[FilesListOutput]] = FilesListOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="source.list",
        version="1.0.0",
        description="List bounded, read-only entries below the sealed challenge source root.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=FilesListInput,
        output_model=FilesListOutput,
        required_capabilities=("source.read",),
        default_timeout_seconds=5,
        max_output_bytes=256 * 1024,
    )


class SourceReadTool:
    """Production source reader with a smaller output ceiling than ``files.read``.

    This deliberately does not subclass :class:`FilesReadTool`: its input
    model is stricter, while a mutable class-level ``input_model`` declaration
    is invariant under static type checking. Both contracts use the same
    bounded implementation, so the security behavior stays identical.
    """

    input_model: ClassVar[type[SourceReadInput]] = SourceReadInput
    output_model: ClassVar[type[FilesReadOutput]] = FilesReadOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="source.read",
        version="1.0.0",
        description="Read at most 32 KiB of UTF-8 challenge source by line range.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=SourceReadInput,
        output_model=FilesReadOutput,
        required_capabilities=("source.read",),
        default_timeout_seconds=5,
        max_output_bytes=64 * 1024,
    )

    def requested_url(self, request: SourceReadInput) -> None:
        del request
        return None

    def requested_path(
        self,
        request: SourceReadInput,
        context: ToolInvocationContext,
    ) -> str:
        del context
        return request.path

    async def invoke(
        self,
        request: SourceReadInput,
        context: ToolInvocationContext,
    ) -> FilesReadOutput:
        return _read_bounded_line_range(request, context)


class SourceSearchTool(FilesSearchTool):
    """Production alias for literal-only, bounded source search.

    Regular expressions are intentionally not accepted by this first slot
    contract.  A future regex variant needs a reviewed, non-backtracking
    engine rather than exposing Python's potentially expensive regex engine
    to untrusted source text.
    """

    input_model: ClassVar[type[FilesSearchInput]] = FilesSearchInput
    output_model: ClassVar[type[FilesSearchOutput]] = FilesSearchOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="source.search",
        version="1.0.0",
        description="Search bounded UTF-8 challenge source files for a literal string.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=FilesSearchInput,
        output_model=FilesSearchOutput,
        required_capabilities=("source.read",),
        default_timeout_seconds=10,
        max_output_bytes=256 * 1024,
    )


class SourceManifestTool:
    """Produce a small deterministic inventory for role prompts and evidence.

    The scanner intentionally derives only filenames and structural hints. It
    never parses package manifests or returns source text, so a malicious
    challenge dependency file cannot influence a privileged parser here.
    """

    input_model: ClassVar[type[SourceManifestInput]] = SourceManifestInput
    output_model: ClassVar[type[SourceManifestOutput]] = SourceManifestOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="source.manifest",
        version="1.0.0",
        description="Return deterministic source inventory and framework/path hints only.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=SourceManifestInput,
        output_model=SourceManifestOutput,
        required_capabilities=("source.read",),
        default_timeout_seconds=5,
        max_output_bytes=128 * 1024,
    )

    def requested_url(self, request: SourceManifestInput) -> None:
        del request
        return None

    def requested_path(
        self,
        request: SourceManifestInput,
        context: ToolInvocationContext,
    ) -> str:
        del request, context
        # Supplying a logical root lets policy require an explicit workspace
        # scope while preserving that no worker-selected path reaches a host.
        return "."

    async def invoke(
        self,
        request: SourceManifestInput,
        context: ToolInvocationContext,
    ) -> SourceManifestOutput:
        del request
        root = _workspace_root(context)
        inventory, truncated = _bounded_inventory(root)
        manifest_paths = tuple(
            path for path in inventory if Path(path).name.lower() in _MANIFEST_FILENAMES
        )
        framework_hints = _framework_hints(inventory)
        route_path_hints = tuple(
            path
            for path in inventory
            if any(
                marker in {part.lower() for part in Path(path).parts[:-1]}
                for marker in _ROUTE_PATH_MARKERS
            )
        )[:128]
        digest_payload = {
            "files": inventory,
            "manifest_paths": manifest_paths,
            "framework_hints": framework_hints,
            "route_path_hints": route_path_hints,
            "truncated": truncated,
        }
        inventory_digest = hashlib.sha256(
            json.dumps(
                digest_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        ).hexdigest()
        return SourceManifestOutput(
            file_count=len(inventory),
            manifest_paths=manifest_paths[:128],
            framework_hints=framework_hints,
            route_path_hints=route_path_hints,
            inventory_sha256=inventory_digest,
            truncated=truncated,
        )


def _bounded_inventory(root: Path, *, max_files: int = 2_000) -> tuple[tuple[str, ...], bool]:
    """Walk without following symlinks and stop before inventory becomes unbounded."""

    files: list[str] = []
    truncated = False
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        # A symlink must not affect either traversal or reported metadata.
        directory_names[:] = sorted(
            name for name in directory_names if not (current_path / name).is_symlink()
        )
        for name in sorted(file_names):
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                continue
            if len(files) >= max_files:
                truncated = True
                return tuple(files), truncated
            files.append(path.relative_to(root).as_posix())
    return tuple(files), truncated


def _framework_hints(paths: tuple[str, ...]) -> tuple[str, ...]:
    """Map only fixed filenames to fixed labels; no challenge text is parsed."""

    names = {Path(path).name.lower() for path in paths}
    return tuple(label for marker, label in _FRAMEWORK_MARKERS if marker in names)


__all__ = [
    "SourceListTool",
    "SourceManifestInput",
    "SourceManifestOutput",
    "SourceManifestTool",
    "SourceReadInput",
    "SourceReadTool",
    "SourceSearchTool",
]
