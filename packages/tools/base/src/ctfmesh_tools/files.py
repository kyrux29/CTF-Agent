"""Bounded read-only workspace tools."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath
from typing import ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from ._compat import ToolRisk
from .contracts import ToolContractModel, ToolInvocationContext, ToolSpec


class WorkspaceAccessError(RuntimeError):
    pass


class WorkspacePathError(WorkspaceAccessError):
    pass


class WorkspaceFileError(WorkspaceAccessError):
    pass


def _validate_relative_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("path must be a POSIX workspace-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("path must remain below the workspace root")
    return str(path)


def _workspace_root(context: ToolInvocationContext) -> Path:
    if context.workspace_root is None:
        raise WorkspacePathError("workspace root is required")
    root = Path(context.workspace_root)
    if not root.is_absolute():
        raise WorkspacePathError("workspace root must be absolute")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise WorkspacePathError("workspace root does not exist") from exc
    if not resolved.is_dir():
        raise WorkspacePathError("workspace root is not a directory")
    return resolved


def _resolve_path(
    context: ToolInvocationContext,
    relative_path: str,
    *,
    expected: Literal["any", "file", "directory"] = "any",
) -> Path:
    safe_relative = _validate_relative_path(relative_path)
    root = _workspace_root(context)
    relative = PurePosixPath(safe_relative)

    # Reject every symlink component. This is intentionally stricter than merely
    # allowing symlinks whose current target is inside the workspace, avoiding a
    # simple swap-to-outside race between canonicalization and use.
    current = root
    for part in relative.parts:
        if part in {"", "."}:
            continue
        current = current / part
        try:
            if current.is_symlink():
                raise WorkspacePathError("symlink paths are not readable by workspace tools")
        except OSError as exc:
            raise WorkspacePathError("workspace path cannot be inspected") from exc

    try:
        candidate = (root / Path(*relative.parts)).resolve(strict=True)
    except OSError as exc:
        raise WorkspacePathError("workspace path does not exist") from exc
    if not candidate.is_relative_to(root):
        raise WorkspacePathError("workspace path escapes the canonical root")
    if expected == "file" and not candidate.is_file():
        raise WorkspaceFileError("workspace path is not a regular file")
    if expected == "directory" and not candidate.is_dir():
        raise WorkspaceFileError("workspace path is not a directory")
    return candidate


def _read_bounded_text(path: Path, *, max_bytes: int) -> str:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise WorkspaceFileError("workspace file cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise WorkspaceFileError("special devices and non-regular files are denied")
    if metadata.st_size > max_bytes:
        raise WorkspaceFileError("workspace file exceeds the configured byte limit")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise WorkspaceFileError("workspace file cannot be read") from exc
    if b"\x00" in payload:
        raise WorkspaceFileError("binary data is denied by text tools")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkspaceFileError("workspace file is not valid UTF-8 text") from exc


class FilesListInput(ToolContractModel):
    path: str = "."
    recursive: bool = False
    max_entries: int = Field(default=500, ge=1, le=10_000)

    _safe_path = field_validator("path")(_validate_relative_path)


class FileEntry(ToolContractModel):
    path: str
    kind: Literal["file", "directory", "symlink", "other"]
    size_bytes: int | None = Field(default=None, ge=0)


class FilesListOutput(ToolContractModel):
    entries: tuple[FileEntry, ...]
    truncated: bool


class FilesListTool:
    input_model: ClassVar[type[FilesListInput]] = FilesListInput
    output_model: ClassVar[type[FilesListOutput]] = FilesListOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="files.list",
        version="1.0.0",
        description="List bounded entries below the active workspace root.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=FilesListInput,
        output_model=FilesListOutput,
        default_timeout_seconds=5,
        max_output_bytes=1024 * 1024,
    )

    def requested_url(self, request: FilesListInput) -> None:
        return None

    def requested_path(
        self,
        request: FilesListInput,
        context: ToolInvocationContext,
    ) -> str:
        return request.path

    async def invoke(
        self,
        request: FilesListInput,
        context: ToolInvocationContext,
    ) -> FilesListOutput:
        root = _workspace_root(context)
        directory = _resolve_path(context, request.path, expected="directory")
        entries: list[FileEntry] = []
        truncated = False

        def add_entry(path: Path) -> bool:
            nonlocal truncated
            if len(entries) >= request.max_entries:
                truncated = True
                return False
            relative = path.relative_to(root).as_posix()
            try:
                metadata = path.lstat()
            except OSError:
                kind: Literal["file", "directory", "symlink", "other"] = "other"
                size: int | None = None
            else:
                if stat.S_ISLNK(metadata.st_mode):
                    kind = "symlink"
                elif stat.S_ISDIR(metadata.st_mode):
                    kind = "directory"
                elif stat.S_ISREG(metadata.st_mode):
                    kind = "file"
                else:
                    kind = "other"
                size = metadata.st_size if kind == "file" else None
            entries.append(FileEntry(path=relative, kind=kind, size_bytes=size))
            return True

        if request.recursive:
            for current, directory_names, file_names in os.walk(directory, followlinks=False):
                directory_names.sort()
                file_names.sort()
                current_path = Path(current)
                # Do not recurse into symlink directories even if the platform's
                # os.walk behavior changes.
                directory_names[:] = [
                    name for name in directory_names if not (current_path / name).is_symlink()
                ]
                for name in [*directory_names, *file_names]:
                    if not add_entry(current_path / name):
                        break
                if truncated:
                    break
        else:
            for child in sorted(directory.iterdir(), key=lambda path: path.name):
                if not add_entry(child):
                    break
        return FilesListOutput(entries=tuple(entries), truncated=truncated)


class FilesReadInput(ToolContractModel):
    path: str
    start_line: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    max_file_bytes: int = Field(default=1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_output_bytes: int = Field(default=256 * 1024, ge=1, le=1024 * 1024)

    _safe_path = field_validator("path")(_validate_relative_path)

    @model_validator(mode="after")
    def _ordered_lines(self) -> FilesReadInput:
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line cannot precede start_line")
        return self


class FilesReadOutput(ToolContractModel):
    path: str
    text: str
    start_line: int
    end_line: int
    total_lines: int
    truncated: bool


class FilesReadTool:
    input_model: ClassVar[type[FilesReadInput]] = FilesReadInput
    output_model: ClassVar[type[FilesReadOutput]] = FilesReadOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="files.read",
        version="1.0.0",
        description="Read a bounded UTF-8 line range below the workspace root.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=FilesReadInput,
        output_model=FilesReadOutput,
        default_timeout_seconds=5,
        max_output_bytes=512 * 1024,
    )

    def requested_url(self, request: FilesReadInput) -> None:
        return None

    def requested_path(
        self,
        request: FilesReadInput,
        context: ToolInvocationContext,
    ) -> str:
        return request.path

    async def invoke(
        self,
        request: FilesReadInput,
        context: ToolInvocationContext,
    ) -> FilesReadOutput:
        return _read_bounded_line_range(request, context)


def _read_bounded_line_range(
    request: FilesReadInput,
    context: ToolInvocationContext,
) -> FilesReadOutput:
    """Read a line range shared by compatible read-only tool contracts.

    ``SourceReadInput`` is a strict subtype of ``FilesReadInput`` with a lower
    output ceiling. Keeping the actual file operation in this helper lets the
    production ``source.read`` contract use that subtype without widening its
    public schema or inheriting a mutable class-level input-model declaration.
    """

    path = _resolve_path(context, request.path, expected="file")
    text = _read_bounded_text(path, max_bytes=request.max_file_bytes)
    lines = text.splitlines(keepends=True)
    end = min(request.end_line or len(lines), len(lines))
    selected = "".join(lines[request.start_line - 1 : end])
    encoded = selected.encode("utf-8")
    truncated = False
    if len(encoded) > request.max_output_bytes:
        selected = encoded[: request.max_output_bytes].decode("utf-8", errors="ignore")
        truncated = True
    return FilesReadOutput(
        path=request.path,
        text=selected,
        start_line=request.start_line,
        end_line=end,
        total_lines=len(lines),
        truncated=truncated,
    )


class FilesSearchInput(ToolContractModel):
    path: str = "."
    query: str = Field(min_length=1, max_length=4096)
    case_sensitive: bool = True
    max_files: int = Field(default=500, ge=1, le=10_000)
    max_matches: int = Field(default=200, ge=1, le=10_000)
    max_file_bytes: int = Field(default=1024 * 1024, ge=1, le=16 * 1024 * 1024)

    _safe_path = field_validator("path")(_validate_relative_path)


class SearchMatch(ToolContractModel):
    path: str
    line: int = Field(ge=1)
    column: int = Field(ge=1)
    preview: str


class FilesSearchOutput(ToolContractModel):
    matches: tuple[SearchMatch, ...]
    files_scanned: int = Field(ge=0)
    files_skipped: int = Field(ge=0)
    truncated: bool


class FilesSearchTool:
    input_model: ClassVar[type[FilesSearchInput]] = FilesSearchInput
    output_model: ClassVar[type[FilesSearchOutput]] = FilesSearchOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="files.search",
        version="1.0.0",
        description="Search bounded UTF-8 workspace files for a literal string.",
        risk=ToolRisk.READ_ONLY,
        idempotency="safe",
        input_model=FilesSearchInput,
        output_model=FilesSearchOutput,
        default_timeout_seconds=10,
        max_output_bytes=1024 * 1024,
    )

    def requested_url(self, request: FilesSearchInput) -> None:
        return None

    def requested_path(
        self,
        request: FilesSearchInput,
        context: ToolInvocationContext,
    ) -> str:
        return request.path

    async def invoke(
        self,
        request: FilesSearchInput,
        context: ToolInvocationContext,
    ) -> FilesSearchOutput:
        root = _workspace_root(context)
        search_root = _resolve_path(context, request.path)
        candidates: list[Path]
        if search_root.is_file():
            candidates = [search_root]
        elif search_root.is_dir():
            candidates = sorted(
                (
                    path
                    for path in search_root.rglob("*")
                    if path.is_file() and not path.is_symlink()
                ),
                key=lambda path: path.as_posix(),
            )
        else:
            raise WorkspaceFileError("search path must be a regular file or directory")

        matches: list[SearchMatch] = []
        scanned = 0
        skipped = 0
        truncated = False
        needle = request.query if request.case_sensitive else request.query.casefold()
        for path in candidates:
            if scanned >= request.max_files:
                truncated = True
                break
            try:
                text = _read_bounded_text(path, max_bytes=request.max_file_bytes)
            except WorkspaceFileError:
                skipped += 1
                continue
            scanned += 1
            for line_number, line in enumerate(text.splitlines(), start=1):
                haystack = line if request.case_sensitive else line.casefold()
                offset = haystack.find(needle)
                if offset < 0:
                    continue
                matches.append(
                    SearchMatch(
                        path=path.relative_to(root).as_posix(),
                        line=line_number,
                        column=offset + 1,
                        preview=line[:512],
                    )
                )
                if len(matches) >= request.max_matches:
                    truncated = True
                    break
            if truncated:
                break
        return FilesSearchOutput(
            matches=tuple(matches),
            files_scanned=scanned,
            files_skipped=skipped,
            truncated=truncated,
        )


__all__ = [
    "FileEntry",
    "FilesListInput",
    "FilesListOutput",
    "FilesListTool",
    "FilesReadInput",
    "FilesReadOutput",
    "FilesReadTool",
    "FilesSearchInput",
    "FilesSearchOutput",
    "FilesSearchTool",
    "SearchMatch",
    "WorkspaceAccessError",
    "WorkspaceFileError",
    "WorkspacePathError",
]
