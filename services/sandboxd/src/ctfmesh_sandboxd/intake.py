"""Read-only materialization of an already validated archive intake."""

from __future__ import annotations

import io
import json
import os
import re
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_INTAKE_ID = re.compile(r"^intake_[0-9a-f]{32}$")
_CHUNK_BYTES = 1024 * 1024


class IntakeMaterializationError(RuntimeError):
    """Stable, non-sensitive failure returned by the private workspace API."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ChallengeArchive:
    """An in-memory tar built solely from the service-owned extracted tree."""

    digest: str
    payload: bytes
    file_count: int
    expanded_size_bytes: int


class ArchiveIntakeLocator:
    """Find a published intake by digest and copy regular files without links.

    `sandboxd` receives the artifact volume directly, never a browser path or
    raw archive stream. The API owns archive validation; this second check
    makes the process boundary resilient if the volume is tampered with.
    """

    def __init__(self, artifact_root: Path, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._root = artifact_root
        self._intakes = artifact_root / "archive-intakes"
        self._max_bytes = max_bytes

    def challenge_archive(self, digest: str) -> ChallengeArchive:
        """Return a bounded tar payload for the unique matching intake digest."""

        intake = self._find_intake(digest)
        workspace = intake / "workspace"
        if not _is_regular_directory(workspace):
            raise IntakeMaterializationError("archive_workspace_unavailable")
        payload, file_count, total_bytes = self._archive_workspace(workspace)
        return ChallengeArchive(
            digest=digest,
            payload=payload,
            file_count=file_count,
            expanded_size_bytes=total_bytes,
        )

    def _find_intake(self, digest: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise IntakeMaterializationError("archive_digest_invalid")
        if not _is_regular_directory(self._intakes):
            raise IntakeMaterializationError("archive_intake_unavailable")

        try:
            entries = sorted(self._intakes.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise IntakeMaterializationError("archive_intake_unavailable") from exc
        for entry in entries:
            if not _INTAKE_ID.fullmatch(entry.name) or not _is_regular_directory(entry):
                continue
            if self._report_digest(entry) == digest:
                # Equal SHA-256 source archives have the same immutable input
                # bytes. Choosing the first service-generated receipt keeps a
                # duplicate browser upload usable without accepting a path.
                return entry
        raise IntakeMaterializationError("archive_digest_not_found")

    @staticmethod
    def _report_digest(intake: Path) -> str | None:
        report = intake / "report.json"
        try:
            metadata = report.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                return None
            if metadata.st_size > 1024 * 1024:
                return None
            value = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        archive = value.get("archive") if isinstance(value, dict) else None
        candidate = archive.get("sha256") if isinstance(archive, dict) else None
        if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{64}", candidate):
            return candidate
        return None

    def _archive_workspace(self, workspace: Path) -> tuple[bytes, int, int]:
        stream = io.BytesIO()
        total_bytes = 0
        file_count = 0
        try:
            with tarfile.open(fileobj=stream, mode="w") as output:
                for relative, source in _walk_regular_tree(workspace):
                    metadata = source.lstat()
                    if stat.S_ISDIR(metadata.st_mode):
                        info = tarfile.TarInfo(f"{relative.as_posix()}/")
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o700
                        info.uid = 1000
                        info.gid = 1000
                        info.mtime = 0
                        output.addfile(info)
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise IntakeMaterializationError("archive_workspace_entry_invalid")
                    total_bytes += metadata.st_size
                    file_count += 1
                    if total_bytes > self._max_bytes:
                        raise IntakeMaterializationError("archive_workspace_too_large")
                    # `lstat` and O_NOFOLLOW prevent a local race from turning
                    # archive copy-in into an arbitrary host-file read.
                    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        with os.fdopen(descriptor, "rb", closefd=True) as input_file:
                            descriptor = -1
                            info = tarfile.TarInfo(relative.as_posix())
                            info.size = metadata.st_size
                            info.mode = 0o700 if metadata.st_mode & stat.S_IXUSR else 0o600
                            info.uid = 1000
                            info.gid = 1000
                            info.mtime = 0
                            output.addfile(info, input_file)
                    finally:
                        if descriptor >= 0:
                            os.close(descriptor)
        except IntakeMaterializationError:
            raise
        except (OSError, tarfile.TarError) as exc:
            raise IntakeMaterializationError("archive_workspace_materialization_failed") from exc
        return stream.getvalue(), file_count, total_bytes


def _is_regular_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def _walk_regular_tree(root: Path) -> list[tuple[PurePosixPath, Path]]:
    """Enumerate sorted directories/files and reject every link or special node."""

    result: list[tuple[PurePosixPath, Path]] = []
    try:
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            directories.sort()
            files.sort()
            relative_directory = current_path.relative_to(root)
            if relative_directory != Path("."):
                result.append((PurePosixPath(relative_directory.as_posix()), current_path))
            for name in directories:
                candidate = current_path / name
                if candidate.is_symlink() or not _is_regular_directory(candidate):
                    raise IntakeMaterializationError("archive_workspace_entry_invalid")
            for name in files:
                candidate = current_path / name
                metadata = candidate.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise IntakeMaterializationError("archive_workspace_entry_invalid")
                relative = PurePosixPath(candidate.relative_to(root).as_posix())
                if relative.is_absolute() or ".." in relative.parts:
                    raise IntakeMaterializationError("archive_workspace_entry_invalid")
                result.append((relative, candidate))
    except IntakeMaterializationError:
        raise
    except OSError as exc:
        raise IntakeMaterializationError("archive_workspace_materialization_failed") from exc
    return result


__all__ = ["ArchiveIntakeLocator", "ChallengeArchive", "IntakeMaterializationError"]
