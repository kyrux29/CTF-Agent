"""Remove only known generated CTFMesh development outputs.

The script deliberately has no path argument: it cannot be redirected to a
user directory or source tree. Use ``--dry-run`` to inspect its fixed target
list before removal.
"""

from __future__ import annotations

import argparse
import os
import shutil
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GENERATED_DIRECTORIES = (
    ".artifacts",
    ".coverage",
    ".mypy_cache",
    ".playwright-cli",
    ".pyright",
    ".pytest_cache",
    ".ruff_cache",
    ".hypothesis",
    "apps/web/dist",
    "coverage",
    "htmlcov",
    "output/playwright",
    "playwright-report",
    "services/pi-runner/dist",
    "test-results",
)
DEPENDENCY_DIRECTORIES = (
    ".venv",
    "node_modules",
    "apps/web/node_modules",
    "services/pi-runner/node_modules",
)
SOURCE_ROOTS = ("apps", "packages", "services", "tests", "support")
IGNORED_TREE_DIRECTORIES = frozenset({".vite", "coverage", "dist", "node_modules"})


def _inside_workspace(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    return True


def targets(*, include_dependencies: bool) -> Iterable[Path]:
    names = GENERATED_DIRECTORIES + (DEPENDENCY_DIRECTORIES if include_dependencies else ())
    for relative_path in names:
        candidate = ROOT / relative_path
        if candidate.exists() or candidate.is_symlink():
            yield candidate

    for relative_root in SOURCE_ROOTS:
        source_root = ROOT / relative_root
        if not source_root.is_dir():
            continue
        for current, directories, _ in os.walk(source_root):
            current_path = Path(current)
            if current_path.name == "__pycache__":
                yield current_path
                directories.clear()
                continue
            directories[:] = [name for name in directories if name not in IGNORED_TREE_DIRECTORIES]


def remove_path(path: Path) -> None:
    if not _inside_workspace(path):
        raise RuntimeError(f"refusing to remove a path outside the workspace: {path}")
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely remove generated CTFMesh outputs.")
    parser.add_argument(
        "--dependencies",
        action="store_true",
        help="also remove generated root/web node_modules directories",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print targets without removing them"
    )
    args = parser.parse_args()

    selected = targets(include_dependencies=args.dependencies)
    unique_targets = sorted({path.resolve() for path in selected})
    if not unique_targets:
        print("Nothing to clean.")
        return

    action = "Would remove" if args.dry_run else "Removing"
    for path in unique_targets:
        print(f"{action}: {path.relative_to(ROOT)}")
        if not args.dry_run:
            remove_path(path)


if __name__ == "__main__":
    main()
