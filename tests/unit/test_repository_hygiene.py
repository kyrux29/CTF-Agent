"""Release metadata invariants shared by every distributable workspace package."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _project_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("pyproject.toml")
        if not {".venv", "node_modules"}.intersection(path.parts)
    )


def test_every_workspace_package_declares_mit_license() -> None:
    project_files = _project_files()
    assert project_files
    for path in project_files:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        assert document["project"]["license"] == "MIT", path.relative_to(ROOT)

    for relative_path in (
        "package.json",
        "apps/web/package.json",
        "services/pi-runner/package.json",
        "tests/package.json",
    ):
        document = json.loads((ROOT / relative_path).read_text(encoding="utf-8"))
        assert document["license"] == "MIT", relative_path


def test_root_license_is_mit_without_obsolete_apache_notice() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert license_text.startswith("MIT License\n\nCopyright (c) 2026 CTFMesh contributors")
    assert "Permission is hereby granted, free of charge" in license_text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text
    assert not (ROOT / "NOTICE").exists()

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[MIT License](LICENSE)" in readme
    assert "[NOTICE](NOTICE)" not in readme


def test_product_trees_do_not_contain_test_or_support_files() -> None:
    """Keep deployable source reviewable without colocated repository tooling."""

    product_roots = (ROOT / "apps", ROOT / "packages", ROOT / "services")
    misplaced: list[Path] = []
    for product_root in product_roots:
        misplaced.extend(path for path in product_root.rglob("tests") if path.is_dir())
        misplaced.extend(product_root.rglob("*.test.*"))
        misplaced.extend(product_root.rglob("*.spec.*"))
    assert misplaced == []

    assert (ROOT / "tests" / "web" / "vitest.config.ts").is_file()
    assert (ROOT / "tests" / "pi-runner" / "tsconfig.json").is_file()
    assert (ROOT / "support" / "scripts" / "release_smoke.py").is_file()
    assert (ROOT / "support" / "examples").is_dir()


def test_raw_flag_policy_is_ui_reveal_only() -> None:
    """The repository policy allows local display, not durable leakage."""

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    usage = (ROOT / "docs" / "usage-guide-vi.md").read_text(encoding="utf-8")

    assert "Never log or persist API keys, cookies, bearer tokens, raw flags" in agents
    assert "explicitly requests an input-candidate reveal" in agents
    assert "independent verifier has marked the run `solved`" in agents
    assert "one-time verified reveal" in agents
    assert "raw flag không hiển thị trong log/live output" in usage
    assert "ô **Raw flag**" in usage
