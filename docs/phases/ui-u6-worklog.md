# UI U6 worklog — History lifecycle terminology

**Milestone:** U6
**Started:** 2026-09-02
**Completed:** 2026-09-02
**Status:** Complete

## Invariant

`Hide` is reversible browser presentation state. `Remove` is an explicit,
permanent server mutation and must never be simulated with local storage.
Only an archive receipt with no durable challenge/run reference may be
removed. Append-only run events, evidence, verification, custody records, and
their immutable artifact references are never deleted from History.

## Implementation notes

- The archive and run menus call the reversible action `Hide`, with Restore.
- `Remove` appears only for archive entries. It requires a separate destructive
  confirmation and then calls a dedicated API operation; it is never an alias
  for a local preference change.
- `DELETE /v1/archive-intakes/{intake_id}` repeats the exact server-issued ID in
  `X-Confirm-Remove`, serializes against both UI launch paths, and checks every
  durable challenge manifest before crossing the filesystem deletion boundary.
- The archive service validates a regular service-owned receipt directory,
  atomically moves it out of the visible catalog, and deletes its raw archive,
  private index, redacted report, and extracted workspace without following a
  planted top-level symlink.
- Explicit source bindings and the legacy generated Power challenge name both
  count as durable references. Referenced archives fail with
  `409 archive_intake_in_use`; no bytes are removed.
- Run rows expose Rename and Hide only. No `DELETE /v1/runs/{run_id}` route was
  added, so event/evidence/verification/custody history remains append-only.
- Tests cover Hide persistence and Restore, successful permanent removal,
  missing confirmation, repeated removal, durable-reference denial, legacy
  Power references, invalid IDs, and absence of a run hard-delete path.

## Verification

- `pnpm --filter @ctfmesh/web check` — PASS; TypeScript, 23/23 Vitest,
  production Vite build.
- `pnpm --filter @ctfmesh/pi-runner check` — PASS; TypeScript, 41/41 Vitest.
- `uv lock --check` — PASS through the existing temporary uv 0.5.26 tool
  environment; the resolved lock was unchanged.
- `uv run ruff format --check .` — PASS; 287 files formatted.
- `uv run ruff check .` — PASS.
- `uv run pyright` — PASS; 0 errors, 0 warnings.
- `uv run pytest -q` — PASS; 389 passed, 6 skipped, one upstream Starlette
  deprecation warning.
- `uv run pytest -q tests/integration/test_compose_m3.py
  tests/integration/test_power_compose.py` — PASS; 8 passed.
- `docker compose config --quiet` — PASS.
- Docker rebuild — PASS; API and Web are healthy at
  `http://127.0.0.1:5173`.
- Playwright browser smoke — PASS: temporary archive upload, distinct
  Hide/Remove confirmations, permanent archive removal (subsequent GET 404),
  linked-archive denial (subsequent GET 200), run menu without Remove,
  Hide/Restore, and a clean fresh browser console.
- `git diff --check` — PASS. The temporary browser archive and all generated
  Playwright snapshots/logs were removed after verification.

The host does not provide `just` or `uv` in `PATH`; the locked commands were
run through the existing temporary uv environment. No dependency or lockfile
changed in U6.
