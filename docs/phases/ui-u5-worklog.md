# UI U5 worklog — History management

**Milestone:** U5
**Started:** 2026-09-02
**Completed:** 2026-09-02
**Status:** Complete

## Invariant

History cleanup is presentation-only. Rename and hide operations must never
mutate or delete archive receipts, append-only events, evidence, custody data,
or verified results. The original server identifiers remain the navigation
authority and hidden entries are recoverable.

## Implementation notes

- Work started after all U4 acceptance gates passed.
- The visual direction remains the compact CTF operator rail: one filter, one
  per-row action button, and no additional dashboard or route.
- Added `HistoryPanel.tsx` so growing archive/run lists can be filtered by
  alias, original name or identifier, category, status, and timestamp metadata.
- Each row exposes a quiet, keyboard-labelled SVG action control on hover or
  focus. Rename opens an inline editor and preserves the immutable original
  name or run identifier as secondary metadata and navigation authority.
- Hide requires a second explicit confirmation. It stores a bounded local
  hidden-item preference and reports that evidence was not deleted; Restore
  clears the hidden set without losing aliases.
- Browser preferences are validated on load and bounded to 200 aliases and 500
  hidden identifiers. Corrupt or unsupported data fails back to an empty local
  preference set.
- Added focused tests for metadata filtering, alias persistence, hiding across
  remount, restoration, exact archive navigation, and absence of any network
  mutation during History management.
- No API endpoint, database record, archive receipt, run event, evidence,
  custody record, verified result, provider key, or Power/Pi contract changed.

## Verification

- `pnpm --filter @ctfmesh/web check` — PASS; TypeScript, 22/22 Vitest,
  production Vite build.
- `pnpm --filter @ctfmesh/pi-runner check` — PASS; TypeScript, 41/41 Vitest.
- `uv lock --check` — PASS through the existing temporary uv 0.5.26 tool
  environment; the resolved lock was unchanged.
- `uv run ruff format --check .` — PASS; 286 files formatted.
- `uv run ruff check .` — PASS.
- `uv run pyright` — PASS; 0 errors, 0 warnings.
- `uv run pytest -q` — PASS; 386 passed, 6 skipped, one upstream Starlette
  deprecation warning.
- `uv run pytest -q tests/integration/test_compose_m3.py
  tests/integration/test_power_compose.py` — PASS; 8 passed.
- `docker compose config --quiet` — PASS.
- Docker Web rebuild — PASS; Web and API healthy, Pi runner active.
- Playwright smoke at `http://127.0.0.1:5173` — PASS against real local
  History data: menu layout, inline rename, reload persistence, two-step
  hiding, restore, status filtering, and zero browser console errors.
- `git diff --check` — PASS. Browser screenshots and snapshots were moved out
  of the repository after visual inspection.

The host did not provide `just` or `uv` in `PATH`, and its checked-out `.venv`
contains container-only shebangs. The same locked commands were run through the
temporary uv environment already used by U3/U4; no dependency or lockfile
changed.
