# UI U3 worklog — Console ba cột

**Milestone:** U3
**Started:** 2026-09-02
**Completed:** 2026-09-02
**Status:** Complete

## Invariant

Power console renders only the durable console snapshot: actual run state,
budget, per-racer counters, reviewed action summaries, and append-only lifecycle
events. It never renders model reasoning, provider payloads, raw command output,
argv, credentials, or an unrevealed flag.

## Implementation notes

- Work started after U1 and U2 acceptance gates passed.
- Added `RacerColumn.tsx`; its prop surface accepts only a label, validated
  state, counters, reviewed action summary, and optional hex fingerprint.
- Power Overview now projects three latest A/B/C receipts and a maximum of 12
  append-only activity rows. Unknown action/lifecycle text is dropped rather
  than rendered.
- Power header shows the real durable state (`Racing`, `Verifying`, terminal),
  elapsed/limit, and reserved cost/limit. It does not claim model thought.
- Stop still calls the tracked-run cancellation endpoint through `App.tsx`.
  A solved run now exposes the existing one-time Reveal API inside the console
  footer, followed by a read-only value and explicit Copy control.
- Removed the Power-only Run Index/custody rails from the Overview surface;
  Trace and Verification remain explicit tabs for the complete evidence path.
- Kept the racer role label neutral because M-PI-4 role specialization is the
  next unchecked harness milestone. Displaying static/dynamic/exploit now would
  invent state that is not present in the console snapshot.
- Repaired four stale Compose proof assertions left behind by M-PI-2: current
  tests require credential leases instead of provider-key environment variables,
  `pi-runner-live` instead of the removed `solver-runtime`, the source-slot
  initializer, and the current expanded Compose volume representation.
- U4 remains the next unchecked UI milestone and was not implemented in this
  slice, per the repository one-milestone protocol.

## Verification

- `pnpm --filter @ctfmesh/web check` — PASS; TypeScript, 19/19 Vitest,
  production Vite build.
- `pnpm --filter @ctfmesh/pi-runner check` — PASS; TypeScript, 41/41 Vitest.
- `uv lock --check` — PASS through a temporary uv 0.5.26 tool environment.
- `uv run ruff format --check .` — PASS; 284 files formatted.
- `uv run ruff check .` — PASS.
- `uv run pyright` — PASS; 0 errors, 0 warnings.
- `uv run pytest -q` — PASS; 386 passed, 6 skipped, one upstream Starlette
  deprecation warning.
- `uv run pytest -q tests/integration/test_compose_m3.py
  tests/integration/test_power_compose.py` — PASS; 8 passed.
- `docker compose config --quiet` — PASS.
- `docker compose up -d --build web` — PASS; Web and API healthy after rebuild.
- Rebuilding the API interrupted the already-running Pi worker as expected by
  its fail-closed transport behavior; `docker compose --profile power up -d
  pi-runner-live` restored the harness, which remained running with no new
  control error before handoff.
- Playwright smoke at `http://127.0.0.1:5173` — PASS on an existing Power run:
  real Racing header, three racer columns, reviewed activity rail, Stop, Trace,
  and Verification were all accessible in the embedded workbench.
- `git diff --check` — PASS.

The host did not provide `just` or `uv`, and its checked-out `.venv` contained
container-only `/app/.venv` shebangs. The same locked commands were therefore
run with uv 0.5.26 and a disposable environment under `/tmp`; no dependency or
lockfile was changed.
