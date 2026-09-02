# UI U4 worklog — Polish

**Milestone:** U4
**Started:** 2026-09-02
**Completed:** 2026-09-02
**Status:** Complete

## Invariant

Polish may improve keyboard containment, motion safety, and clarity, but it
must not widen browser authority, alter the Power/Pi protocol, expose secrets,
or weaken capability and independent-verification gates.

## Implementation notes

- Work started only after U3 acceptance gates passed.
- Scope is limited to reduced-motion, the Settings focus trap, targeted CSS
  consolidation, and the two U4 launch/reveal regression contracts.
- Settings now places initial focus on its Close control, contains forward and
  reverse Tab navigation, closes with Escape, and restores focus to the exact
  invoking Settings button. The trap exists only while the modal is mounted.
- Consolidated four scattered `prefers-reduced-motion` blocks into one final
  stylesheet safety net. It neutralizes drawer, window, status, drag, and panel
  motion while preserving immediate visible state and focus feedback.
- The Start control remains disabled when the capability endpoint reports the
  Power profile unavailable; the regression also proves no launch request is
  sent from that state.
- The verified-flag control latches the first reveal request immediately, so a
  double click cannot issue a second request. A failed request releases the
  latch for an explicit retry; a successful request remains one-shot and is
  replaced by the read-only revealed value.
- No Power/Pi endpoint, contract, authority boundary, provider-key path, or
  verification rule changed in U4.

## Verification

- `pnpm --filter @ctfmesh/web check` — PASS; TypeScript, 20/20 Vitest,
  production Vite build.
- `pnpm --filter @ctfmesh/pi-runner check` — PASS; TypeScript, 41/41 Vitest.
- `uv lock --check` — PASS through the existing temporary uv 0.5.26 tool
  environment; the resolved lock was unchanged.
- `uv run ruff format --check .` — PASS; 285 files formatted.
- `uv run ruff check .` — PASS.
- `uv run pyright` — PASS; 0 errors, 0 warnings.
- `uv run pytest -q` — PASS; 386 passed, 6 skipped, one upstream Starlette
  deprecation warning.
- `uv run pytest -q tests/integration/test_compose_m3.py
  tests/integration/test_power_compose.py` — PASS; 8 passed.
- `docker compose config --quiet` — PASS.
- `docker compose build web && docker compose up -d --no-deps web` — PASS;
  Web and API healthy, Pi runner still active.
- Playwright smoke at `http://127.0.0.1:5173` — PASS: initial modal focus,
  reverse/forward Tab wrapping, Escape restoration, reduced-motion media query,
  and zero browser console errors were observed against the Docker build.
- `git diff --check` — PASS. Browser trace/snapshot artifacts were moved out of
  the repository after inspection.

The host did not provide `just` or `uv` in `PATH`, and its checked-out `.venv`
contains container-only shebangs. The same locked commands were run through the
temporary uv environment already used by U3; no dependency or lockfile changed.
