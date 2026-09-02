# Power Pi M-PI-0 worklog — ADR and upstream pin

## Started — 2026-09-01

### Objective

Make the Pi SDK pin reproducible and record the authority boundary before any
Power controller or ACI integration changes. This milestone makes no live
provider request and does not inspect an operator credential or challenge.

### Upstream review

- Repository: `https://github.com/earendil-works/pi`
- Tag: `v0.84.4`
- Commit: `b79e4cc834970cca69daebffab7df1da7d1e52c4`
- Package: `@earendil-works/pi-coding-agent@0.84.4`
- npm integrity:
  `sha512-jmOlrqUmvhh/siNWFRXjYLJzhKFIHNsAQaysRwzQPQFnPAaV/vhqHsLH/MBsIISA1Rjj7WTUFR3nJrpXoLx39w==`
- License: MIT

The exact tag source exports the APIs required by the plan:
`createAgentSession`, `defineTool`, `SettingsManager.inMemory`,
`SettingsManager.applyOverrides`, and session `compact`, `steer`, and `abort`.
Its SDK contract supports `noTools: "all" | "builtin"`.

### Security boundary

- Pi is the future Power model harness, not policy, sandbox, evidence, budget,
  or verification authority.
- Built-in host tools stay disabled and challenge-local resource discovery stays
  denied.
- M-PI-0 changes only provenance, lock state, an import gate, and architecture
  documentation. Power still uses the old path until M-PI-2 acceptance passes.

### Status

Complete. The canonical ExecPlan marks only M-PI-0 complete; no M-PI-1 tool or
production controller edge was introduced.

### Changes

- Added ADR 0010 and registered this migration plan in `AGENTS.md`.
- Pinned Pi and every resolved Pi package to `0.84.4`; recorded the reviewed
  tag, commit, integrity, license, and SDK allowlist in `UPSTREAM.md`.
- Added a package-level regression for the imported factory/settings/session
  surface and a no-network compaction regression proving the summary request
  receives no custom tool definitions.
- Reused the existing reviewed-session tests to prove `noTools: "all"` leaves
  built-in `bash` and `read` unavailable and that challenge-local policy files
  are rejected.

### Verification

- `pnpm --filter @ctfmesh/pi-runner check`: TypeScript passed; **30 tests
  passed** across 6 files.
- Docker Python gate (`uv lock --check`, sync, Ruff lint/format, Pyright, full
  Pytest): lock/lint/format/type passed; **381 passed, 14 skipped, 1 dependency
  deprecation warning** in 287.24 seconds.
- `pnpm --filter @ctfmesh/web check`: TypeScript and production build passed;
  **16 tests passed**.
- Default and `power` Compose models both passed `config --quiet` with an empty
  environment file.
- `just check` and host `uv` were unavailable, so the repository's reproducible
  Docker `test` target ran the unchanged Python gates instead.

### Assumptions and remaining risk

- No live provider call was needed or made; this milestone validates the SDK
  contract and dependency pin, not provider quality.
- Power model traffic still follows the pre-migration Python implementation.
  M-PI-2, not this milestone, removes it from the production Compose path.
- M-PI-1 must add the typed Power tools and deny-path/truncation fixtures before
  any Power controller is connected to Pi.
