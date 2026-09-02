# Power Pi M-PI-2 worklog — durable controller to runner

## Started — 2026-09-01

### Objective

Move the opt-in Power profile from Python's provider loop to durable Pi
sessions. The controller creates one AutoPrompter and three racers, while Pi
uses only the M-PI-1 custom tools through typed control routes.

### Invariant

- A Power model credential is an in-memory, session-scoped runner lease. It is
  never stored in a job, database row, event, artifact, workspace, or process
  environment.
- The control API mediates every sandboxd and flag-router request; the Pi
  runner has no Docker socket, shell, target URL, or service credential.
- Only an accepted flag-router decision may finish a Power run as solved. The
  controller then requests sibling aborts and keeps the five-second cleanup
  grace period.

### Implementation

- Added durable Power job kinds: `power_session_start`, `power_steer`, and
  `power_abort`, plus persisted Power session and steer records in migration
  `0008_power_pi_sessions`.
- `PowerRunController` now creates exactly one AutoPrompter and three racer
  workspaces, deposits a memory-only Pi credential lease per session, then
  queues durable session jobs. It passes only a bounded brief and an optional
  declared TCP allowlist.
- Pi Runner resolves Power work and tools only through authenticated static
  control routes. The API derives the workspace from job/session ownership and
  retains sandboxd and flag-router capabilities; Pi sees neither those tokens
  nor a target URL or Docker access.
- A flag-router acceptance queues aborts for every non-winning session before
  controller-owned workspace cleanup. Four live model turns can coexist with
  three bounded abort claims, and a ten-second heartbeat renews a live Power
  start lease until its session becomes terminal.
- Removed the Python model backend from the Power Compose path. The legacy
  solver-runtime module remains available only for isolated compatibility and
  fixture tests.

### Focused validation

| Command | Result |
|---|---|
| `pnpm --filter @ctfmesh/pi-runner check` | 37 Pi Runner tests passed. Includes four active Power starts plus three immediately claimable abort jobs. |
| `uv run pytest -q tests/integration/test_power_operator_api.py tests/unit/test_power_pi_composition.py tests/unit/test_power_runtime_bootstrap.py` | 9 passed. The no-key fixture creates four sessions, renews the live lease, derives workspace authority server-side, has flag-router re-read an artifact, solves, and aborts B/C. |
| `uv run pytest -q tests/integration/test_power_*.py tests/unit/test_power_*.py` | 67 passed, 8 skipped. |
| `docker compose config --quiet && docker compose --profile power config --quiet` | Passed for both default and opt-in Power models. |

### Full gates

The Docker-contained repository gate completed with resolved lock, frozen
sync, Ruff lint/format, Pyright (`0 errors, 0 warnings`), and `pytest -q`:
**377 passed, 14 skipped**. Pytest retains one existing FastAPI/TestClient
dependency deprecation warning.

### Assumptions and remaining risk

- Validation uses a no-key artifact fixture, not a real challenge or provider.
  A live operator still supplies the reviewed provider key only through the
  browser request and Pi's local in-memory lease broker.
- M-PI-2 intentionally keeps the bootstrap brief static. Category-specific
  compact briefs, compaction/usage ledger mapping, and their focused tests are
  reserved for the still-unchecked M-PI-3 and M-PI-4 milestones.

### Status

Completed 2026-09-01.

## Post-completion runtime repair — 2026-09-01

### Trigger

An operator Power run could reach a Pi assistant message but report a generic
connection error before its first custom-tool action. Older runs also showed
only queued racer placeholders, which made it impossible to distinguish an
idle racer from a failed model turn.

### Corrections

- The live Pi entry point now installs the reviewed proxy-aware Undici
  dispatcher used by Pi itself before constructing a model runtime. Node's
  `--use-env-proxy` setting alone did not configure Pi's bundled Undici client.
- `ctf.fs_list` uses BusyBox-compatible `find -print`; the Power workspace is
  Alpine-based and does not provide GNU `find -printf`.
- A terminal provider error is now a stable, secret-free session failure rather
  than an incorrect `ready` completion. The start lease heartbeat is stopped
  and awaited before job completion, eliminating a completion/renewal race.
- Every completed Power custom-tool request now creates a metadata-only
  `power.command.observed` event. The console can show a racer action and an
  immutable observation reference, while commands, paths, outputs, targets,
  prompts, candidates, flags, and credentials remain outside the event.

### Validation

| Command | Result |
|---|---|
| `pnpm --filter @ctfmesh/pi-runner check` | 38 passed, including provider-proxy dispatch and stable terminal-turn failure tests. |
| isolated `pytest` for `test_health_and_readiness` and `test_power_operator_api.py` | 5 passed after warming the test-only SQLite schema; no live provider key or challenge was used. |
| Live Pi probe with a deliberately invalid credential | Received HTTP 401 through the reviewed proxy instead of a connection error. |
| `docker compose --profile power up -d --build api pi-runner-live` | API healthy and live Pi runner polling. |
| isolated full Python gate (`ruff`, formatting, Pyright, `pytest -q`) | Completed with exit code 0. The fresh SQLite bootstrap was warmed first because initial schema creation can exceed the test framework's five-second startup window on a cold container filesystem. |
| `pnpm --filter @ctfmesh/web check` | 16 web tests passed; production Vite build completed. |

### Remaining operator step

Runs created before this repair cannot resume: their in-memory credential
leases disappeared when the runner was rebuilt. Start a fresh Power run from
the existing archive and selected model. The expected first visible receipt is
`Racer A/B/C: exec (running)`; its Trace entry identifies only the typed action
and immutable evidence reference. A `solved` state still requires a separate
flag-router verification, never a model claim.
