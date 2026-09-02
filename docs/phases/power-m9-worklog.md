# Power P9 worklog — raw evaluation and Power + Pi-harness scope

## Started — 2026-09-01

### Objective

Prepare a repeatable, raw-count Power evaluation receipt while reducing only
the checked-in surface that has no consumer in the authorized Power profile or
Pi execution harness. The cleanup must retain the independent flag-router,
typed sandbox boundary, append-only evidence, Docker-only operator path, and
Pi's reviewed-resource/typed-gateway path.

### Initial audit boundary

- Retain the Power path: archive intake, run/evidence database, Power API and
  UI, provider relay, typed ReAct runtime, `sandboxd`, flag-router, reviewed
  category packs, local knowledge, and the toolkit images.
- Retain the Pi harness and its typed gateway as the solver-harness foundation.
  They remain an execution adapter only: policy, sandboxd scope enforcement,
  evidence storage, and flag verification do not move into Pi. The cleanup
  must not remove their Compose edges, reviewed resource loader, credential
  lease, or deny-path coverage.
- Treat only the M5 synthetic labs and M6 fixture/evaluation surfaces as
  cleanup candidates, and only after imports, Compose edges, documentation,
  and test-only fixtures prove they have no Power or Pi-harness consumer.
- Do not make live provider calls or inspect operator secrets/challenges as
  part of this audit. Raw P9 figures require operator-authorized labs and are
  recorded separately once supplied.

### Audit result — 2026-09-01

- `pi-runner`, `pi-runner-live`, the credential lease, reviewed resource
  loader, task queue, and M3 typed gateway are retained. They are still the
  supported Pi harness path and have focused TypeScript and Compose coverage.
- The Power loop currently uses the separate typed ReAct solver runtime and
  `sandboxd`; it does **not** secretly route model actions through Pi. This is
  deliberate: Pi remains an execution adapter, not policy or verifier
  authority. A future adapter change must be separately planned and tested,
  rather than being hidden in source cleanup.
- M5/M6 labs and evaluation fixtures are retained for now: P9's required
  A/B/C/D comparison needs controlled challenge data, and their Compose/test
  edges are still active. No product source was deleted on an assumption.
- The main web operator surface was simplified to the Power flow: import one
  archive, select the three racers in Settings, optionally declare one TCP
  target, then monitor the run. Keys remain outside the main surface and are
  tab-memory by default; optional persistence uses the existing encrypted
  browser vault.

### Focused verification — 2026-09-01

| Command | Result |
|---|---|
| `pnpm --filter @ctfmesh/tests web:test -- --reporter=dot` | 16 passed |
| `pnpm --filter @ctfmesh/web check` | Type check, 16 web tests, production build passed |
| `pnpm --filter @ctfmesh/pi-runner check` | Type check and 28 Pi-harness tests passed |
| `docker compose --profile power config --quiet` | Passed |
| `docker compose --profile power up -d --build --wait` | Rebuilt Power stack; API, flag-router, sandboxd and Web healthy |

No provider request, flag reveal, or operator credential inspection was used
for this verification.

### Status

In progress: dependency graph and deletion set are being verified before any
destructive edit. P9 remains unchecked until a dated receipt contains raw
counts for the A/B/C/D matrix.
