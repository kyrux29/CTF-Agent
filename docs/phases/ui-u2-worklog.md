# UI U2 worklog — Power launch card

## Complete — 2026-09-02

### Objective

Implement only U2 from `CTFMesh-ui-design-guide.md`: extract the Power launch
surface, make launch readiness fail closed with stable missing codes, and show
the configured racer map as read-only data with one Settings action.

No Control API, Pi, sandboxd, provider credential, event, or verifier contract
changed.

### Design decision

The post-intake surface is one compact operator receipt rather than another
configuration form. It presents, in order, safe archive metadata, three racer
rows, the optional target boundary, limits, and one primary action. A single
status line reports machine-readable blockers such as `sandboxd`,
`provider_key:deepseek-chat`, or `target_authorization`.

### Implementation

- Extracted `PowerLaunch` to `apps/web/src/components/PowerLaunch.tsx`; the
  desk shell now supplies only receipt, settings projections, capabilities,
  credentials, and callbacks.
- Replaced the repeated archive dropzone after intake with a safe receipt:
  format, entry count, expanded bytes, truncated SHA-256, and heuristic
  category marked `suggested`.
- Made Racer A/B/C provider, model, and temperature read-only. Changes remain
  available only through `Edit in Settings`.
- Start is disabled until Power capability, required provider keys/models, and
  optional target validation/authorization are all ready. Missing reasons are
  deduplicated and never contain an API key or provider response.
- Added a compact `wall time · cost cap · racer count` line and reset launch
  form state when another archive is selected.
- Added responsive receipt layout for narrow screens and used the existing U1
  graphite/teal tokens for all new rules.

### Validation

- `pnpm --filter @ctfmesh/web check` — passed: TypeScript, 17/17 Vitest tests,
  and production Vite build.
- `pnpm --filter @ctfmesh/pi-runner check` — passed: 41/41 tests.
- Focused Power-on-Pi fixture — passed: one observed flag artifact was accepted
  independently, the run became SOLVED, and two sibling racers were aborted.
- Full Python gates in the repository test container — passed: lock check,
  Ruff format/lint, Pyright with 0 diagnostics, and 378 passed / 14 skipped.
- Default and Power Compose configuration validation — passed.
- Docker built the Web image from the repository Dockerfile and recreated only
  the Web service. API, Pi runner, sandboxd, flag router, and Web remained
  running; services with healthchecks reported healthy.
- Playwright smoke on the Docker URL — passed: U2 receipt/readiness rendering,
  archive selection, and browser console with 0 errors / 0 warnings.

### Gate environment note

The first full-test container invocation did not put `/workspace/.venv/bin` on
`PATH`; consequently one E2E subprocess could not discover the `ctfmesh` CLI
while 377 other tests passed. The failed test passed alone after normalizing
`PATH`, then the complete suite passed under that same environment. No test was
changed, skipped, or weakened.

### Demo boundary

The live Docker workbench is ready at `http://127.0.0.1:5173`. The isolated
Playwright profile deliberately had no provider key, so it verified the
fail-closed `provider_key:deepseek-chat` state instead of copying a secret from
the user's browser. A live provider solve starts after the operator unlocks or
adds the encrypted browser vault key. The no-network integration demo proves
the complete archive → Pi racers → observed flag → independent verification →
sibling abort contract.

### Remaining work

- U3 owns the three-column evidence console and Stop/Reveal presentation.
- M-PI-4 remains the next Power-on-Pi architecture milestone after the UI plan
  reaches the agreed handoff point.

### Cleanup

Stopped the temporary Vite proxy and browser, removed the isolated gate
containers, Playwright screenshot/snapshot files, repository bytecode, and
pytest caches. The Docker product stack, database, archive records, encrypted
browser vault, `.env`, and challenge data were not removed.
