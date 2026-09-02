# Power Pi M-PI-3 worklog — compaction and usage ledger

## Started — 2026-09-01

### Objective

Configure Pi's reviewed in-memory compaction settings for Power sessions and
record bounded harness usage as observability. Provider-reported usage must
never expand, release, or otherwise weaken the durable Power cost ceiling.

### Invariant

- Pi compaction stays in the runner session only; its summaries and transcripts
  never enter the API, event ledger, sandbox, or challenge workspace.
- Usage events may contain validated non-negative counters, a session label,
  and observed cost only. They never carry prompts, responses, tool
  inputs/outputs, credentials, targets, candidates, or raw flags.
- A compact failure is observable but cannot solve a run, release a budget cap,
  or manufacture a tool observation.

### External architecture comparison

`verialabs/ctf-agent` validates the useful performance pattern: coordinator
plus independent, parallel model swarms, isolated CTF-tool containers, shared
findings, loop detection, and per-agent usage tracking. CTFMesh already owns
the equivalent safe primitives: Power A/B/C Pi sessions, `sandboxd`,
append-only events, immutable artifacts, and flag-router verification.

CTFMesh deliberately does **not** adopt that repository's raw shared-message
list or direct Docker sandbox control. Here, cross-racer data remains typed,
redacted, and evidence-bound; only `sandboxd` has the opt-in Docker socket;
the Pi runner never runs a host shell or receives provider keys in its
environment. M-PI-3 adopts only the compatible idea of harness usage telemetry
and bounded context maintenance.

### Initial plan

1. Verify the exact Pi 0.84.4 settings schema and place Power-specific
   `compaction.enabled`, `reserveTokens=8192`, and `keepRecentTokens=6000` in
   the existing in-memory reviewed settings manager.
2. Project only validated Pi assistant/compaction usage into a new, bounded
   control-plane receipt; a positive observed cost may debit, never credit or
   widen, the durable budget ceiling.
3. Add a long fixture that proves compaction occurs and a subsequent prompt
   still works. Add a deny-path proving compaction error cannot solve a run.

### Status

Complete — 2026-09-01.

### Implementation

- Added the Power-only, in-memory Pi policy:
  `compaction.enabled=true`, `reserveTokens=8192`, and
  `keepRecentTokens=6000`. The ordinary v0.1 session path does not inherit
  this override and no user Pi config file is written.
- Added `PowerUsageReporter`, which reads only Pi's settled cumulative session
  stats and completed-compaction events. It calculates a monotonic delta and
  starts from a reopened session's existing totals, preventing a runner restart
  from re-charging old transcript usage.
- Added the static authenticated control route `power-usage`. It revalidates
  the active session lease, writes an append-only counter-only
  `power.pi.usage` event, and debits a positive observed cost through the
  existing `max_cost_usd` ledger. It has no route to prompts, completions,
  commands, artifacts, keys, targets, or flags.
- Added console projection for observed Pi cost and compaction count, so the
  operator can distinguish a real usage measurement from the historical
  reservation display.
- Strengthened the compaction fixture to send three 64 KiB fake observations
  through the actual `ctf_fs_read` custom-tool adapter. This proves that Pi's
  normal tool-result transcript—not an artificial prompt-only path—can be
  compacted and then resumed.

### Fixture token measurement

The deterministic offline fixture had **34,485** context tokens immediately
before compaction. After Pi wrote its summary and the next normal tool-capable
turn completed, it reported **23,528** context tokens: a reduction of 10,957
(31.8%). The retained context can exceed the nominal 6k target when a safe
turn boundary requires a whole recent turn to remain intact; `keepRecentTokens`
is a cut-point target, not permission to split a tool turn. The follow-up
prompt completed successfully.

### Focused validation

- `pnpm --filter @ctfmesh/pi-runner check` — passed: 8 files / 41 tests.
- `pnpm --filter @ctfmesh/web check` — passed: 3 files / 16 tests and a
  production Vite build.
- Isolated Docker Python test: `tests/integration/test_power_operator_api.py`
  plus the Power console usage projection — passed: 5 tests.
- Isolated full Python gate — passed: 378 passed, 14 skipped, 1 upstream
  deprecation warning, in 317.36 seconds.
- Docker static gate (`ruff check`, `ruff format --check`, `pyright`) — passed:
  0 diagnostics.
- `docker compose config --quiet`, `docker compose --profile power config
  --quiet`, and `git diff --check` — passed.
- Docker rebuild: `docker compose --profile power up -d --build api
  pi-runner-live` — passed; API healthy and Pi runner polling.

### Remaining risk

Pi usage is settled after a model turn. The durable budget ceiling remains the
authority for starting work; a usage receipt can only debit that ceiling and
the next turn cannot use a receipt to extend it. Provider-side billing is
ultimately provider-reported telemetry, so M-PI-5 must compare real measured
usage rather than infer cost savings from this fixture.

## Post-completion worker recovery regression — 2026-09-02

### Observed failure

- The append-only ledger proved that AutoPrompter and racers A/B/C were queued
  and leased normally, then all four failed at the first Pi model turn. A
  local-only classification of their private transcripts identified HTTP 401
  authentication rejection; no provider response text or credential was
  printed, copied to an event, or persisted in Postgres.
- `pi-runner-live` later exited on `control_transport_failed` while the Control
  API was being recreated. Because the service had no restart policy and its
  claim loop treated a transient transport failure as fatal, subsequent runs
  had no live consumer.

### Fix

- Pi now reduces terminal provider diagnostics to a fixed allowlist of safe
  failure codes (authentication, rate limit, quota, model, transport, upstream
  availability, or generic failure). Raw SDK/provider text remains exclusively
  in the private Pi transcript.
- The console projects only those fixed codes to short operator messages. An
  unknown or hostile failure string produces no detail, preserving the
  no-transcript/no-secret boundary.
- The runner claim loop retries only `control_transport_failed` and
  `control_request_timeout` with bounded exponential backoff. Other protocol
  errors still fail closed. Compose additionally gives the live runner
  `restart: unless-stopped` for process-level recovery.

### Validation

- Pi focused gate: **8 files / 43 tests passed**, including transient reconnect,
  non-transient fail-closed, and provider-error classification regressions.
- Web focused gate: **4 files / 24 tests passed** plus a production Vite build;
  hostile non-allowlisted failure text is not rendered.
- Python focused gate in the repository test image: **8 passed, 2 skipped**;
  Ruff passed and the post-format check is clean.
- Docker recovery proof: after rebuilding the Power stack, restarting `api`
  produced bounded `control_transport_retry` codes while `pi-runner-live`
  remained running and reconnected. No provider key was used for this proof.
- Full Python gate in the repository test image: **382 passed, 14 skipped**
  (Docker-unavailable integration paths), with one upstream Starlette warning.
  Full Ruff format/check and Pyright gates passed with **0 errors**; both
  default and Power Compose models plus `git diff --check` passed.

## Post-completion DeepSeek tool compatibility — 2026-09-02

### Root cause

The next real Power run reached `deepseek-v4-pro` with an accepted credential,
but all four model turns ended before producing tokens. Private transcript
classification showed an `invalid_request_error` for
`tools[0].function.name`: the Pi-visible names used a dot (`ctf.fs_list`), while
the provider accepts only portable function-name characters. No raw provider
response or key crossed the runner boundary during diagnosis.

### Fix

- Renamed all 16 Pi-visible tools to the provider-portable `ctf_*` namespace,
  including `ctf_fs_list` and `ctf_flag_submit`. Internal typed control actions,
  sandbox scope, leases, artifact evidence and independent verification are
  unchanged.
- Updated the reviewed Power system prompt, controller brief, faux-provider
  fixtures and plan vocabulary. A regression now requires every exposed tool
  name to match `^[A-Za-z0-9_-]+$`.
- Added a fixed `power_pi_provider_tool_schema_rejected` diagnostic so a future
  provider ABI mismatch is distinguishable from authentication, quota or
  transport errors without storing its response text.
- At the operator's explicit request for this loopback-only installation,
  Settings now stores provider keys as plaintext in browser `localStorage` and
  loads them automatically. The legacy encrypted envelope is removed on first
  save. Keys still never enter Postgres, events, artifacts, sandbox/runtime
  tools, challenge volumes, URLs or a container environment; Pi receives only
  its existing short-lived in-memory lease for the active model call.

### Validation

- Pi gate: **8 files / 43 tests passed**.
- Web gate: **4 files / 24 tests passed** and production Vite build passed.
- Docker Power rebuild completed; API, Web and live Pi runner are online.
- Full Python and static gates were still running when this entry was written.

## Post-completion live activity projection regression — 2026-09-02

### Root cause

- The real run `run_600921986b8843eb933af93114ac0bc9` did reach DeepSeek through
  Pi. Its four leased sessions completed more than ninety typed sandbox actions
  before the operator cancelled it at 1 minute 48 seconds.
- The API persisted metadata-only `power.command.observed` receipts with the
  current closed action discriminant, but the Web overview accepted only older
  pre-Pi activity sentences and optional cumulative counters. It therefore
  rendered `0` and hid every action even while the model was actively using
  tools.

### Fix

- The Web projection now maps only the closed internal action vocabulary to
  fixed reviewed descriptions. Unknown action or activity text remains hidden;
  commands, arguments, paths, target traffic, model content, API keys and raw
  observations still cannot enter the race strip.
- Racer action and observation counters are derived from append-only receipts
  when older cumulative fields are absent. Existing explicit counters remain
  authoritative when present, so old and current runs share one projection.
- The compact racer card now labels the first counter `Actions`, which matches
  what the ledger measures instead of presenting a long Pi tool loop as an
  unexplained model `Turn 0`.

### Validation

- `pnpm --filter @ctfmesh/web check` — passed: 4 files / 25 tests and the
  production Vite build.
- Docker rebuilt Web/API successfully; both services became healthy.
- Playwright opened the exact historical run through `127.0.0.1:5173` and
  observed A=`24/24`, B=`22/22`, C=`28/28` actions/observations. No command,
  provider response or secret was rendered.
- Full Python run completed with **381 passed, 14 skipped** and one environment
  failure because the ad-hoc test container did not export its virtualenv on
  `PATH`; the affected E2E file then passed **3/3** with the repository PATH,
  making the effective gate **382 passed, 14 skipped**. Ruff format/check and
  Pyright passed with zero diagnostics.
- Pi gate passed **8 files / 43 tests**. Both Compose models and
  `git diff --check` passed; the deployed API/Web/sandboxd dependencies are
  healthy and the live Pi runner is polling.
