# Power Pi M-PI-4 worklog — compact brief, role lanes, and operator feed

## Started — 2026-09-02

### Objective

Reduce repeated reconnaissance across the three Power racers and give the
operator enough reviewed context to redirect a racer while Pi is working.

### Invariant

- The Power brief is generated only from the redacted archive-intake receipt;
  it is at most 2,000 characters and contains file names, a static excerpt,
  already-tried work, and category.
- Racer A/B/C retain independent Pi sessions but use distinct static,
  dynamic, and exploit-validation system roles. Pi built-in host tools remain
  disabled and only reviewed custom tools can produce observations.
- Duplicate `ctf_fs_read` coordination stores a SHA-256 fingerprint only. A
  filename, command argv, target response, raw tool output, candidate flag,
  API key, bearer token, cookie, and Pi hidden thinking never enters the
  event ledger or browser feed.
- The visible feed is not a chain-of-thought bridge. It contains only the
  CTFMesh-generated short brief, user steering instruction, and final
  assistant text blocks after runner/API redaction. Tool calls/results stay
  as typed metadata plus immutable artifact references.

### Implementation

- Added `PowerBriefContext` and receipt-derived `power_brief_context_from_intake`.
  The controller supplies every Power Pi session with a structured ≤2k brief
  rather than source text or an unbounded archive listing.
- Added distinct A/B/C Power system prompts: A maps static entry points and
  data flow, B pursues local/dynamic behavior, and C turns an observed
  weakness into a narrow scoped proof. The AutoPrompter remains unable to
  submit a flag.
- Added a trusted-adapter identity to `ctf_fs_read`. The API hashes its
  normalized `/challenge` or `/work` path and the repository atomically marks
  the later same-path read as `bumped`, adds a coordination receipt, and
  returns a fixed private nudge to choose a different evidence path.
- Added bounded `power.pi.activity` events, defensive API redaction, Pi
  runner extraction of visible assistant text only, and a compact per-racer
  **Pi feed** in the existing Power overview. The operator can send an
  idempotent suggestion to a live racer; Pi uses `session.steer()` while a
  turn is streaming and starts a new durable turn only from an idle boundary.

### Focused validation

- `tests/integration/test_power_operator_api.py` — **4 passed**. Includes the
  exact M-PI-4 duplicate `fs_read` path proof, brief bound/receipt fields,
  secret redaction, and a streaming steer that preserves its original tool
  authority.
- `pnpm --filter @ctfmesh/pi-runner check` — **9 files / 46 tests passed**.
  Includes feed extraction that excludes thinking/tool blocks and redacts a
  flag, bearer credential, and API key.
- `pnpm --filter @ctfmesh/web check` — **4 files / 26 tests passed** plus a
  production Vite build. Includes the racer input/output feed and Send control.
- Docker Python static gate (`ruff check`, `ruff format --check`, `pyright`)
  — passed with **0 diagnostics**. The test target supplies `libatomic` for
  Pyright without changing the production image.
- Full Python run — **381 passed, 14 skipped**, then the sole environment
  failure (`ctfmesh` CLI absent from an ad-hoc direct-Pytest PATH) was rerun
  with the same virtualenv PATH used by `uv run`: `test_mcp_cli.py` plus this
  Power integration file **7 passed**. The effective result is **382 passed,
  14 skipped**; one upstream Starlette deprecation warning remains.
- `docker compose --profile power config --quiet` and `git diff --check` —
  passed. The running user stack was not restarted during these checks.

### Remaining risk

The feed reports only text finalized by Pi, so a tool-only model turn can
remain quiet until its next reviewed tool receipt or final response. This is
intentional: streaming hidden reasoning, raw tool calls, or raw stdout would
make the UI more detailed but would violate the evidence and secret boundary.
M-PI-5 must measure whether the compact brief, lane separation, and duplicate
bump improve time-to-evidence and token use on real labs.

## Post-completion flag-evidence binding correction — 2026-09-02

### Root cause

The runner had correctly collected immutable observation artifacts, but the
Pi-visible `ctf_flag_submit` contract asked the model to reproduce the
artifact ID and SHA-256. A real model could copy or invent either value. The
flag router correctly rejected those submissions because a candidate must be
bound to the observed artifact that contains it. This was a contract/UX gap,
not a provider, worker, or verifier failure.

### Fix

- Each session now mints a monotonic opaque observation handle (`obs_N`) when
  a reviewed custom tool returns an observation. The handle is shown in the
  tool result with a fixed instruction to use it for `ctf_flag_submit`.
- The private per-session handle map resolves the real immutable artifact ID
  and SHA-256 only at submit time. It is discarded with the Pi session and is
  never written to a prompt, event, database, artifact, workspace, or browser
  projection.
- `ctf_flag_submit` no longer accepts model-controlled artifact IDs or
  digests. An unknown handle fails with a fixed safe code and never contacts
  the control API. A valid handle preserves the existing independent
  flag-router decision path.

### Validation

- `tests/pi-runner/power-tools.test.ts` now proves both a valid opaque-handle
  binding and rejection before control dispatch for `obs_999`.
- Web check: **26 tests passed** and production Vite build passed.
- Pi runner check: **47 tests passed**.
- Reproducible Docker Python gate: Ruff format/lint, Pyright, and
  **382 passed, 14 skipped** tests; the only warning is an upstream Starlette
  deprecation notice.
- Power Compose was rebuilt from this source. `/v1/ready` and
  `/v1/runtime/capabilities` both report ready, including `power: ready`.
