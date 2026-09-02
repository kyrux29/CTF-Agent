# Power Pi M-PI-5 worklog — controlled raw evaluation

## Started — 2026-09-02

### Objective

Measure the Power-on-Pi implementation with raw, comparable evidence rather
than describing performance from an individual operator run.

### Evaluation invariant

- Use one authorized file-flag lab and one authorized toy Web or Pwn lab.
- Hold provider, exact model ID, model settings, wall-time cap, cost cap,
  tool cap, source bundle, and flag format constant per paired condition.
- Compare one Pi session (A) with AutoPrompter plus three Pi racers (B).
  Record the former Python ReAct implementation only as a clearly labelled
  historical reference (X), never as a live peer if its fixture differs.
- Record wall time, observed custom-tool actions, independently verified
  outcome, and Pi usage telemetry only when emitted. Do not put prompts,
  provider output, API keys, raw flags, or tool stdout in the report.

### Current status

No benchmark score has been recorded. Historical interactive runs are not a
valid M-PI-5 comparison: they used concurrent AutoPrompter/A/B/C sessions,
were stopped by the operator, and did not include a matching single-session
control. They are therefore excluded rather than being reinterpreted as a
performance claim.

Before any evaluation run, the flag-evidence contract was corrected: Pi now
submits an opaque, session-minted observation handle instead of asking a model
to recreate an artifact ID and digest. This allows a candidate to reach the
independent verifier only when it is bound to an actually observed result.

### Operator observability added — 2026-09-02

Each racer now emits a bounded, terminal-like record after every completed Pi
custom-tool operation. The record contains the reviewed command or operation,
its stdout/stderr result, exit/timeout state, and an output-cap marker. It is
useful for observing wasted paths and steering a racer before the next turn;
it is not hidden model reasoning and it does not decide a run outcome.

- The Pi runner redacts first, and the internal API redacts again before the
  append-only event is stored.
- Each terminal receipt has a runner-generated idempotency key, so a control
  transport retry during the same live Pi session does not duplicate a command
  in the operator timeline.
- API keys, cookie/bearer/session values, write/send payloads, flag candidates,
  and raw flags are absent; the UI rejects a malformed transcript containing
  any of those values as a final display defence.
- Command output is capped at 6 KiB for the terminal. The full bounded tool
  observation remains an immutable sandbox artifact and flag-router still
  verifies it independently.

This narrows debugging time for M-PI-5 live measurements without putting raw
tool output into the evaluation report required by the milestone.

### Validation completed before live measurement

- Pi custom-tool tests: **48 passed**, including valid/invalid observation
  handle submission paths and bounded terminal records for every custom tool.
- Web tests and production build: **28 passed**, including terminal rendering
  and client-side raw-secret rejection.
- Focused Power operator API test: **4 passed**, including API redaction of
  terminal command/output.
- Full reproducible Docker gate after the terminal change: **382 passed, 14
  skipped**; Ruff format/check and Pyright passed (one upstream Starlette
  deprecation warning only).
- `docker compose --profile power up -d --build --wait` rebuilt successfully;
  `/v1/ready` and `runtime-capabilities.power` both report `ready`.
- Power Compose rebuilt successfully; the local runtime capabilities endpoint
  reports `power: ready`.

### Remaining operator action

Run the two authorised labs with the same selected provider/model and caps,
export only the reviewed aggregate counters to
`docs/operations/power-pi-eval-YYYYMMDD.md`, and mark M-PI-5 complete only
when the resulting table makes no unsupported solve-rate claim.
