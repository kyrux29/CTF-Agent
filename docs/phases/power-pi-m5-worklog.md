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

### Candidate lifecycle correction — 2026-09-02

An authorised reverse run exposed a false-positive route in the former
automatic capture shortcut. The shortcut extracted at most four bracketed
strings from a tool result and immediately sent the first format-matching
value to flag-router. Its provenance check proved only that the value occurred
in the observation—not that it was the unique intended flag. A decoy, encoded
intermediate, or value printed by a racer command could therefore end the race
before the other candidate paths were reviewed.

- Removed automatic candidate submission from every Power observation.
  `ctf_flag_submit` is retained only as a Pi compatibility hold; the browser
  selects a retained candidate for independent verification, and flag-router
  remains the only component that can mark a run solved.
- Added explicit `POST /v1/runs/{run_id}/candidate-flags/reveal`. It collects
  **every** broadly braced or manifest-format-matching value from all readable
  sandboxd observation artifacts recorded for the Power run, de-duplicates
  only identical values, and reports the contributing racer labels. It has no
  arbitrary four-candidate cap, including when the operator selects a
  non-braced literal format such as `FLAG-...`.
- The route reads artifact references from the ledger and rescans immutable
  bytes at request time. Raw values are returned only to the requesting local
  browser with `Cache-Control: no-store`; they are not inserted into events,
  database rows, prompts, or transcripts. If an artifact cannot be read,
  `scan_complete: false` and its count make the omission visible instead of
  silently hiding a candidate.
- The Power **Candidates** panel now has **Scan runtime** beside **Load from
  archive**. When a durable review gate is pending, **Confirm** selects one
  candidate for independent verification and **Wrong · continue** resumes the
  existing racers without sending its value to them.

Focused validation:

- Pi runner regression: flag-shaped output no longer creates any automatic
  flag-router call; Pi runner check: **51 passed**.
- API regression: six braced candidates plus one manifest-format-only
  candidate (more than the old four-item cap) are returned with both source
  racers, while the same values are absent from the durable run and events;
  focused API test: **2 passed**.
- Web regression: the explicit runtime scan loads candidates with racer
  attribution and uses a no-store request; Web check: **32 passed**.
- Ruff check/format and Pyright completed without findings.  Power Compose
  configuration validated and rebuilt API, Pi runner, and Web reached ready
  state.  A local rescan of the diagnostic run completed all **50** recorded
  observation artifacts and returned **2** review candidates.

### Per-run flag format — 2026-09-02

Power launch now accepts one optional literal format hint (`picoCTF{...}` or
`DUCTF{...}` for example). It is deliberately not a user regex and it is not a
candidate/flag value.

- The Control API normalizes the literal, derives a bounded capture pattern,
  and persists it with the new run's challenge manifest. When supplied, this
  is Power's exact automatic-capture filter; leaving it blank uses the normal
  Power fallback formats (`HTB{...}`, `CTF{...}`, `FLAG{...}`).
- The short Pi brief includes the selected hint so a racer can submit an
  observed candidate without guessing its format.
- On `ctf_flag_submit`, flag-router independently fetches the stored patterns
  using its own control-plane credential. It does not trust the calling API,
  runner, or model to provide a matching rule. It still re-reads the immutable
  sandboxd artifact and requires the candidate bytes to occur in it.
- The new private route exposes rules only to the flag-router credential and
  only for manifests tagged `power-profile`; it returns no candidate or secret.

### Exact wildcard capture correction — 2026-09-02

A local reverse run produced a valid `DH{...}` value whose body used standard
Base64 padding. The former literal-derived pattern allowed only letters,
numbers, `_`, `:`, and `-`; it therefore skipped `+`, `/`, or `=` and the
candidate review gate never opened for that observed value. Meanwhile, a
generic fallback could pause the race for an unrelated `CTF{...}` decoy.

- The format field now accepts `DH{*}` as the preferred wildcard spelling;
  the older `DH{...}` spelling remains compatible. The wildcard matches any
  bounded non-whitespace, non-brace body, including Base64 punctuation. Its
  literal prefix is case-exact, so `DH{*}` cannot pause on a lower-case
  `dh{...}` decoy.
- For Power only, an entered template is now the exact automatic-capture
  pattern. An empty field continues to use the reviewed generic fallback.
  This keeps a known contest prefix fast and prevents a different prefix from
  creating the first review pause.
- Candidate confirmation is additionally fenced to the artifacts and exact
  values in the current paused queue. A browser cannot submit an adjacent
  substring or stale observation merely because it appears elsewhere in the
  run history.
- Redaction at the API, database, Pi activity, console, and browser display
  boundaries uses the same braced-body character set, so a Base64 flag cannot
  leak into a durable transcript while it is waiting for local review.

Focused regression coverage: `DH{*}` derives a single exact manifest pattern;
an immutable observation containing a Base64-padded `DH{...}` value and a
`CTF{...}` decoy returns only the configured value to the automatic queue;
and Pi activity redacts the same Base64-shaped value before publication.

Validation for this correction:

- Docker Python 3.12 focused candidate/API tests: **6 passed**; this includes
  complete-match-only confirmation from the current queue.
- Full Docker Python suite: **396 passed, 14 skipped** (one upstream
  Starlette deprecation warning).
- `uv lock --check`, `ruff format --check .`, `ruff check .`, and `pyright`:
  passed with **0** type errors.
- `pnpm --filter @ctfmesh/pi-runner check`: **55 passed**; `pnpm --filter
  @ctfmesh/web check`: **35 passed** and production build completed.
- `docker compose --profile power up -d --build --wait` and `GET /v1/ready`:
  passed; API, Pi runner, sandboxd, flag-router, and Web are healthy.

M-PI-5 remains unchecked: this fixes the candidate correctness path but does
not replace the planned, paired authorised raw evaluation.

Focused validation after the change:

- Custom `picoCTF{...}` manifest → Pi brief → private resolver contract:
  **passed**.
- Custom candidate accepted only when present in a sandboxd artifact and the
  resolver returns that run's pattern: **passed**.
- Browser regex input is rejected; unauthenticated pattern lookup is rejected:
  **passed**.
- Web type/tests/production build: **28 passed**.
- Docker Power rebuild completed; API, flag-router, Pi runner, sandboxd and
  Web all report healthy/ready.

### Live-run diagnostic snapshot — 2026-09-02

This is an operational diagnosis of one authorised local reverse/file run,
not an M-PI-5 benchmark result.  It has no matching one-session control and
must not be used to claim a solve rate or a token improvement.

- After roughly eight minutes, A had reached its idle boundary after 34
  observed commands, C after 22, while B had 87 and AutoPrompter 76 commands
  and were still inside their first native Pi model turn.
- The two completed sessions had already reported 33,795 input and 12,122
  output tokens in total.  The two still-streaming sessions had not emitted a
  terminal Pi usage record yet, so those figures are a lower bound.
- No `ctf_flag_submit` action occurred.  The run therefore had no candidate
  for independent verification, rather than a verifier rejection.
- Pi currently waits for `session.waitForIdle()` for each initial Power job.
  There is no per-session tool-batch circuit breaker, so a model can keep
  issuing commands inside one provider turn.  Usage is flushed at the idle
  boundary, making an overlong turn both expensive and hard for the operator
  to price in real time.
- A cancelled historical run also left two start jobs reclaimable.  They
  repeatedly log `pi_job_lease_lost`; this is queue/log overhead, not the
  cause of the current sessions' successful tool calls, but should be
  terminalised before comparative measurement.

The next corrective slice must add a bounded per-session tool batch, flush
usage while a batch is in progress, narrow AutoPrompter's reconnaissance tool
surface, and terminalise stale cancelled-run jobs.  These changes require
focused regression tests before any new live evaluation.

### Performance corrective slice — 2026-09-02

- Pi now checkpoint-batches Power calls: a racer receives at most ten
  authorized tool actions in one native model turn and can make four focused
  continuation batches. Each continuation preserves the same Pi transcript,
  asks it to avoid repeated reconnaissance, and is still bounded by the
  run's existing wall-time, cost, and tool-call caps. A no-tool model result
  remains terminal for that racer.
- The batch boundary uses Pi's supported `steer()` operation rather than
  `abort()`: fixture coverage established that abort terminates the session
  and prevents a durable continuation. `ctf_flag_submit` is deliberately not
  counted, so an observed candidate can be submitted immediately after the
  final evidence action.
- AutoPrompter is limited to six actions and the minimal `fs_list`, `fs_read`,
  and argv-only `shell_exec` surface. It cannot consume interactive/GDB/TCP
  capacity intended for racers or submit a flag.
- Usage counters are now reported at custom-tool boundaries as well as final
  idle. They remain counter/cost deltas only; no Pi prompt, model response,
  command output, credential, or candidate crosses that telemetry path.
- Completing a Power abort now terminalises its paired leased start job. A
  repeated cancel also reconciles historical sessions already marked
  `aborted`, preserving the append-only cancellation event and preventing
  their start jobs from being reclaimed indefinitely. The local stale pair
  observed during diagnosis was reconciled through that idempotent cancel
  path after deployment.

Validation for this slice:

- Pi runner typecheck and tests: **50 passed**, including an SDK fixture that
  caps a native tool loop and then accepts a focused continuation, plus a
  regression proving flag submission remains available after the cap.
- Web check and production build: **28 passed**.
- Focused Power Pi fixture/API integration: **1 passed** (with six unrelated
  API cases deselected) in the reproducible Docker test image.
- `docker compose --profile power config --quiet` passed. Rebuilt API and
  Pi-runner services reached healthy/running state; the stale cancelled start
  jobs no longer appear in the runnable queue.

This establishes controllable measurement conditions; it is not an M-PI-5
comparison result. The one-racer/three-racer authorized lab runs remain the
next acceptance gate.

### Operator challenge description — 2026-09-02

- Added one optional **Description** field to the Power launch card. It
  accepts up to 1,000 characters for the challenge objective, organizer hint,
  or known behavior and is carried with the launch request into the shared
  first Pi brief for AutoPrompter and racers.
- The API collapses whitespace and redacts accidental flags, bearer values,
  API keys, and common secret assignments before the text can enter the
  durable brief. Events and run metadata retain only whether a description
  was configured; it is neither policy nor verifier evidence.
- Focused API test and Python Ruff/format checks passed in the reproducible
  Docker test image. Web typecheck, tests (**28 passed**), and production
  build passed. The API and Web services were rebuilt under the `power`
  profile.

### Retired automatic observed flag capture — 2026-09-02

The former automatic-capture shortcut described in an earlier M-PI-5 update
was retired after it proved capable of accepting a decoy or racer-emitted
value.  It must not be restored: the current candidate lifecycle is the
explicit, exhaustive runtime review documented above.  Historical test counts
for the retired shortcut are not a claim about the current behavior.

### Live racer I/O projection — 2026-09-02

- Each racer lane now keeps its most recent server-reviewed custom-tool
  receipt visible as a compact **Live I/O** cassette: the invoked command
  (`IN`), bounded result (`OUT`), tool name, exit status, timeout, and output
  cap state. While the racer is briefing or running, the cassette indicates
  that it is awaiting the next reviewed receipt instead of presenting a
  static terminal as current activity.
- The full receipt list is retained behind a collapsed **History** disclosure
  for that racer. This keeps all three lanes readable during a race without
  removing the operator's ability to inspect older, reviewed tool results.
- Command and output continue through the existing runner/API/browser
  redaction gates. Raw flags remain absent from the timeline and the live I/O
  view; after independent verification, the existing one-time verified-flag
  reveal is the sole raw browser hand-off.

Validation for this UI slice:

- Focused RunConsole test: **16 passed**, including the current Live I/O
  command/output projection and default-collapsed history.
- Full Web check: **28 passed** (TypeScript, Web tests, production build).
- `docker compose --profile power up -d --build --no-deps web` rebuilt the
  deployed Web image; the subsequent `up -d --wait --no-build web` completed
  with the Web and its required API dependencies healthy.
- `git diff --check` passed.

### Flag-router artifact-read repair — 2026-09-02

- Diagnosis of the latest authorized reverse run found that Pi had produced
  immutable tool observations and attempted automatic candidate capture, but
  flag-router returned `flag_observation_unavailable`. The router container
  used UID 65532 while sandboxd/API wrote owner-only (`0600`) artifact objects
  as UID 10001, so the independent re-read required before a solve was denied
  by the filesystem.
- The router now runs as the same **non-root numeric owner** (`10001:10001`)
  as the trusted artifact writers. Its mount remains read-only; it still has
  no Docker socket, no published port, no provider credential, and only the
  control network. This preserves owner-only artifacts rather than making
  every object group- or world-readable.
- Existing observations become readable after the router is redeployed. A
  cancelled run cannot be retroactively solved because its transient candidate
  was intentionally never persisted; a newly started run will submit a newly
  observed candidate through the repaired verifier path.

Validation for this repair:

- Rebuilt `flag-router` with the Power profile; it reached healthy state.
- In the running router, the prior owner-only observation is readable. A
  diagnostic non-matching candidate against it returns `200 {"accepted":
  false}` rather than `503 flag_observation_unavailable`, proving the router
  reached its provenance/pattern check without serializing a raw candidate.
- Compose static proof confirms the router has `user: "10001:10001"`, a
  single read-only artifact mount, and no Docker socket. `docker compose
  --profile power config --quiet` and `git diff --check` passed.
- Focused Compose regression: **2 passed**. Focused flag-router/API checks:
  **2 passed**. Pi runner typecheck and test suite: **52 passed**.

### Verified flag reveal placement — 2026-09-02

- The solved-state raw flag control moved from the console footer to a sticky
  banner directly under the Power run header.  A solved run now immediately
  shows a `Reveal flag` action without requiring the operator to scroll past
  racer lanes.
- The reveal remains a deliberate one-time API call.  It is not auto-fetched
  on refresh and it is not written to events, Live I/O, trace, artifacts, or
  the database.  After a successful reveal, the browser displays the raw flag
  in a read-only `Raw flag` field with a copy action.

Validation for this UI repair:

- Full Web check: **28 passed** (TypeScript, Web tests, production build).
- Rebuilt the deployed Web container with the Power profile; Web and required
  API dependencies reached healthy state.

### Raw flag display policy clarification — 2026-09-02

- The root repository policy now distinguishes durable leakage from local
  operator display. Raw flags remain forbidden in logs, events, artifacts,
  database rows, provider transcripts, sandbox/challenge mounts, and model
  prompts, but raw input candidates may be shown through explicit local
  candidate reveal and a verified raw flag may be shown through the explicit
  one-time reveal control after `solved`.
- The user guide, threat model, and root operational plan were aligned with
  that rule so future changes do not accidentally treat UI reveal as a policy
  violation or turn logs into a flag display channel.

Validation for this policy update:

- Repository hygiene test for the raw-flag UI reveal policy: **passed**.

### Manual candidate review and reload search — 2026-09-02

- The Power console now includes a compact **Candidates** board below the
  racer strip. It can load explicitly revealed archive candidates, adds the
  verified reveal value after the operator clicks `Reveal flag`, and lets the
  operator mark each candidate `Right` or `Wrong` for manual CTF platform
  checking.
- The `Reload search` control queues a reviewed steer to every ready/running
  racer asking for a distinct evidence path and fresh observed candidate. If
  the current racers have already stopped but the operator is still on the same
  archive/session context, the same control starts a fresh Power run from the
  last launch configuration.
- Reload steering intentionally omits the raw candidate value, so manual review
  does not put a flag into model prompts, event payloads, or the database.
  Solver work still flows through Pi, the typed Power tools, sandboxd, and
  flag-router.

Validation for this UI slice:

- Full Web check: **31 passed** (TypeScript, Web tests, production build).
- Repository hygiene invariants: **passed** via direct stdlib runner because
  the current shell does not have `pytest`/`uv` on `PATH` and the local `.venv`
  Python symlink is not portable in this environment.
- `git diff --check`: **passed**.
- Rebuilt the deployed Web container with the Power profile; Web and required
  API dependencies reached healthy state.

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

### Mandatory candidate gate — 2026-09-02

The previous manual board could label a value `Right` or `Wrong`, but that
label did not control the live Power lifecycle. It has been replaced for a
paused runtime candidate with a durable review gate:

- After any typed sandbox observation, the API rescans only the run's
  manifest-derived flag formats. A match persists a metadata-only
  `power.candidate.review.requested` event and transitions the run to
  `paused`; raw values remain solely in the immutable artifact.
- The typed response tells Pi only that review is required. Pi steers its
  current native turn to a safe boundary and does not begin another tool or
  model batch. The API independently fences later tool calls while paused.
- Normal `exec` output is complete for this decision: the immutable `stdout`
  and `stderr` artifacts are both retained as metadata-only references, so a
  matching value from a diagnostic stream cannot be silently dropped.
- A sibling already inside a model turn receives a stable, value-free gate
  code at its next tool boundary. Pi maps it to the same local safe-boundary
  stop, avoiding further tool/model batches while review is pending.
- The active Power console automatically loads the complete local candidate
  queue from the immutable output references that opened the gate; no manual
  scan is needed. The historical full-runtime scan is diagnostic-only.
  **Confirm** re-finds the selected bytes in a retained sandboxd artifact and
  forwards them straight to the independent flag router.
  A successful router decision is the only path to `solved`; a negative router
  decision automatically resumes the same racers with the same source-free
  continuation as **Wrong · continue**.
- **Wrong · continue** writes no candidate. It transitions the run back to
  `running` and queues one source-free, distinct-evidence steer for each
  ready/running racer. The existing Pi sessions continue rather than starting
  a new race.
- `ctf_flag_submit` is now a hold-only compatibility tool and the internal
  runner route denies direct flag-router calls. This closes the stale-client
  path that could otherwise bypass the operator gate.

Focused validation after the change:

- Pi runner typecheck and custom-tool suite: **52 passed**. Coverage verifies
  that a control-plane candidate signal exhausts the active turn, emits a
  candidate-review steer (including a sibling already in-flight), and never
  calls flag-router from Pi.
- Browser TypeScript, component tests, and production build: **33 passed**.
  The runtime candidate panel calls the new confirm/reject routes with
  no-store browser requests and reports the pending review state.
- Reproducible Python 3.12 Docker test image: **7 passed** across candidate
  reveal/review, three-racer pause/requeue and sandbox stdout/stderr
  provenance regressions. `uv run pyright` in the same image reported **0
  errors**. The host `.venv` is a container-created symlink, so it cannot run
  pytest directly outside Docker.

M-PI-5 stays unchecked: this changes correctness and operator control; it is
not the paired raw evaluation required to complete the milestone.

### Automatic runtime candidate queue — 2026-09-02

- Replaced the active Power UI's manual **Scan runtime** step with a
  `GET /v1/runs/{id}/candidate-review/queue` read that occurs only after the
  durable candidate gate changes the run to `paused`.
- The gate now records both non-empty stdout/stderr artifact references from
  the triggering typed action. The queue rereads only those references using
  the run's manifest-derived formats, so all values from that observation are
  available immediately without rescanning unrelated history.
- While pending, the candidate panel offers **Confirm**, **Continue search**,
  and **Stop all**. There is no per-candidate resume action: continuing is an
  explicit queue-level decision that resumes every ready/running racer.
- A router acceptance remains the only transition to `solved`; its existing
  controller path fences and aborts all racers. A router rejection resumes the
  current sessions. Candidate strings are response-only (`Cache-Control:
  no-store`) and remain absent from events/database.
- Focused API and Web/component coverage was added for automatic queue load,
  queue resume, and stop-all controls. M-PI-5 is still unchecked pending the
  planned paired raw evaluation.

Validation for this increment:

- `pnpm --filter @ctfmesh/web check` — **35 passed**; TypeScript and production
  build passed.
- `pnpm --filter @ctfmesh/pi-runner check` — **52 passed**; typed candidate
  gate/safe-boundary behavior remains intact.
- Docker Python 3.12 test image: `pytest -q -rA
  tests/integration/test_power_flag_api.py
  tests/integration/test_power_operator_api.py` — **11 passed**; validates
  queue auto-read, append-only concurrent candidate evidence, requeue, and
  accepted-router abort handoff. `pyright` — **0 errors**; focused Ruff check
  and format check passed.
- `docker compose --profile power config --quiet && docker compose --profile
  power up -d --build --wait` — passed; API, Web, sandboxd, flag-router, and
  Pi runner deployed healthy. `GET /v1/ready` returned `status: ready`.

### Power racer transaction stability — 2026-09-02

Observed against the local Power run: concurrent racer startup could deadlock
PostgreSQL because job claiming locked `agent_jobs` while the Power work route
locked the same job before `runs`. The API then returned a non-JSON 500 and Pi
incorrectly terminalized the affected racer as `power_pi_session_start_failed`.
Rapid repeated steering could also lease multiple correction jobs for the same
native Pi session, which is not re-entrant.

This increment keeps M-PI-5 in progress and makes the runtime behaviour
recoverable:

- Power job work, lease renewal, completion, failure, and tool-authority
  transactions now use the canonical `run → job → session` lock order. Job
  claiming locks only its `agent_jobs` row; the joined run is a predicate.
- Database failures have a typed `503 database_unavailable` response. Pi treats
  it as retryable and leaves the leased durable job for safe reclaim instead of
  failing a racer.
- At most one queued or leased Power steer exists per Pi session. A browser
  retry of the same message converges on the existing item; a different message
  receives the explicit `power_pi_steer_already_pending` conflict.
- A failed steer now fails only that steer and returns an idle racer to `ready`;
  it does not kill the whole session. A run becomes `failed` only after every
  racer startup has actually failed, so the desk no longer reports a dead swarm
  as running.

Focused validation:

- Docker Python 3.12: `pytest -q tests/integration/test_power_operator_api.py
  tests/integration/test_power_flag_api.py` — **14 passed**. This includes the
  typed database response, serialized steer/recovery, and all-racers-terminal
  projection regressions.
- `ruff format` plus focused `ruff check` — passed.
- `pnpm --filter @ctfmesh/pi-runner check` — **54 passed**. This includes the
  retryable typed database failure without calling `failPower`.
- `pnpm --filter @ctfmesh/web check` — **35 passed** with production build.

Remaining risk: this fixes the observed lock inversion and runner recovery;
M-PI-5 still needs the planned paired authorized raw evaluation before its
benchmark acceptance gate can be marked complete.

### Fresh-machine Power deployment correction — 2026-09-02

A clean clone exposed a configuration edge case: copying `.env.example`
creates blank Power capability fields and `CTFMESH_POWER_ENABLED=false`.
The previous bootstrap treated the field names as an existing legacy setup,
added only the later M-PI-2 fields, and could leave Power disabled.

- The bootstrap now recognises the copied template's blank values as
  placeholders. It appends a final `CTFMESH_POWER_ENABLED=true` assignment and
  generates every missing Power-only capability, while preserving an existing
  non-empty M6 runner capability.
- A partially configured, non-empty Power capability set remains fail-closed;
  the helper never rotates an existing secret. A complete legacy setup still
  receives only the missing runner/socket/enablement fields.
- Added bilingual clean-machine deployment guides,
  `docs/deployment-local.md` and `docs/deployment-local-vi.md`, covering
  clone, bootstrap, Power Compose, readiness checks, UI setup, redeploy, logs,
  cleanup, and destructive volume reset.

Validation:

- Bootstrap regression including an actual copied `.env.example`: **4
  passed**.
- Full Docker Python gate: **397 passed, 14 skipped**; Ruff and Pyright
  passed with zero findings.
- Pi runner check: **55 passed**. Web check: **35 passed**, including the
  production build. Default, `power`, and `m6-ui` Compose configurations
  passed.

M-PI-5 remains unchecked: reproducible local deployment is prerequisite
infrastructure, not the paired raw evaluation required by the milestone.

### Braced flag-template provisioning correction — 2026-09-02

An operator Power run failed before any Pi session or model turn began even
though sandboxd had successfully created the AutoPrompter and three racer
workspaces. The controller then rolled all four workspaces back and the desk
showed every racer as failed.

- Root cause: the literal browser hint `DH{*}` or `HTB{...}` was copied into
  the durable Pi brief. The repository's intentional raw-secret guard treats
  braced values as candidate-shaped and correctly rejected that record, so
  `create_power_pi_sessions` never published the session start jobs.
- The controller now renders a braced template as non-candidate prose (for
  example, an exact `DH` prefix with a brace-delimited payload). Pi retains
  the useful solving cue; the manifest-derived literal pattern remains the
  only flag-router matching authority.
- The brief defensively applies the same redaction helper to the optional
  operator description before persistence. No format value, candidate, key,
  or raw flag is added to events or the database by this repair.

Focused validation in an ephemeral Python 3.12 Docker environment:

- `tests/integration/test_power_operator_api.py -k 'flag_format or
  pi_fixture_flag_solves'` — **2 passed**. The provision test now launches
  with `DH{*}` and asserts that all four durable sessions/jobs are created.
- Ruff check and format check for the changed API and regression test —
  passed.
- Rebuilt `api`, `sandboxd`, `flag-router`, `pi-runner-live`, and `web` under
  the `power` Compose profile; the API `/v1/ready` endpoint and an in-image
  brief assertion both passed.
- Full Python 3.12 gate after the repair — **397 passed, 14 skipped**; lock,
  Ruff, and Pyright passed with **0 errors** (one upstream Starlette
  deprecation warning only).
- Web check — **35 passed** plus production build; Pi runner check — **55
  passed**. Default and `power` Compose models and `git diff --check` passed.

M-PI-5 remains unchecked: this is a deployment-blocking correctness repair,
not the paired authorised raw evaluation.
