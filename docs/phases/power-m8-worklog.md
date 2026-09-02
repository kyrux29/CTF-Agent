# Power P8 worklog — operator Power path

**Status:** completed
**Started:** 2026-09-01
**Completed:** 2026-09-01

## Invariant

- A Power run starts only when the explicit profile flag and all reviewed
  internal boundaries are configured. The browser supplies an archive receipt,
  a bounded A/B/C race map, and transient provider credentials; it cannot
  select a Docker resource, filesystem path, provider URL, or arbitrary
  network range.
- A declared TCP target is one normalized host:port pair and is passed only to
  sandboxd's existing tube allowlist. No target means no network target.
- Provider keys remain in the request/background task only. They are not put
  in a manifest, repository record, event, workspace, sandboxd RPC, or flag
  router request.
- The trace is a concise ledger of lifecycle/tool observations rather than
  private model reasoning. Stop cancels the controller task and invokes the
  coordinator's existing workspace cleanup path. A flag is revealed only by
  the existing independent flag-router decision and one-time reveal store.

## Delivered

1. Added the feature-gated receipt-to-Power API contract and `PowerRunController`.
   It composes the existing isolated racers, sandboxd client, provider
   backends, local knowledge retriever, and independent flag router. The HTTP
   route never invokes tools directly.
2. Added append-only, safe Power lifecycle/action receipts for the existing
   console. They carry action type, counters, and a command fingerprint only;
   raw command arguments, tool output, model reasoning, provider keys, and
   raw flags are excluded.
3. Added the compact **Power solve** receipt flow in the browser. It uses the
   encrypted client vault only for the current launch, applies Settings-held
   A/B/C provider/model/budget preferences, and supports either an offline
   archive or one authorized public TCP `host:port` target. Three racers are
   deliberately fixed for the current local baseline. Open egress is shown as
   unavailable rather than silently accepted.
4. Added a persistent local Power bootstrap helper and `just power-bootstrap`.
   It generates only internal service capabilities in ignored `.env`, refuses
   to rotate an existing setup, and never handles a provider credential.
5. Updated Compose so only the trusted `sandboxd` manager reaches the declared
   target bridge; each disposable solver workspace remains network-isolated
   until its typed scope is applied. No default service gains the Docker socket.

## Verification

- `uv lock --check`, `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run pyright`, and `uv run pytest -q` completed in the Docker test image:
  **364 passed, 14 skipped, 1 dependency deprecation warning**.
- `pnpm --filter @ctfmesh/web check`: TypeScript passed, **36 Web tests
  passed**, and production build passed.
- `pnpm --filter @ctfmesh/pi-runner check`: TypeScript passed and **28 Pi
  runner tests passed**.
- `docker compose --env-file /dev/null config --quiet` and the Power-profile
  equivalent passed.
- `docker compose --profile power up -d --build --wait --wait-timeout 240`
  completed. The API, Web, sandboxd, flag-router, target connector, and
  supporting services report healthy/running; `/v1/runtime/capabilities`
  reports `power: ready` with no missing requirements.

## Demo path

1. Open `http://127.0.0.1:5173`.
2. Open Settings, enter a provider key in the encrypted browser vault, then
   select the provider/model for racers A, B, and C.
3. Upload an authorized archive, inspect it, and select **Power solve**.
4. Keep the run offline for a file challenge, or enter the exact authorized
   public TCP `host:port` and acknowledge the scope. Start the run and open
   its console to follow verified lifecycle/action receipts.
5. Use **Stop** to cancel. A flag appears only after the independent router
   verifies an observed result; copy it from the short-lived reveal control.

## Remaining risks

- No real provider call or live CTF target was made during this milestone; the
  demo is intentionally ready for an operator-supplied authorized challenge.
- The documented `just` recipe requires the `just` executable on the host.
  The equivalent bootstrap script is available at
  `support/scripts/dev/bootstrap_power_runtime.py` when it is not installed.
- Provider credentials must be entered through Settings, never committed to
  `.env`, passed to Docker, or pasted into a worklog.

## Post-completion runtime regression — 2026-09-01

### Symptom and cause

- An operator Power run reached `power.swarm.failed` immediately with
  `archive_intake_unavailable`, before a provider call or a solver command.
- Archive intakes are correctly owner-only (`10001:10001`, mode `0700/0600`).
  `sandboxd` had been run as UID 0 with every Linux capability dropped; it
  therefore could not traverse the API-owned intake directory. This was an
  integration permission defect, not a model, budget, archive, or target
  failure.

### Fix and validation

- `sandboxd` now runs as the same non-root UID/GID as the API. The Power
  bootstrap helper records only the local Docker socket GID, so `sandboxd`
  receives that one supplementary group without a filesystem-bypass
  capability. It remains the only socket holder; generated workspaces still
  receive neither the socket nor direct networking.
- The client maps only reviewed sandbox service codes to a recovery receipt;
  unreviewed service diagnostics stay opaque. The embedded Power console is a
  compact A/B/C racer board with Trace as the explicit audit view.
- After rebuilding `docker compose --profile power`, the original uploaded
  archive successfully completed: workspace create `201`, bounded command
  `200`, workspace cleanup `200`. The demo used no provider key and did not
  expose challenge contents.
- Focused Power tests: **16 passed, 2 skipped**. Full Python gates: **364
  passed, 14 skipped**. Web check/build: **36 passed**. Compose default and
  Power configurations validated; all running Power services reported
  healthy.

## Post-completion model-compatibility regression — 2026-09-01

### Symptom and cause

- A subsequent authorized Power run created and cleaned up its disposable
  workspace successfully, but stopped before the first racer action. The
  prior generic `power.swarm.failed` receipt concealed the adapter failure.
- The selected DeepSeek V4 model returned a valid JSON action together with
  its documented `reasoning_content` field. The OpenAI-compatible solver
  adapter's deliberately strict response allowlist had not included that
  string-or-null metadata field, so it rejected an otherwise usable action.

### Fix and validation

- The adapter now validates the documented string-or-null
  `reasoning_content` shape then discards it. It is never put into a solver
  turn, event, artifact, database record, prompt, or UI trace. The structured
  `content` action remains the only model value that can reach the typed
  action validator.
- Non-success HTTP statuses are mapped only from the status code to reviewed
  recovery codes (authentication, credits, model availability, rate limit,
  request rejection, or provider availability). Provider response text stays
  opaque. The Power controller records the matching safe recovery receipt,
  so a new run shows an actionable reason without exposing a key, prompt,
  diagnostic, or model reasoning.
- Regression tests cover DeepSeek thinking metadata, stable HTTP recovery-code
  mapping, and the controller's append-only safe failure record. The local
  declared target was probed through the typed scope path: workspace create
  `201`, target connect `201`, target close `200`, workspace cleanup `200`.
- Full backend gate after the fix: **377 passed, 14 skipped, 1 dependency
  deprecation warning**. Web check/build: **36 passed**. Pi runner check:
  **28 passed**. Default and Power Compose models validate cleanly.

## Post-completion swarm-continuity and console repair — 2026-09-01

### Symptom and cause

- A Power run showed all three racers as `waiting (queued)` and stopped after
  AutoPrompter activity. The sandbox audit proved that this was not a
  one-request run: AutoPrompter had created one workspace and completed five
  observed commands before a later provider response failed typed-action
  validation. The coordinator then propagated that one malformed response and
  never reached the racer-spawn phase.
- The initial `BRIEFING` snapshot was also persisted as three racer command
  events. That made empty scheduler slots look like completed/failed workers
  and left the console's tool-call meter at zero for Power receipts.

### Fix and validation

- DeepSeek Power calls explicitly disable private thinking for this strict
  JSON-action turn. The adapter still accepts documented `reasoning_content`
  metadata only to discard it, never as evidence. A schema-invalid response
  gets at most two bounded, budget-charged retries with a fixed protocol hint.
  If the AutoPrompter has already collected observations and remains invalid,
  it returns a receipt-only brief and the three independent racers still run.
- Racer state is published once each task owns its workspace, before its first
  provider request. The API records AutoPrompter progress separately and no
  longer manufactures command receipts for queued slots. The console counts
  real Power action receipts and renders historical queue placeholders simply
  as `Waiting`.
- Focused regression gate passed: `26 passed` (controller receipt separation,
  partial brief continuity, typed-model handling, and console meter). Full
  Python gate (`uv lock`, Ruff, Pyright, and `pytest -q`) completed successfully
  with exit code `0`; Web check/build passed with **36 tests**, Pi runner check
  passed with **28 tests**, default and Power Compose models validate, and the
  rebuilt Power API/Web services are healthy with `power: ready`.
- Browser QA used the live loopback UI and captured both the workspace and a
  Power console. The console now shares the neutral charcoal/green operator
  palette, uses a compact racer board, and keeps detailed receipts behind the
  explicit Trace view. Generated screenshots were removed by the final clean.

## Post-completion budget-accounting repair — 2026-09-01

### Symptom and cause

- A Power run displayed **Budget exhausted** after roughly thirty seconds,
  even though the visible console still showed `$0.00 / $10.00` and all three
  racers appeared to have stopped after `fs.ls`.
- The shared ledger correctly reserves the declared maximum before each model
  call, including the bounded AutoPrompter pass. The former Settings default
  (`$10.00` cap / `$0.25` per call) admitted only 40 calls, while a complete
  bounded race can use 106 (10 briefing + 32 for each racer). In addition,
  every coordinator snapshot re-persisted unchanged racer receipts, inflating
  the visible action count and concealing the conservative reservation.

### Fix and validation

- The Power controller now persists a racer, swarm, AutoPrompter, or budget
  receipt only when its safe projection changes. It records only integer
  reservation totals and the reviewed exhaustion reason; credentials, model
  output, commands, observations, and flags remain excluded.
- The console labels this meter **Reserved cost**, deduplicates historical
  Power snapshot receipts by racer/turn/action, and tells the operator that a
  budget stop is a race-cap recovery action rather than a racer crash.
- New browser defaults reserve `$0.05` per call under the existing `$10` cap
  (200 admissible calls). Settings shows the computed call capacity and the
  106-call worst-case race envelope so a stricter manual reservation is
  explicit before launch.
- Focused Docker gate passed: Ruff, Pyright, and **16 Power/controller/
  console tests**. The complete Docker backend gate then passed: **381
  passed, 14 skipped** (one FastAPI dependency deprecation warning). Web
  typecheck/test/build passed: **37 tests**; Pi runner checks passed: **28
  tests**. Rebuilt `docker compose --profile power up -d --build --wait`; the
  loopback runtime reports Power, archive intake, and exact-instance
  capabilities `ready`.

## Post-completion racer-observability repair — 2026-09-01

### Symptom and cause

- The Power Trace correctly avoided copying command arguments, tool output,
  model reasoning, and candidate flags into the append-only ledger. Its
  generic scheduler receipts consequently rendered as `Not applicable`, which
  made it impossible for an operator to distinguish an active racer from an
  idle one.

### Fix and validation

- Every typed solver turn now produces a fixed-vocabulary activity receipt
  (for example, mapping files, reading a challenge file, or running bounded
  analysis). The receipt carries the racer, state, turn, action type, evidence
  count, and—when present—only an immutable observation artifact reference.
  No model-controlled path, command, interactive input, tool output, prompt,
  key, cookie, bearer value, candidate, private reasoning, or raw flag enters
  the receipt.
- The Power overview shows each racer's current safe activity and `Turn ·
  evidence` count. Expanding its Trace entry shows the same compact fields and
  exposes the immutable artifact reference through the existing artifact
  channel, rather than an inline transcript.
- Focused regression coverage passed: **29 tests**. Full backend gate passed:
  **381 passed, 14 skipped** (one FastAPI dependency deprecation warning).
  Web typecheck/test/build passed: **38 tests**. The rebuilt Power Compose
  stack is healthy; loopback browser QA confirmed the workspace loads. Older
  append-only runs retain their historical generic receipts; newly started
  Power runs receive the enriched fields.
