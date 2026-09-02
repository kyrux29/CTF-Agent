# Power P6 worklog — multi-provider race and shared budget

**Status:** completed
**Started:** 2026-09-01
**Completed:** 2026-09-01

## Invariant

- A race configuration maps only a reviewed provider, model identifier, and
  sampling setting to each visible racer. It never serializes API keys,
  provider URLs, challenge content, flags, or tool output.
- A single provider credential may compose three independent racers using the
  same model with distinct temperatures. Credentials remain in the caller and
  are passed only to short-lived provider backends.
- The coordinator reserves a conservative, declared maximum cost before a
  model call and observes one shared monotonic wall-clock budget. Its ledger is
  append-only, secret-free, and attributes every reservation to AutoPrompter or
  an individual racer. Exhausted racers stop; the flag router remains the sole
  authority that can solve a run.

## Planned slice

1. Add validated, non-secret provider/model/racer assignments and a reviewed
   backend factory for OpenAI, Gemini, and DeepSeek.
2. Add a shared run budget and append-only per-racer reservation ledger, then
   bind it to AutoPrompter and all three ReAct racers.
3. Add Settings controls for the three racer mappings and shared Power limits
   without changing the encrypted credential vault boundary.
4. Add focused deny-path and race tests, run the full gates, then record the
   outcome in this worklog and the canonical ExecPlan.

## Delivered slice

1. Added `PowerRaceConfiguration`, a strict, non-secret map for the bounded
   AutoPrompter plus exactly three `A`/`B`/`C` racers. It accepts only the
   reviewed OpenAI, Gemini, and DeepSeek provider IDs, a bounded model ID,
   temperature, and a declared maximum call reservation. `compose_power_race`
   receives `SecretStr` keys only at live-backend composition time and pins the
   existing provider-proxy route; no configuration/read model retains a key.
2. Added a same-model helper for an operator with one credential. It constructs
   three independent backends at temperatures `0.2`, `0.5`, and `0.8`. A manual
   configuration that maps all three racers to the same provider/model but
   reuses temperature is rejected.
3. Added `PowerBudgetLedger` and `BudgetedModelBackend`. Before provider I/O it
   atomically reserves a reviewed upper bound in integer micro-USD and bounds
   the call by the single monotonic run deadline. It records every accepted or
   denied reservation append-only, includes per-racer/AutoPrompter subtotals,
   and exposes no key, prompt, command, output, observation, or flag.
4. Bound the ledger to AutoPrompter and every racer in `PowerSwarmCoordinator`.
   Cost or wall-time exhaustion produces the explicit `budget_exhausted` state;
   the coordinator cancels outstanding siblings and the existing independent
   flag-router remains the only route to `solved`.
5. Extended the encrypted-vault Settings drawer with three compact Racer
   provider/model/temperature mappings and a shared Power time, run-cap, and
   per-call reservation setting. These are local non-secret preferences only;
   the API key remains exclusively in the existing AES-GCM browser vault. P8
   will consume this already-validated shape when it adds the Power start API.

## Commands and results

- Focused P6 contracts: `uv run pytest -q tests/unit/test_power_race.py
  tests/unit/test_power_swarm.py tests/unit/test_power_solver_model.py` —
  `15 passed in 0.80s`.
- Web check: `pnpm --filter @ctfmesh/web check` — TypeScript, `34` browser
  tests, and the Vite production build passed.
- Pi check: `pnpm --filter @ctfmesh/pi-runner check` — `28 passed`.
- Full backend gate in the pinned Docker test runtime: `uv lock --check`, Ruff
  format/lint, Pyright (`0 errors, 0 warnings, 0 informations`), then full
  `pytest -q` all passed: `350 passed, 14 skipped, 1 warning in 266.16s`
  (the collector reports `364` tests including skips; command exited `0`). No
  provider request, credential, or challenge was used.
- Compose validation: `docker compose config --quiet` and
  `docker compose --profile power config --quiet` passed.

## Remaining risks

- The P6 dollar figure is a conservative pre-request reservation, not an
  invoice reconciliation. This deliberately favors a hard shared upper bound
  when providers omit/format usage differently; a later billing integration
  must never refund a reservation before a verified provider usage receipt.
- The race configuration and coordinator are complete, but the operator button
  and durable run-event projection belong to the explicit P8 UI/start path.
  Until that milestone, Settings can prepare the mappings but cannot start a
  Power run from the browser.
