# Local release readiness

## Supported local profile

| Surface | Status | Boundary |
|---|---|---|
| Manifest validation/import | Supported | Strict domain contract; no host-path input from browser |
| Tracked runs, durable preflight jobs, and console projection | Supported | Local single operator; no model/tool/target consumer in Compose |
| CLI read-only OpenAI triage | Supported with explicit shell opt-in | One provider call, declared artifacts only, proposal-only |
| Browser archive receipt | Supported for bounded ZIP/standard TAR | Loopback-only raw stream; no host path, nested extraction, code execution, or target action |
| Browser OpenAI/Gemini/DeepSeek archive triage | Supported through local Settings | One successful fixed-provider call per receipt; key persists only in the same loopback browser profile's `localStorage`; metadata-only evidence, tools off, proposal-only |
| Skill provenance + category MCP profiles | Supported as local metadata | Commit/license/content digests pinned; no runtime fetch, remote MCP, network, or code execution |
| Local stdio MCP | Supported for declared offline artifacts | No HTTP, network, shell or credential channel |
| Docker Compose | Supported for local integration | Loopback Web reverse proxy to an internal API; provider egress only through allowlist proxy; no solver sandbox |
| M3 first-challenge probe | Supported as an opt-in `m3-source` profile | Separate diagnostic run proves source read, exact HTTP alias, immutable cache and out-of-scope denial without a model key |
| M5 local replay verifier | Supported as an opt-in regression/demo profile | Exactly three project-owned Web labs, random reset flags, closed declarative plans, two fresh replays and signed opaque proof |
| M6 offline verified-solve report | Supported as a strict receipt evaluator | A/B/C matrix, five-or-more runs per cell, raw counts and gate failures; no model/target/provider execution |
| M6 release smoke | Supported for blank default Compose profile | Fresh nonce project, loopback probes, credential filtering and guaranteed project-local teardown |
| M6 assisted-Web exact-instance lane | Implementation and Docker smoke complete; live release evidence open | Validated archive to fixed slot, exact public origin, in-memory credential lease, typed tools and independent two-replay verifier |
| Power archive race | Supported for authorized localhost operation | Opt-in `power` profile; one bounded AutoPrompter and three isolated racers, disposable toolkit workspaces, optional exact public TCP target, independent flag-router only |
| Generic execution/verifier pipeline | Unsupported | No arbitrary URL, shell, model-authored code, plan or target can become `solved` |
| Production/multi-user deployment | Unsupported | Requires auth, secret broker, isolation and operations controls |

## Release checks

```bash
uv sync --all-packages --all-groups
pnpm install --frozen-lockfile

uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest -q
pnpm --filter @ctfmesh/web check
pnpm --filter @ctfmesh/pi-runner check
docker compose config --quiet
docker compose up -d --build --wait
docker compose --profile power config --quiet
docker compose --profile power up -d --build --wait
curl --fail http://127.0.0.1:5173/v1/ready
curl --fail http://127.0.0.1:5173/healthz
python3 support/scripts/release_smoke.py --web-port 5175
```

M5 additionally requires operator-owned service tokens and matching Ed25519
controller keys. Run its isolated Compose/profile smoke only according to
[the M5 operator guide](operations/m5-verifier-labs.vi.md); no deployment
secret belongs in this repository or the release log.

M6's detailed receipt schema, non-fixture evaluation process, chaos coverage
and release checklist are in [the M6 evaluation/release guide](operations/m6-evaluation-release.vi.md).
The M3 authorized Compose E2E gate passed on 2026-08-31. The repository still
cannot claim a live A/B/C model result until operator-provided model runs and
the complete five-run-per-cell receipt matrix pass the M6 gates.

## Handoff facts

- The default profile intentionally contains no bundled operator CTF challenge
  or target. M5 source includes three isolated synthetic regression labs, but
  their flags exist only as random runtime volume state.
- `challenges/` is ignored by Git and excluded from the Docker build context.
- The blank UI must load with an empty ledger on a fresh Compose volume.
- Uploading a supported operator archive must produce a redacted receipt without
  target contact or code execution; traversal/link/oversize denial tests must pass.
- Importing a valid operator manifest must work through UI and API.
- Creating a tracked run must atomically create `PREPARING`, its preflight job,
  events/outbox, and must not contact a target or provider.
- A browser archive-triage key may persist only in the local operator's browser
  profile under ADR 0011. It must not appear in receipt reports, run events,
  error responses, the database, artifacts, challenge mounts, or a sandbox;
  CLI keys remain shell-local.
- Browser triage must reject unknown providers before outbound work, show target
  network separately from provider egress, and never fall back to another key.
- A M5 `SOLVED` result must have two distinct reset IDs, a matching immutable
  plan/proof binding and an opaque controller signature; raw flags must not
  occur in API response, event, proof artifact, log or Pi context.
- A published M6 report must contain the complete A/B/C five-run matrix, raw
  counters and configuration digests. A fixture report is never a model score;
  any false solve, scope/public-answer action, unreflected hint or unexplained
  duplicate blocks the release gate.
- Power's P0–P8 implementation and Docker capability checks are complete.
  Its P9 comparative evaluation remains intentionally open: the repository may
  demonstrate its workflow but must not claim solve-rate superiority until the
  documented operator-owned benchmark matrix has raw receipts.
