# Power P2 worklog — ReAct solver and flag router

**Status:** complete — 2026-08-31

## Scope and invariant

P2 delivers one evidence-first solver loop for the opt-in `power` profile.
Each model turn can produce exactly one versioned ACI action. The model never
supplies an observation, and text alone cannot set a run to `solved`.

The independent flag-router re-reads the immutable `sandboxd` artifact under a
read-only mount. It accepts a candidate only when all of the following hold:

1. artifact digest and reference match;
2. artifact provenance is the same run and `sandboxd` tool producer;
3. the candidate matches configured manifest-owned patterns or the reviewed
   `FLAG|HTB|CTF{...}` fallback; and
4. the candidate bytes occur in the raw observation.

Only then does the router call the dedicated Control API endpoint. That API
records the candidate SHA-256, a masked preview and observation references;
the raw candidate is never placed in an event or run result.

## Delivered slice

- Added `packages/aci` strict discriminated contracts for `shell.exec`,
  `fs.ls`, `fs.read`, `fs.write` and `flag.submit`, including path jail and
  argv validation.
- Added `services/solver-runtime` with a one-action ReAct loop, bounded recent
  observation context, deterministic evidence-only summary, `sandboxd` and
  flag-router HTTP clients, plus reviewed OpenAI-compatible routes for OpenAI,
  Gemini and DeepSeek through `provider-proxy`.
- Added `services/flag-router` as a separately deployed private service. Its
  artifact store opens read-only; it owns its own solver-facing capability and
  a distinct digest-only Control API capability.
- Added the only Power completion repository/API path. It is idempotent for
  the same digest proof and rejects inactive or conflicting runs.
- Updated the Power Compose profile and `.env.example`; no provider key is an
  environment variable of a solver, sandbox, router or API service.
- Added a read-only artifact-store mode so an empty initialized volume does
  not require the router to create data directories.

## Verification record

Focused static and behavior gate:

```text
ruff check + ruff format --check (P2 paths)
pyright
pytest P2 unit/integration selection
Result: 22 passed, 2 skipped, 1 third-party FastAPI TestClient deprecation warning
```

Full repository gates after the P2 implementation:

```text
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -q
Result: 327 passed, 10 skipped, 1 third-party FastAPI TestClient deprecation warning

pnpm --filter @ctfmesh/web check
Result: TypeScript clean, 33 Web tests passed and production Vite build completed
```

Real Docker workspace proof (opt-in, no provider call):

```text
CTFMESH_RUN_POWER_DOCKER_SMOKE=1 pytest -q tests/integration/test_power_react_sandboxd_smoke.py
Result: 1 passed
```

The smoke creates a temporary archive with `flag.txt`, copies it into the P1
workspace, reads it through the P2 solver, has the router independently verify
the resulting observation, and asserts that no workspace container remains.

Compose proof used a disposable project with generated internal capabilities:

```text
docker compose -p ctfmesh-p2-smoke --env-file /dev/null --profile power up -d --build sandboxd flag-router
Result: api, sandboxd and flag-router healthy
```

The initial smoke exposed two integration issues, both fixed in this slice:
the router previously initialized a writable artifact store despite its
read-only volume, and a one-time Postgres connection race could leave the API
down. The former now uses `LocalArtifactStore(read_only=True)`; the Compose API
has a bounded `on-failure:5` retry for that transient startup condition.

## Deliberate non-goals and remaining risks

- PTY, gdb and tube actions remain P3 only; P2 does not invoke them.
- P2 creates one racer. Auto-prompting, coordination, cancellation of sibling
  racers and live progress UI remain P4/P8.
- Provider routes are verified with transport fixtures. A live provider call
  intentionally requires an operator-owned key and is not part of CI.
- The fallback pattern supports offline fixture solves. A later dispatcher
  must pass the reviewed manifest pattern set when a manifest supplies one.

## Next unchecked milestone

P3 — IAT `gdb` + `tube` (including PTY lifecycle and scope-limited target
connectivity).
