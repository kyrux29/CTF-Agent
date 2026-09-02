# CTFMesh

CTFMesh is a local, evidence-first control plane for **authorized** CTF work.
Its default profile starts with an empty operator workspace: it contains no
operator challenge artifact, target, or static flag. An opt-in M5 profile adds
three project-owned synthetic Web labs whose flags are random at runtime and
never bundled into Pi-visible assets. An operator can upload one of their own
offline CTF archives into a bounded local receipt, then optionally run a
one-shot, metadata-only triage request through OpenAI, Google Gemini, or
DeepSeek.

The current product slice lets an operator inspect a supported archive safely,
validate/import a scoped manifest, create an auditable run with a durable
preflight job, inspect its event projection, and use read-only provider triage.
Its opt-in M6 assisted-Web lane can materialize validated source into a fixed
slot, lease one selected provider credential in memory, collect typed source
and exact-origin HTTP observations, and submit a bounded declarative candidate
to an independent two-replay verifier. It never executes an uploaded archive
or arbitrary model-generated code, and a model cannot mark a run solved.

For authorized local CTF archives across categories, the separate opt-in
**Power** profile runs one bounded AutoPrompter pass followed by three isolated
ReAct racers. Each racer receives a disposable toolkit workspace and may use
reviewed shell/file/PTY/GDB/TCP actions only through `sandboxd`. The model
never receives the Docker socket or provider keys, and only the independent
flag router can transition a run to `solved` from an observed candidate.

## What is included

- strict `Challenge` manifest validation for Web, Crypto, Pwn, Reverse,
  Forensics, OSINT, Misc, AI/ML, Mobile, Blockchain, Hardware, Stego, and
  Programming categories;
- local Control API with challenge import, run records, event stream, console
  projection, and state transitions;
- React Scope Ledger UI for JSON-manifest validation and import;
- browser archive intake for ZIP and standard TAR variants with streamed upload
  quotas, path/link/special-file denial, extraction limits, redacted inventory,
  and explicit direct-candidate reveal;
- optional one-shot browser triage after receipt creation through exactly one
  selected provider (OpenAI Responses, Google Gemini, or DeepSeek); the key is
  sent only for that local request, never enters a manifest, event, report,
  database, sandbox, or fallback provider; in the local single-operator
  profile it is retained in that browser profile's `localStorage` so Settings
  can restore it after a restart;
  provider egress contains no archive path, source excerpt, printable string,
  or candidate flag value;
- read-only artifact triage through the CLI with a one-call OpenAI Responses
  adapter, structured output, `store: false`, and no provider-native tools;
- a provenance-pinned, non-executable CTF skill catalog with reviewed local
  guidance plus reference metadata for `ljagiello/ctf-skills`, OWASP WSTG,
  pwn.college Dojo, and Google CTF; it never downloads or prompts upstream text
  at runtime;
- category-aware local stdio MCP profiles for declared offline artifacts only;
- an opt-in M3 typed tool gateway: source list/read/search/manifest,
  fixed allowlisted text transforms, and alias-bound HTTP observations with
  durable budget/idempotency records and immutable redacted artifacts;
- isolated source slots and a provider-only exact-host HTTPS CONNECT proxy;
  source slots have no provider/public network, browser triage keys exist only
  in the individual API request routed via that proxy, and M6 Pi receives only
  a request-scoped in-memory credential lease;
- an opt-in M5 independent verifier with a canonical declarative `GET`-only
  replay plan, fresh cookie jar and two random-reset attempts; it is restricted
  to three local project-owned labs, stores only opaque Ed25519 proof data, and
  is the sole route to `SOLVED` for those labs;
- an opt-in Power CTF profile for an operator-supplied archive: one bounded
  reconnaissance pass, three provider/model-configurable isolated racers,
  typed shell/file/IAT actions, shared reservation budget, optional exact
  public TCP target, local knowledge retrieval, and independent flag routing;
- policy, immutable artifact, verification, and multi-agent Council contracts
  that remain separate from provider and tool implementations;
- Docker Compose for a loopback-only PostgreSQL, local content-addressed
  artifact volume, API, and Web stack. The `power` profile additionally starts
  the trusted `sandboxd` manager; it is the sole Docker-socket holder. Redis
  and MinIO are intentionally not included until a real consumer needs them.

## Repository layout

| Path | Purpose |
|---|---|
| `apps/` | User-facing API, CLI, and Web product entry points |
| `packages/` | Reusable product contracts and implementations |
| `services/` | Deployable runtime services, including Pi and verifier |
| `tests/` | All Python, Web, and Pi Runner test code and test-only config |
| `docs/` | Architecture, operations, decisions, plans, and worklogs |
| `support/` | Host-only scripts and documentation examples; excluded from images |
| `challenges/` | Gitignored operator-owned runtime input; never bundled |

The first three directories are product source. Tests, documentation, examples,
and maintainer utilities are deliberately kept outside those trees so package
and Docker build boundaries remain easy to review.

## Important boundary

Only use CTFMesh against targets and material you are authorized to inspect.
The local Control API has no authentication or tenant isolation, so it must stay
on loopback and be used by one trusted operator. It is not an Internet scanner
or multi-user credential broker. The Power profile is a scoped CTF solver: its
shell runs only in disposable workspaces and its TCP access is limited to one
operator-declared public host and port.

## Deploy with Docker only

Every product process and its build dependency runs in a container. The host
only needs Docker Engine with the Compose plugin, plus operator-controlled
challenge directories and secrets; it does not need host `uv`, Python, Node, or
`pnpm` to deploy CTFMesh.

Start the blank, target-free control-plane stack:

```bash
mkdir -p challenges
docker compose up -d --build --wait
curl --fail http://127.0.0.1:5173/v1/ready
curl --fail http://127.0.0.1:5173/healthz
```

Open <http://127.0.0.1:5173>. The first page deliberately shows no bundled
case. You can either upload an authorized offline archive to create a local
receipt, or paste/select a JSON manifest for an explicit target scope. Archive
intake does not execute code or contact a target. Creating a run queues a
durable deterministic preflight job. The default Compose profile has no model,
tool, or target consumer; the opt-in M2 fixture profile proves the isolated Pi
control loop without granting those capabilities.

After preparing the two reviewed source slots and private runtime variables as
described in the M3 guide, deploy the complete M3 runtime with one Compose
profile:

```bash
docker compose --profile m3 up -d --build --wait
```

The aggregate `m3` profile starts the durable preflight worker, session
initializer, live Pi runner, provider proxy, tool gateway, and both fixed
source slots alongside the default API/Web/PostgreSQL services. It intentionally
excludes the `pi-smoke` fixture runner, because two runners must not compete for
the same durable queue. The narrower `m3-source` and `m3-provider` profiles
remain available only for focused diagnostics.

For the target-free Pi SDK fixture, lifecycle, steering, and isolation checks,
follow the [M2 Pi Runner smoke guide](docs/operations/pi-runner-m2-smoke.vi.md).

For the opt-in M3 source/tool/provider boundary and the distinction between its
tested contract slice and a real authorized lab E2E, follow the
[M3 tool-gateway guide](docs/operations/m3-tool-gateway.vi.md).

The M6.a browser-driven Web-instance lane requires its separate private local
service wiring. Create it once with `python3 support/scripts/dev/bootstrap_m6_runtime.py`
(or the Docker-only alternative in the [Vietnamese usage guide](docs/usage-guide-vi.md)),
then use `docker compose --profile m6-ui up -d --build --wait`. This `.env`
contains internal service credentials only; never put an AI-provider API key,
cookie, or flag in it.

To use the authorized multi-category CTF solver, bootstrap Power's internal
service credentials once, then run the complete profile:

```bash
just power-bootstrap
docker compose --profile power up -d --build --wait
curl --fail http://127.0.0.1:5173/v1/runtime/capabilities
```

The response must report `"power":{"status":"ready"}`. Add provider keys in
the browser's local Settings store; never add them to `.env`. The complete
archive-to-flag workflow, target declaration rules, and cancellation behavior
are documented in [the Power section of the Vietnamese usage guide](docs/usage-guide-vi.md#power-solve-archive-đến-flag).

For the isolated M5 verifier/lab profile, secret setup, proof lifecycle, and
safe Docker smoke procedure, follow the
[M5 verifier/lab guide](docs/operations/m5-verifier-labs.vi.md). It is a
closed local regression/demo profile, not a generic target verifier.

For M6's strict A/B/C verified-solve receipt format, raw-count report, chaos
coverage and release checklist, see the
[M6 evaluation/release guide](docs/operations/m6-evaluation-release.vi.md).
It intentionally does not turn a fixture or a model self-report into a score;
the M3 transport gate is complete, while live A/B/C model results remain
pending until an operator supplies an authorized challenge and provider.

The host-local [`challenges/`](challenges/.gitkeep) directory is ignored by Git
and the Docker build context. The base API never mounts it. In M3, each reviewed
`challenges/<challenge-id>/` directory is mounted read-only into exactly one
fixed source slot at `/challenge`; keep private challenge material there rather
than committing it to this repository.

To stop the local services while retaining your local database/artifact state:

```bash
docker compose down --remove-orphans
```

To intentionally reset that local state, use `docker compose down -v` only
after you have exported anything you need.

## Import through the API

The Workbench accepts JSON. A YAML manifest can be validated with the CLI and
then converted by your own workflow before calling the API. The API never reads
an arbitrary host path from the browser.

```bash
curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST http://127.0.0.1:5173/v1/challenges/validate \
  --data @manifest-request.json

curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST http://127.0.0.1:5173/v1/challenges \
  --data @manifest-request.json

curl --fail http://127.0.0.1:5173/v1/challenges
```

`manifest-request.json` must have this envelope:

```json
{ "manifest": { "apiVersion": "ctfmesh.io/v1alpha1", "kind": "Challenge" } }
```

The nested manifest must satisfy the domain contract; validation returns safe,
structured errors for missing scope, artifact, budget, flag-policy, or mode
requirements.

## Archive intake and read-only AI triage

The archive route is deliberately narrower than a generic file executor. It
accepts a raw `ZIP`, `TAR`, `TAR.GZ`/`TGZ`, `TAR.BZ2`, or `TAR.XZ`/`TXZ` stream
up to 128 MiB. It rejects unsupported/encrypted archives, path traversal,
backslashes, duplicate/path-prefix collisions, links, special files, files
over 64 MiB, more than 512 entries, compression-ratio bombs, and total expanded
data over 512 MiB. Nested archives remain files; they are not recursively
unpacked.

From the UI, select an archive and click **Create receipt**. The result reports
only redacted metadata, static hints, and a bounded direct-candidate count. A
candidate is not a verified flag; its raw value appears only after the explicit
**Reveal direct candidates** control and is not written into the receipt report.

To request browser triage, add one or more provider keys to the local Settings
store, enable metadata-only requests for the tab, then choose a provider and
exact model independently in each pane. The receipt must be created first.
For this loopback single-operator profile, Settings stores keys in the browser
profile's `localStorage` and restores them after reload. Keys never enter the
ledger, database, artifacts, sandbox, or challenge workspace; use a dedicated
browser profile and remove saved keys before sharing the machine. The server
requires the acknowledgement, an explicit
provider, a request body no larger than 16 KiB, and a key no larger than 8 KiB.
The operator may select a provider wait from 10 seconds to 24 hours.
**Unlimited** removes the normal UI deadline, keeps an emergency 24-hour
watchdog, and can always be stopped with **Cancel**. While waiting, the pane
shows `Thinking` with elapsed time and code-owned runtime checkpoints. The Web
reverse proxy and allowlist relay retain bounded margins above the watchdog so
the API can return a sanitized terminal error.
It passes the key directly to the selected fixed provider boundary through the
internal allowlist proxy and does not persist it. Provider evidence contains
only service-generated file IDs, sizes,
SHA-256 values, media types, and controlled structural markers; it contains no
archive path, source text, printable string, or candidate flag value. A receipt
accepts one successful provider result; a failed request can be retried using
the connected provider key. OpenAI uses strict structured output with `store: false`; Gemini and
DeepSeek use JSON mode with the same local Pydantic/evidence-citation
validation. All adapters disable provider tools and use a fixed HTTPS host with
redirects and ambient proxy trust off. The resulting category, facts,
hypotheses, and next actions are proposals only: no generated code, target
interaction, archive recursion, or verifier is run.

The VS Code-style activity bar switches one side panel at a time between
durable History, ledger-backed Progress, Statistics, and on-demand Help; its
clearly separated gear opens workspace settings. Clicking the active view
collapses the panel and returns the width to the challenge panes. Settings
stores only local, non-secret preferences: provider/model,
display density, one to three panes, and bounded run values. Presets remain,
while Custom can tune archive output to 512–3,072 tokens, provider wait to
10–86,400 seconds, and exact-instance time/tool/HTTP/cost below the existing
900 s/120/80/$3 hard ceiling. Separate
OpenAI, Gemini, and DeepSeek keys use separate local Settings slots and are
restored only in the same browser profile. Each pane selects its own
provider/model without re-entering a key. Each pane shows a model-family
token estimate; it is planning guidance, not provider usage
or billing evidence. The browser still cannot modify archive quota, source-slot
count, exact public-origin policy, provider endpoints, or two-pass verification.
The Web app is only a local control surface: solve runs travel through the
control API to the local Pi harness, typed tool gateway, fixed sandbox slots,
and independent verifier; browser code never becomes an agent runtime.

The existing CLI remains useful when you already have an explicit manifest and
declared local artifacts:

```bash
export CTFMESH_LIVE_PROVIDERS_ENABLED=true
read -rs OPENAI_API_KEY
export OPENAI_API_KEY

uv sync --frozen --all-packages --all-groups
uv run --frozen ctfmesh challenge validate challenges/<case>/challenge.yaml
uv run --frozen ctfmesh triage run \
  challenges/<case>/challenge.yaml \
  --challenge-root challenges/<case> \
  --model <operator-approved-model-id> \
  --output .artifacts/triage/<case>
```

The command copies only declared artifacts into a disposable read-only
workspace, fingerprints/redacts bounded evidence, writes a safe report, and
finishes as `completed`. It never executes a model-proposed next action or
creates a `solved` state.

## Local MCP

For an offline `artifact_bundle` manifest that explicitly allows
`artifacts.inspect` and `files.list`:

```bash
uv run --frozen ctfmesh mcp serve challenges/<case>/challenge.yaml \
  --challenge-root challenges/<case>
```

MCP uses stdio only. It does not expose an HTTP server, network tool, shell, or
provider credential.

## Reviewed skill and MCP metadata

`GET /v1/skill-catalog` exposes the checked-in source provenance for the local
skill catalog and category-specific local MCP profiles. It does not fetch,
install, execute, or send third-party skill text to a model. Use the optional
`?category=web` filter to inspect one category. Each source is pinned by HTTPS
repository URL, immutable commit SHA, source/license path, SHA-256, SPDX
license, and role (`reviewed_catalog` or `reference_only`).

The only MCP profiles currently published are `local_stdio` profiles for the
existing `ctfmesh.local.readonly` facade. They expose only `files_list` and
`artifacts_inspect`, which still pass through the typed runtime and manifest
allowlists. An upstream catalog reference cannot add a remote endpoint, network
permission, code execution, or tool access.

## Control API

| Endpoint | Purpose |
|---|---|
| `GET /v1/health` | Process liveness |
| `GET /v1/ready` | Database and artifact-store readiness |
| `POST /v1/challenges/validate` | Validate a manifest without persisting it |
| `POST /v1/challenges` | Persist a validated manifest idempotently by digest |
| `GET /v1/challenges` | List operator-imported manifests |
| `POST /v1/archive-intakes` | Stream a bounded offline archive into a redacted local receipt |
| `GET /v1/archive-intakes/{id}` | Read a receipt without exposing raw extracted content |
| `POST /v1/archive-intakes/{id}/candidate-flags/reveal` | Explicitly reveal direct input candidates; never marks solved |
| `GET /v1/archive-triage/providers` | Fixed non-secret browser triage provider allowlist |
| `POST /v1/archive-intakes/{id}/triage` | One successful metadata-only triage request to the selected provider |
| `GET /v1/skill-catalog` | Checked-in skill provenance and local-only category MCP metadata |
| `POST /v1/runs` | Create a bounded `PREPARING` run and durable preflight job |
| `GET /v1/runs/{id}/console` | Read the evidence-oriented UI projection |
| `GET /v1/runs/{id}/agent-sessions` | Read Pi lifecycle metadata, never a transcript or credential |
| `GET /v1/runs/{id}/candidates` | Read M5 candidate lifecycle without plan body or raw candidate |
| `GET /v1/runs/{id}/verifications` | Read M5 replay/proof projection without a raw flag |
| `POST /v1/runs/{id}/flag-reveal` | Explicitly reveal the verified raw flag once after `solved` |
| `POST /v1/runs/{id}/pause|resume|cancel` | Human state transitions |
| `POST /v1/runs/{id}/steer` | Record bounded human steering text |

## Development checks

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
```

## Current limitations

- Browser intake is limited to supported offline archives; it is not a generic
  parser, recursive extractor, host-path reader, shell, or code runner.
- Browser triage is one selected provider per request and proposal-only. It is
  not a secret broker, automatic fallback/multi-provider router, or autonomous
  solver.
- No generated-code execution, host shell, Docker socket, public MCP endpoint,
  or unrestricted network tool is wired.
- The M2 Pi Runner profile remains a no-key fixture. M3's authorized
  source-slot/operator-lab transport gate is complete; live M6 solve-rate
  evaluation still requires operator-supplied provider access and scope.
- The M1 fake harness exists only in tests/dev composition to prove durable
  preflight and verifier authority. It is never mounted as an API route or a
  production consumer.
- Only an independent verifier may transition a run to `solved`. M5 connects
  that path only for its three code-owned local labs; no generic verifier or
  arbitrary exploit execution pipeline is connected in this release.
- Live multi-provider routing, secret brokering, benchmark-gated model choice,
  and production multi-user operation remain future work.

See the Vietnamese operator guide in
[docs/usage-guide-vi.md](docs/usage-guide-vi.md) for the detailed workflow.

## License

CTFMesh is licensed under the [MIT License](LICENSE). Third-party dependencies
and provenance-pinned reference sources retain their own licenses; the Pi SDK
pin is documented in [services/pi-runner/UPSTREAM.md](services/pi-runner/UPSTREAM.md).
# CTF-Agent
