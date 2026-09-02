# CTFMesh

CTFMesh is a localhost-only agent runtime for **authorized CTF labs**. Its
optional `power` profile gives a Pi-harnessed team of isolated racers a shared,
auditable workspace. A model may inspect evidence and request typed actions,
but it cannot access provider keys, the host, or the Docker socket. A run is
only `solved` after the independent flag router verifies an evidence-bound
candidate.

The default Compose profile is an empty control plane. It ships no challenge,
target, flag, or provider credential.

## Start here

### Use CTFMesh locally

Docker Engine with the Compose plugin runs every product service. Start the
empty workbench:

```bash
docker compose up -d --build --wait
```

Visit <http://127.0.0.1:5173>. To run the optional Power solver, create its
ignored, local internal-service configuration once with `just` (or
`python3 support/scripts/dev/bootstrap_power_runtime.py`) and start the profile:

```bash
just power-bootstrap
docker compose --profile power up -d --build --wait
curl --fail http://127.0.0.1:5173/v1/runtime/capabilities
```

The response must show `power.status` as `ready`. The bootstrap file contains
only internal service credentials. Add OpenAI, Gemini, or DeepSeek keys in the
browser **Settings** panel; they are retained only in that browser profile's
`localStorage`, never in Git, the database, an event, or a sandbox.

In the browser, the normal Power path is:

1. Create a workspace and upload an authorized ZIP or TAR challenge archive.
2. In Settings, save provider keys and choose a provider/model for each racer.
3. Add a short challenge description and, when applicable, declare the exact
   authorized TCP target and expected flag format.
4. Start the Power race and follow each racer's command, output, observation,
   and Pi activity in the run console.
5. When a candidate matches the flag format, the run pauses. Confirm the
   evidence-bound candidate to verify it, or reject it to continue the racers.

Use `docker compose down --remove-orphans` to stop services while retaining
local state. `docker compose down -v` permanently removes local Compose state.
The detailed Vietnamese operator guide is
[docs/usage-guide-vi.md](docs/usage-guide-vi.md).

### Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md), then use the
[documentation map](docs/README.md). Product code lives only in `apps/`,
`packages/`, and `services/`; tests, docs, and maintainer material live in
separate top-level directories.

```bash
uv sync --all-packages --all-groups
pnpm install --frozen-lockfile
just check
docker compose config --quiet
docker compose --profile power config --quiet
```

## Architecture at a glance

```text
Web UI → Control API → Power controller → Pi harness → typed ACI tools
                                                        │
                                                        ▼
                                              sandboxd disposable workspace
                                                        │
observed candidate ───────────────────────→ independent flag router
                                                        │
                                                        ▼
                                                    solved / continue
```

`sandboxd` is the only Power service permitted to create disposable Docker
workspaces. Racers can execute only through that service; they never receive a
Docker socket, host namespace, provider key, or undeclared network target.
The exact rules and threat model are linked from [docs/README.md](docs/README.md).

## Repository layout

| Path | Contents |
|---|---|
| `apps/` | API, CLI, and Web entry points |
| `packages/` | Domain contracts and reusable implementations |
| `services/` | Deployable runtime services, Pi harness, verifier, and sandbox manager |
| `tests/` | Unit, contract, integration, end-to-end, Web, and Pi tests |
| `docs/` | Product guides, architecture decisions, plans, and historical worklogs |
| `support/` | Host-only bootstrap, cleanup, and release utilities plus examples |
| `challenges/` | Ignored operator-owned challenge material |
| `knowledge/writeups/` | Ignored operator-owned local retrieval notes |

## Scope and current status

CTFMesh is for one trusted local operator working on targets and material they
are authorized to inspect. It is not an Internet scanner, a shared SaaS, or a
generic remote-execution platform. The live Power workflow is available as an
opt-in localhost profile. Comparative solve-rate evaluation remains open; see
the [current Pi migration plan](docs/CTFMesh-pi-harness-execplan.md) before
claiming performance results.

For security boundaries and disclosure guidance, see [SECURITY.md](SECURITY.md).
For a release checklist, see
[docs/release-readiness-v0.1.md](docs/release-readiness-v0.1.md).

## License

CTFMesh is released under the [MIT License](LICENSE). Third-party dependencies
and provenance-pinned references retain their own licenses.
