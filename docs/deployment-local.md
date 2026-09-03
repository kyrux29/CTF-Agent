# Deploy CTFMesh on a local machine

**Language:** [English](deployment-local.md) · [Tiếng Việt](deployment-local-vi.md)

This guide deploys the complete Power workbench from a fresh CTFMesh clone. Every product service runs through Docker Compose; normal use does not require host installations of Node, Python packages, PostgreSQL, or Pi Runner.

Use CTFMesh only with CTF challenges and instances you are authorized to inspect.

## 1. Prerequisites

- Docker Engine running with the Docker Compose v2 plugin.
- The current user can access the Docker socket.
- `git` and Python 3. Python is used only to create Power's internal capabilities.
- An OpenAI, Gemini, or DeepSeek API key for live model runs. Enter it in the browser after startup, never in `.env`.

Check the machine:

```bash
docker version
docker compose version
docker ps
python3 --version
```

If `docker ps` reports `permission denied`, grant Docker access to the current user according to Docker's documentation, then sign out and in again. Do not use `sudo docker compose`: it can leave root-owned volumes that break later runs.

## 2. Clone and bootstrap Power

```bash
git clone <YOUR-REPOSITORY-URL> ctfmesh
cd ctfmesh
cp .env.example .env
python3 support/scripts/dev/bootstrap_power_runtime.py
```

The bootstrap creates distinct local capabilities for API, Pi Runner, `sandboxd`, and flag-router, and enables `CTFMESH_POWER_ENABLED=true`. It makes `.env` readable only by the current user. Do not put API keys, cookies, bearer tokens, or flags in `.env`.

If `just` is installed, `just power-bootstrap` is the equivalent bootstrap command. Run it only once for a complete `.env`; it refuses to rotate existing Power capabilities.

## 3. Start the workbench

```bash
docker compose --profile power config --quiet
docker compose --profile power up -d --build --wait
```

The first build downloads base images and builds the toolkit image. Later starts can omit `--build`:

```bash
docker compose --profile power up -d --wait
```

Open `http://127.0.0.1:5173`. CTFMesh publishes only this Web ingress on loopback; do not expose the API, database, Pi Runner, `sandboxd`, or flag-router to the Internet.

## 4. Verify deployment

```bash
docker compose --profile power ps
curl --fail --silent --show-error http://127.0.0.1:5173/v1/ready
curl --fail --silent --show-error http://127.0.0.1:5173/v1/runtime/capabilities
```

Expected state:

- `api`, `web`, `provider-proxy`, `sandboxd`, and `flag-router` are `healthy`.
- `pi-runner-live` is `running`.
- `/v1/ready` returns `status: ready`.
- `/v1/runtime/capabilities` reports `power.status: ready`.

`power.status` confirms required deployment configuration, not model API-key validity. A provider key is checked only when a browser run begins.

## 5. First browser setup

1. Open **Settings**.
2. Add the provider key and choose a provider/model for racers A, B, and C.
3. Create a workspace, upload an authorized ZIP/TAR challenge archive, and add a description when useful.
4. For an instance challenge, declare the exact authorized host:port and acknowledge the scope.
5. Enter the organizer's flag format when known, such as `DH{*}`. `*` is a case-sensitive wildcard.
6. Select **Power solve**.

Provider keys stay only in the current browser profile's `localStorage`. Clearing browser data or changing profiles requires entering the key again. Keys never enter the database, events, artifacts, sandbox, or container environment.

A format-matching observed candidate pauses the run and appears in the review queue. Historical/archive hits are shown only as clues; only an item labelled **queue · format match** can be finalized for the paused run. Choose **Confirm final** only after the challenge's own checker or organizer submission accepts that exact value; otherwise choose **Continue search** or **Stop all**. The flag-router independently re-checks the selected value's format and immutable-artifact provenance before it can transition the run to `solved`; it cannot infer an organizer verdict from a wildcard such as `DH{*}` alone.

## 6. Default profile without Power

Use the intake/triage UI without racers or a shell workspace:

```bash
docker compose up -d --build --wait
```

The default profile has no challenge, target, provider credential, or Power solver. Complete the bootstrap in step 2 before switching to Power.

## 7. Update and redeploy

```bash
git pull --ff-only
docker compose --profile power config --quiet
docker compose --profile power up -d --build --wait
```

This retains PostgreSQL and artifact state. Export any operational data you need before a large update and review related migration or ADR notes.

## 8. Troubleshooting

### UI unavailable

```bash
docker compose --profile power ps
docker compose --profile power logs --tail=200 web api
```

If port 5173 is in use, choose another loopback port:

```bash
WEB_PORT=5174 docker compose --profile power up -d --build --wait
```

Then open `http://127.0.0.1:5174`.

### Power unavailable or racers do not receive jobs

```bash
docker compose --profile power logs --tail=200 api pi-runner-live sandboxd flag-router
curl --fail --silent --show-error http://127.0.0.1:5173/v1/runtime/capabilities
```

Confirm that bootstrap-generated values remain in `.env` and `CTFMESH_POWER_ENABLED` is `true`. Do not share `.env` or logs containing challenge material with unauthorized people.

### Provider errors

Check the selected provider/model in Settings and ensure the key belongs to that provider. Editing `.env` cannot replace a browser-stored key. Inspect racer activity and `pi-runner-live` logs; do not inject provider keys into a container for debugging.

### Services from another profile remain

```bash
docker compose down --remove-orphans
docker compose --profile power up -d --build --wait
```

This retains volumes and state. Do not use `-v` if the database and artifacts must be retained.

## 9. Stop, clean, or reset

Stop services while retaining local state:

```bash
docker compose down --remove-orphans
```

Preview and remove generated cache/build output:

```bash
python3 support/scripts/dev/clean.py --dry-run
python3 support/scripts/dev/clean.py
```

To remove local dependency directories such as `.venv` and `node_modules`, which can be recreated from lockfiles:

```bash
python3 support/scripts/dev/clean.py --dependencies
```

The following command **permanently deletes** local database, artifacts, and Compose state:

```bash
docker compose down -v --remove-orphans
```

Use this volume reset only after confirming that no run history, intake, artifact, or operational data on the machine needs to be retained.

## 10. Check before contributing or pushing

```bash
uv sync --all-packages --all-groups
pnpm install --frozen-lockfile
just check
docker compose config --quiet
docker compose --profile power config --quiet
git status --short
```

See the [English README](../README.md), [Vietnamese operator guide](usage-guide-vi.md), [documentation map](README.md), and [CONTRIBUTING.md](../CONTRIBUTING.md).
