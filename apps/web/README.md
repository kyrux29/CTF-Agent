# CTFMesh Power Web

The Web app is the local operator surface for the authorized Power profile:

1. drop one bounded ZIP or TAR archive;
2. select three provider/model racers in **Settings**;
3. optionally declare one authorized TCP `host:port` target;
4. start the bounded Power race and follow its evidence-backed console; and
5. reveal a flag only after the independent flag-router has verified it.

The main surface contains no provider key field. For the local single-operator
profile, Settings persists provider keys in this browser profile's
`localStorage` so they survive a restart. This is a convenience store, not a
secret vault: use it only on a protected loopback browser profile and remove
saved keys before sharing the machine. Keys never enter manifests, events,
reports, artifacts, Pi, a sandbox, or the database.

Archive intake is not a generic file runner: it accepts only bounded supported
archive formats, rejects traversal/links/special files/bombs, never executes
the content, and does not recursively unpack nested archives.

Pi remains the separate reviewed harness for its typed gateway and controlled
session path. It is never the policy or flag-verification authority, and the
Power ReAct loop does not imply that Pi has access to provider credentials or a
Docker socket.

## Commands

```bash
pnpm install --frozen-lockfile
pnpm --filter @ctfmesh/web dev
pnpm --filter @ctfmesh/web test
pnpm --filter @ctfmesh/web build
pnpm --filter @ctfmesh/web check
```

Vite proxies `/v1` to `http://127.0.0.1:8000` during local development.

## Container profile

```bash
docker compose up --build --wait
```

The runtime image serves the static build as an unprivileged `nginx` user on
port `8080`; Compose publishes it only on `127.0.0.1:5173`. Nginx proxies `/v1/`
to the internal API service, streams permitted archive bodies rather than
buffering them into the Web container, and has a 128 MiB request cap. The
standalone image health endpoint is `/healthz`.

Only the Web reverse proxy is loopback-published (`127.0.0.1:5173`); the API
has no host port and is reachable only through `/v1/` on that proxy. The local
control plane has no authentication or tenant isolation.
