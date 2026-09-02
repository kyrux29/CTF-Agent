# Power P5 worklog — toolkit image and reviewed category packs

**Status:** completed
**Started:** 2026-09-01
**Completed:** 2026-09-01

## Invariant

- A Power workspace uses one reviewed, reproducibly-built slim image. It remains non-root and receives neither API keys, Docker socket, host mounts, nor network by default.
- Category guidance is checked into the trusted orchestrator package. It is not loaded from the archive, a challenge-local `.pi`/`.agents`/`AGENTS.md`, or the public web.
- Pack selection is deterministic from sanitized AutoPrompter category signals and typed actions. A pack is an operational checklist, never evidence or flag authority.

## Planned slice

1. Add five small reviewed packs (`web`, `pwn`, `rev`, `crypto`, `forensics`) with digest-aware loader and deterministic selector.
2. Feed exactly one selected reviewed pack into every P4 racer after AutoPrompter finishes.
3. Create `images/ctf-toolkit/Dockerfile` with exact Alpine/Python tool pins; make the Power Compose workspace image build it.
4. Add unit and Docker smoke proof for pack selection and `gdb`, `pwn`, and `r2`; run full gates and complete the canonical Progress/Decision Log.

## Delivered slice

1. Added five compact trusted packs under the orchestrator package: web, pwn,
   reverse, crypto, and forensics. The loader accepts only these fixed resource
   names, bounds each file to 4,000 characters, validates its Markdown header,
   and exposes its SHA-256 digest. The wheel build was checked to contain all
   five resources.
2. Added deterministic category selection after the ten-turn AutoPrompter
   brief. The selector receives only typed action names and bounded in-memory
   category labels derived from observations; it does not persist or return raw
   source/tool output. Every racer receives the selected checklist as context,
   while the flag router remains the only completion authority.
3. Added `images/ctf-toolkit/Dockerfile` using a digest-pinned Alpine base,
   exact APK versions, and `requirements.lock` with all resolved pip tool
   versions. It supplies the slim default CTF surface: GDB, radare2, binutils,
   Python/pwntools/ROPGadget/gmpy2, Z3, crypto and web helpers, exiftool, tshark,
   binwalk, tracing, and core shell tools. Sage and Ghidra remain deliberately
   outside the default slim tag and require a future explicit full-image slice.
4. Pointed Power Compose and the sandboxd immutable image setting at
   `ctfmesh-ctf-toolkit:0.1`. The former P1–P4 image remains only as a narrow
   compatibility fixture for earlier milestone smoke tests; it is no longer the
   deployed Power workspace image.
5. Corrected a real runtime boundary found by the P5 smoke: Docker tmpfs mounts
   defaulted to root ownership despite image-directory ownership. `/work` is
   now uid/gid 1000 and mode 0700; `/tmp` is a noexec sticky tmpfs. The solver
   stays non-root, has a read-only root filesystem and no network or Docker
   socket.

## Commands and results

- Focused P5/unit/Compose proof: `20 passed, 2 skipped, 1 warning in 1.39s`.
- Orchestrator wheel build: `uv build --package ctfmesh-orchestrator --wheel`
  passed; a zip inspection verified all five `reviewed_packs/*.md` files.
- Direct toolkit smoke: digest-pinned image built successfully; `pip check`,
  `gdb --version`, `python3 -c "import gmpy2; import pwn"`, `r2 -v`, and a
  non-root writable `/work` check passed with network disabled and a read-only
  root filesystem.
- P5 sandboxd smoke (`CTFMESH_RUN_POWER_DOCKER_SMOKE=1`): `1 passed in
  55.85s`. It builds the toolkit, enters it only through `WorkspaceService`,
  verifies GDB/pwntools/radare2, writes to `/work`, destroys the workspace, and
  removes its uniquely-tagged image. It uses no provider, API key, target, or
  committed challenge data.
- Compose validation: `docker compose config --quiet` and
  `docker compose --profile power config --quiet` passed.
- Web/Pi check: `33` web tests plus Vite production build and `28` Pi tests
  passed.
- Full Python gate in the pinned test image: `uv lock --check`, Ruff format and
  lint, and Pyright (`0 errors`) passed; `341 passed, 14 skipped, 1 warning in
  265.79s`.

## Remaining risks

- The image is intentionally slim, not a Kali replacement. Sage/Ghidra and
  other large/category-specific extras must be a separately reviewed opt-in
  image, with their own pins and smoke proof.
- P5 wires static packs and a local image only. P6 must map provider/model/
  budget to racers; P8 must expose the operator-start Power flow in the UI.
