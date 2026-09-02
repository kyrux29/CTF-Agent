# UI U1 worklog — token and operator shell

## Complete — 2026-09-02

### Objective

Implement only U1 from `CTFMesh-ui-design-guide.md`: establish the dark
operator token layer, replace the history-only sidebar with the 48px activity
bar and four mutually exclusive views, and make the empty workbench obvious
without exposing Power launch controls before an archive exists.

No Control API, Pi, sandbox, credential, or flag-reveal contract changed.

### Design decision

The page is a dense local CTF workbench. Its visual signature is the slim
teal-lab activity rail: one active signal on an otherwise neutral graphite
surface. Typography stays system-local; IDs and metrics use the existing mono
stack. Motion is limited to useful state transitions and respects reduced
motion.

### Implementation

- Added the §3 graphite, text, state, focus, spacing, and activity-bar tokens
  to the single root token block. No CDN font or icon was introduced.
- Added inline SVG controls for History, Progress, Stats, Help, and Settings.
  Clicking the active view again returns its width to the workbench.
- History retains archive/run navigation. Progress projects only active runs;
  Stats shows four ledger-derived counts; Help stays three short operator
  instructions.
- Reduced cold start to one archive dropzone and one Settings link. Racer,
  target, and Start controls do not enter the DOM until intake exists.
- On widths below 720px, the activity rail moves to the bottom and the selected
  panel fills the area between the fixed header and bottom bar.
- Updated the document title and browser theme color to Operator Desk tokens.

### Validation

- `pnpm --filter @ctfmesh/web check` — passed: TypeScript, 16 Vitest tests,
  and production Vite build.
- `pnpm --filter @ctfmesh/pi-runner check` — passed: 41 tests.
- Full isolated repository gate — passed: lock check, Ruff formatting/lint,
  Pyright with 0 diagnostics, and 378 passed / 14 skipped Python tests.
- Compose default and Power configuration validation — passed.
- Playwright visual smoke — passed at desktop and 390×844. History/Stats view
  switching, Settings opening, collapsed-panel recovery, and mobile bottom bar
  were checked in a real Chromium session.
- Docker runtime smoke at `http://127.0.0.1:5173` — healthy, correct Operator
  Desk title, 0 browser console errors or warnings.
- After the Web service recreation, `pi-runner-live` was restarted because its
  previous control transport had been interrupted. API, Web, provider proxy,
  sandboxd, flag router, and Pi runner were confirmed running; every service
  with a healthcheck reported healthy.

### Environment note

The Docker daemon stalled while resolving the pinned Nginx manifest even
though the host could reach Docker Hub. For the local demo only, the tested
Vite bundle was copied into a disposable container based on the already
trusted `ctfmesh-web` image, committed with the original Nginx entrypoint/user,
and the Web service alone was recreated. The repository Dockerfile remains
unchanged and reproducible; a clean-machine image build still depends on the
daemon's registry path becoming responsive.

### Cleanup

Removed the disposable full-gate container, Vite process, Playwright browser,
all Playwright screenshots/snapshots, repository Python bytecode outside the
ignored `.venv`, and pytest caches. The running product data, `.env`, archive
records, and challenge data were not touched.
