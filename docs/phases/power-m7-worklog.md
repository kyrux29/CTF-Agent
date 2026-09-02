# Power P7 worklog — local knowledge retrieval

**Status:** completed
**Started:** 2026-09-01
**Completed:** 2026-09-01

## Invariant

- Knowledge consists only of operator-managed Markdown under the checked local
  `knowledge/writeups/` root. Archive/challenge files, `.pi`, `.agents`, and
  `AGENTS.md` are never corpus inputs.
- Every indexed document is bounded and digest-pinned. Retrieval returns only
  bounded excerpts plus document IDs/digests; it does not make a writeup fact,
  observation, command, or flag authority.
- In `contest_offline` mode no document is loaded, searched, or injected into
  a model context. The result must be an explicit empty receipt.
- AutoPrompter never receives retrieved text. Only a selected executor may
  receive top-k local guidance after the receipt-only brief is complete.

## Planned slice

1. Add a repository-owned local corpus root and a strict Markdown loader with
   filename, size, UTF-8, and digest checks.
2. Add deterministic token retrieval with a top-k bound and `contest_offline`
   deny path.
3. Bind retrieval after AutoPrompter to one delegated racer only; keep other
   racers and the coordinator read-model free of writeup content.
4. Add focused corpus/race tests, run full gates, and update this worklog plus
   the canonical ExecPlan.

## Delivered slice

1. Added the local-only `ctfmesh-knowledge` package and the ignored,
   operator-owned `knowledge/writeups/` corpus root. The loader accepts only
   bounded UTF-8 Markdown regular files, rejects symlinks and hidden paths,
   records a per-document SHA-256 digest, and derives a canonical corpus pin.
   A caller can supply an expected pin to reject a changed corpus.
2. Added deterministic lexical retrieval with a strict top-k maximum of five
   and bounded excerpts. It requires no embedding service, provider request,
   API key, or network access. Flag-shaped literals in historical notes are
   redacted before an excerpt can enter a model context, while the original
   bytes are still reflected by the change-detecting digest.
3. Added `contest_offline` as a hard precondition both at local retrieval and
   swarm coordination: it returns an explicit empty receipt before validating
   a path, reading a corpus, or inspecting the query. A malformed or changed
   optional corpus becomes an `unavailable` metadata result; it cannot turn a
   valid CTF run into a self-reported solve.
4. Bound retrieval to the Power flow after AutoPrompter and category-pack
   selection. The retrieval query contains only bounded receipt/category
   labels rather than archive content or tool output. The rendered advisory
   excerpts go to one configured racer only; sibling racers, AutoPrompter,
   and the coordinator snapshot receive no writeup text. The independent
   flag router remains the only `solved` authority.

## Commands and results

- Focused P7 contracts in the pinned Docker test runtime: `uv run pytest -q
  tests/unit/test_power_knowledge.py tests/unit/test_power_swarm.py
  tests/unit/test_power_race.py tests/unit/test_power_solver_model.py` —
  `21 passed in 0.67s`. The acceptance fixture has three documents; query
  `padding oracle` returned the intended technique paragraph. The offline
  test used a nonexistent root and confirmed zero hits without filesystem
  access.
- Focused Ruff and Pyright over P7 code/tests passed: `0 errors, 0 warnings,
  0 informations`.
- Web check: `pnpm --filter @ctfmesh/web check` — TypeScript, `34` browser
  tests, and production Vite build passed.
- Pi check: `pnpm --filter @ctfmesh/pi-runner check` — `28 passed`.
- Full backend gate in the pinned Docker test runtime: `uv lock --check`,
  Ruff format/lint, Pyright (`0 errors, 0 warnings, 0 informations`), and
  full `pytest -q` — `356 passed, 14 skipped, 1 warning in 258.56s`; exit 0.
  No provider request, credential, archive, or live challenge was used.
- Compose validation: `docker compose config --quiet` and
  `docker compose --profile power config --quiet` passed.

## Remaining risks

- P7 deliberately uses transparent lexical ranking rather than embeddings.
  It is deterministic and fully offline, but semantic recall will be lower
  for vocabulary not present in an operator note. Any future embedding option
  must remain local, digest-pinned, bounded, and disabled by
  `contest_offline`.
- P8 is responsible for connecting the P7 options to the Power UI/start API.
  The coordinator seam is complete today, but no browser path can silently
  enable local writeups before that milestone.
