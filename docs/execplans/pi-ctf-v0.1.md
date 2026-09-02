# CTFMesh Pi v0.1 — operational execution companion

> This concise companion is derived from the canonical
> [CTFMesh Pi v0.1 ExecPlan](../CTFMesh-Pi-v0.1-ExecPlan.vi.md). The canonical
> plan remains the source of truth for the full rationale, diagrams, contracts,
> threat model, acceptance criteria, Progress, and Decision Log. This file
> exists to make the active execution order discoverable from `AGENTS.md`
> without creating a second, drifting copy of the long-form plan.

- Status: active — M3 passed its authorized source-slot/lab deployment gate on
  2026-08-31. M6.a's browser-to-remote-verifier implementation is present and
  Docker-smoked; the UI now has a secret-free runtime readiness gate, embedded
  evidence panel and a local browser provider-key store under ADR 0011,
  alongside Unlimited wait, Thinking elapsed time and operator Cancel. Full
  release-hygiene pass removed unused legacy host-exec/scripted backends,
  standardized MIT metadata and added repository CI guardrails. Deterministic
  product/test/docs/support trees are now separated and CI-enforced. Tests and
  their Node dependencies live in the dedicated `tests` workspace; host-only
  utilities/examples live under `support` and are excluded from images. Gates
  pass (`306` Python, `33` Web and `28` Pi tests); all 11 `m6-ui`
  services are healthy and exact-instance capability is ready. Its
  earliest unfinished gate is an operator-authorized live challenge, followed
  by live A/B/C evidence.
- Scope: source-available assisted Web CTFs over declared exact HTTP(S) origin;
  local labs remain supported. `contest` cannot authorize a public target.
- Execution rule: retain typed tools, fixed slots and verifier authority. The
  UI lane must not execute an uploaded archive or become a generic Internet,
  Docker, shell or flag-text-to-solved pipeline.

## Non-negotiable boundary

- The Python kernel owns policy, budgets, state, audit events, and run status.
- Pi is a harness, not a sandbox or authority; custom reviewed tools are its
  only future execution surface.
- Web is only a local control surface; solve work travels through the Control
  API to Pi, typed tools, fixed slots and the independent verifier.
- The control plane never gets a Docker socket, privileged container, host
  namespace, or a path to create arbitrary containers.
- Provider keys and raw flags never enter sandbox environments, event payloads,
  database rows, or model prompts.
- A strategy, council, worker, or claimed flag cannot set `SOLVED`. Only an
  independent verifier with manifest-required clean replay proof can do so.
- Hint Cards are human hypotheses, not facts or untrusted prompt text.

## Milestone order

| Milestone | Outcome | State |
|---|---|---|
| M0 | Baseline, ADRs, repository guardrails, verifier assertion | Complete — 2026-08-28 |
| M1 | Durable kernel and deterministic fake vertical slice | Complete — 2026-08-28 |
| M2 | Pi Runner SDK/event bridge without target access | Complete — target-free Docker fixture lifecycle passed on 2026-08-29 |
| M3 | Typed tool gateway and fixed Docker slots | Complete — authorized Compose E2E passed 2026-08-31 |
| M4 | Master/worker loop, evidence and Hint Card flow | Complete — 2026-08-29 |
| M5 | Independent verifier and local lab replay | Complete — 2026-08-29; closed three-lab profile only |
| M6 | Hardening, UI exact-instance slice and release evidence | In progress — M6.a implementation/Docker smoke complete under ADR 0007; authorized live challenge and A/B/C evidence remain open |

## Required execution record

For every milestone, update the canonical plan and a phase worklog with:

1. changed contracts and explicit non-goals;
2. focused and full command results;
3. assumptions, denied paths, and remaining risks; and
4. the next earliest unchecked milestone.

M0 work is recorded in
[docs/phases/v0.1-pi-execplan-m0-worklog.md](../phases/v0.1-pi-execplan-m0-worklog.md).

M1 work is recorded in
[docs/phases/v0.1-pi-execplan-m1-worklog.md](../phases/v0.1-pi-execplan-m1-worklog.md).

M2 work in progress is recorded in
[docs/phases/v0.1-pi-execplan-m2-worklog.md](../phases/v0.1-pi-execplan-m2-worklog.md).

M3 work is recorded in
[docs/phases/v0.1-pi-execplan-m3-worklog.md](../phases/v0.1-pi-execplan-m3-worklog.md).

M4 work is recorded in
[docs/phases/v0.1-pi-execplan-m4-worklog.md](../phases/v0.1-pi-execplan-m4-worklog.md).

M5 work is recorded in
[docs/phases/v0.1-pi-execplan-m5-worklog.md](../phases/v0.1-pi-execplan-m5-worklog.md).

M6 work in progress is recorded in
[docs/phases/v0.1-pi-execplan-m6-worklog.md](../phases/v0.1-pi-execplan-m6-worklog.md).
