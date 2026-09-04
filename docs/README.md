# CTFMesh documentation

This page is the documentation entry point. Read the smallest set that matches
your role; detailed execution history is intentionally separated from the
operator and contributor guides.

## I want to use CTFMesh

Start with the [root README](../README.md) for Docker startup, or use the
[Vietnamese repository README](../README.vi.md). For a reproducible fresh
machine setup, follow [Local deployment](deployment-local.md) or [Local
deployment (Vietnamese)](deployment-local-vi.md). Then use the [Vietnamese
usage guide](usage-guide-vi.md) for the browser workflow, Power profile,
troubleshooting, and cleanup. Use only authorized CTF material and targets.

For a release or demo, use the
[release-readiness checklist](release-readiness-v0.1.md). Focused operations
guides are available for the legacy Pi fixture, M3 typed tools, M5 verifier
labs, and M6 evaluation under [operations/](operations/).

## I want to contribute

Read [CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md), then
use this order:

1. [Threat model](threat-model/v0.1.md) and the relevant [ADR](adr/).
2. The active plan below.
3. The related product source and a focused existing test in `tests/`.
4. The current phase worklog only for assumptions, command records, and
   remaining risk.

## Plans and status

| Area | Current source of truth | Status |
|---|---|---|
| Original v0.1 control plane | [Pi v0.1 operational companion](execplans/pi-ctf-v0.1.md) | Baseline complete through M5; M6 release evidence remains open |
| Original Vietnamese product design | [CTFMesh Pi v0.1 ExecPlan](CTFMesh-Pi-v0.1-ExecPlan.vi.md) | Historical design and decision record |
| Power profile | [Power ExecPlan](CTFMesh-power-execplan.md) | P0–P8 complete; P9 comparative evaluation remains open |
| Power on Pi | [Pi harness ExecPlan](CTFMesh-pi-harness-execplan.md) | M-PI-0–M-PI-4 complete; M-PI-5 raw evaluation is next |
| Web UX | [UI design guide](CTFMesh-ui-design-guide.md) | Design contract for the operator desk |

Only the first unchecked milestone in the applicable active plan may be
implemented. This prevents unrelated work from silently changing the product
contract.

## Architecture and operations

| Need | Document |
|---|---|
| Security boundaries and local-operator assumptions | [Threat model](threat-model/v0.1.md) and [Security policy](../SECURITY.md) |
| Why a design constraint exists | [Architecture decisions](adr/README.md) |
| Browser interface and interaction rules | [UI design guide](CTFMesh-ui-design-guide.md) and [frontend notes](development/frontend.md) |
| Add bounded Power Pi technique guidance | [Reviewed Pi skill library](../services/pi-runner/reviewed-skill-packs/README.md) |
| Docker startup, acceptance checks, release sign-off | [Release readiness](release-readiness-v0.1.md) |
| Legacy Pi smoke, typed tool gateway, verifier labs, and evaluation | [Operations guides](operations/README.md) |

## Historical implementation records

[Phase worklogs](phases/README.md) are append-only milestone records. They preserve test
commands and design context, but are not normative setup instructions. New
contributors normally need only the current plan and its latest worklog:

- Power on Pi: [power-pi-m5-worklog.md](phases/power-pi-m5-worklog.md)
- Power profile: [power-m9-worklog.md](phases/power-m9-worklog.md)
- Original v0.1: [v0.1-pi-execplan-m6-worklog.md](phases/v0.1-pi-execplan-m6-worklog.md)

When a worklog conflicts with a current plan, ADR, or source contract, the
current plan/ADR/source contract wins. Keep new documentation concise: put
lasting guidance in a guide or ADR and only chronological evidence in a
worklog.
