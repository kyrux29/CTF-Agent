# Architecture decisions

ADRs record durable technical decisions. Read the ADR matching the subsystem you
are changing; do not copy a decision into a worklog or replace it with an
implementation detail.

| ADR | Decision |
|---|---|
| [0001](0001-vertical-slice.md) | Deliver the verified Web-lab vertical slice first |
| [0002](0002-pi-sdk-harness.md) | Use Pi as a constrained agent harness |
| [0003](0003-no-docker-socket.md) | Use isolated execution slots, never a control-plane Docker socket |
| [0004](0004-web-only-v0.1.md) | Limit the original v0.1 scope to local source-available Web labs |
| [0005](0005-verifier-authority.md) | Reserve `SOLVED` for independent verification |
| [0006](0006-hint-card-epistemics.md) | Treat a Hint Card as a human hypothesis |
| [0007](0007-ui-driven-exact-instance-flow.md) | Use a UI-driven exact-instance flow for authorized Web CTFs |
| [0008](0008-encrypted-browser-provider-vault.md) | Document the superseded browser key-vault approach |
| [0009](0009-power-profile.md) | Enable the opt-in Power profile with one trusted Docker manager |
| [0010](0010-power-on-pi-harness.md) | Route Power model turns through the Pi harness |
| [0011](0011-local-browser-provider-key-store.md) | Store Power provider keys only in the local browser profile |

The current browser key-storage contract is ADR 0011. ADR 0008 remains for
history and must not be treated as the active implementation.
