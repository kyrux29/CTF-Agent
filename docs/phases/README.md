# Phase worklogs

Phase worklogs are append-only implementation records: commands run, test
results, assumptions, and residual risks. They are useful for audit and
handoff, but they are not the primary installation or product documentation.

| Stream | Latest worklog | Current next gate |
|---|---|---|
| Original v0.1 | [M6](v0.1-pi-execplan-m6-worklog.md) | Operator-authorized live evidence |
| Power profile | [P9](power-m9-worklog.md) | Comparative raw evaluation |
| Power on Pi | [M-PI-5](power-pi-m5-worklog.md) | File-flag and toy pwn/web raw evaluation |
| Operator desk UI | [U6](ui-u6-worklog.md) | Follow the active Power-on-Pi plan before new UI scope |

Earlier files in this directory are retained as chronological evidence. When a
worklog conflicts with a current execution plan, ADR, or source contract, the
current plan/ADR/source contract wins.
