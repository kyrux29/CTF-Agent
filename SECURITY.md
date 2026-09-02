# Security policy

## Supported profile

The current local profile is intended for authorized CTF work. It does not
claim secure execution of untrusted generated code. Production deployment is
unsupported until the rootless OCI/gVisor, OS-level egress, secret broker, and
container escape suites pass.

## Reporting

Do not open a public issue for a vulnerability that could expose credentials,
flags, or host infrastructure. Send a minimal reproducer to the maintainers'
private security contact configured for the repository. Do not include live
contest flags or third-party targets.

## Invariants

- exact manifest scope; deny by default;
- known credential/flag-shaped values and sensitive fields are redacted from
  events, logs, and generated exports. The explicit local single-operator
  convenience profile stores provider keys as plaintext only in the browser
  origin's `localStorage`; it is not a secret vault and must be used only on a
  protected, loopback-only browser profile. Keys never enter the database,
  event ledger, artifacts, sandboxes, challenge volumes, or containers;
- no Docker socket, privileged mode, host network/PID/IPC, or host devices;
- provider/generated-code subprocesses do not use `shell=True`, and there is no
  host execution fallback for generated code;
- the run-event repository API exposes append/list operations only, and
  artifact reads verify content digests;
- only the repository verification-record path may set `solved`; the deployed
  verifier uses a distinct internal credential and signed two-replay proof;
- contest manifests cannot enable public search or authorize public targets;
  long-term memory retrieval is not implemented in v0.1.

Security findings are triaged as Critical, High, Medium, or Low. A Critical or
High finding blocks release until a regression test and fix are merged.
