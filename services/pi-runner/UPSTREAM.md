# Pi SDK upstream record

- Package: `@earendil-works/pi-coding-agent`
- Pinned version: `0.84.4`
- Upstream tag: `v0.84.4`
- Upstream commit: `b79e4cc834970cca69daebffab7df1da7d1e52c4`
- npm integrity:
  `sha512-jmOlrqUmvhh/siNWFRXjYLJzhKFIHNsAQaysRwzQPQFnPAaV/vhqHsLH/MBsIISA1Rjj7WTUFR3nJrpXoLx39w==`
- Upstream repository: <https://github.com/earendil-works/pi>
- Upstream package directory: `packages/coding-agent`
- License: MIT
- Reviewed: 2026-09-01
- Local patches: none

Reviewed SDK surface:

- `createAgentSession`
- `defineTool`
- `SettingsManager.inMemory()` and `applyOverrides()`
- `AgentSession.compact()`, `steer()`, and `abort()`
- `CreateAgentSessionOptions.noTools`

CTFMesh uses Pi through its TypeScript SDK (`createAgentSession`), never by
parsing CLI stdout. The runner pins a reviewed resource loader, an empty trusted
working directory, and an explicit custom-tool allowlist. Built-in file/shell
tools are disabled for every session.
