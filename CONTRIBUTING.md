# Contributing

1. Read `AGENTS.md`, the relevant ADR, threat model, and current phase worklog.
2. Open an issue describing the smallest coherent behavior change.
3. Add tests, including deny paths for policy or security changes.
4. Run backend and Web checks shown in `README.md`.
5. Record assumptions, commands, results, and residual risks in the worklog.

Keep provider SDKs in provider adapters, infrastructure out of the domain
package, and all tool actions behind `ToolRuntime`. Do not disable a failing test
or loosen a security rule to make a contribution pass.

Pull requests should state architecture impact, security impact, migration
impact, tests run, and remaining risk. Examples must remain executable and must
not contain a real flag, credential, or writeup answer in agent-visible input.
