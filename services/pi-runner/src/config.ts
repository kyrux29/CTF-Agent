/** Runtime configuration for the isolated Pi consumer. */

import { resolve } from "node:path";

import { ControlProtocolError } from "./contracts.js";

export type RunnerMode = "fixture" | "live";

export interface RunnerConfig {
  readonly runnerId: string;
  readonly controlBaseUrl: string;
  readonly controlToken: string;
  readonly trustedCwd: string;
  readonly trustedAgentDir: string;
  readonly sessionRoot: string;
  readonly mode: RunnerMode;
  readonly pollIntervalMs: number;
  readonly requestTimeoutMs: number;
  /** Private API-to-runner credential handoff listener; never published. */
  readonly credentialBrokerBindHost: string;
  readonly credentialBrokerBindPort: number;
  /** Upper TTL accepted from the control API for an in-memory API-key lease. */
  readonly credentialLeaseMaxTtlSeconds: number;
  /** Small bounded grace period for a start job racing the lease handoff. */
  readonly credentialLeaseWaitMs: number;
  /**
   * Backstop against a racer looping forever, not the operating limit.  The
   * run budget (`max_cost_usd`, `wall_time_seconds`) is what should normally
   * end a race; a low value here silently caps a run far below the budget the
   * operator chose.
   */
  readonly powerRacerMaxSolveBatches: number;
  /**
   * Reasoning effort for Power sessions.
   *
   * This was fixed at `"off"`, so a reasoning model solved with its reasoning
   * disabled — on a hard binary-exploitation challenge that is most of the
   * capability being paid for. It stays a deployment choice because effort is
   * billed: a higher level costs more per turn and is not always the better
   * trade for a cheap recon pass.
   */
  readonly powerThinkingLevel: PowerThinkingLevel;
  /**
   * Legacy non-secret model identifiers. UI-run leases choose the actual
   * provider/model; these remain only to keep older deployment config valid.
   */
  readonly modelProvider: string | null;
  readonly modelId: string | null;
}

const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const MODEL_PART = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;
const CREDENTIAL_BROKER_HOSTS = new Set(["0.0.0.0", "127.0.0.1", "::", "::1"]);
const FORBIDDEN_PROVIDER_KEY_ENVIRONMENTS = [
  "OPENAI_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "DEEPSEEK_API_KEY",
] as const;

function configError(code: string): never {
  throw new ControlProtocolError(code);
}

export const POWER_THINKING_LEVELS = [
  "off", "minimal", "low", "medium", "high", "xhigh", "max",
] as const;

export type PowerThinkingLevel = (typeof POWER_THINKING_LEVELS)[number];

function thinkingLevel(raw: string | undefined): PowerThinkingLevel {
  if (raw === undefined || raw === "") {
    return "medium";
  }
  const match = POWER_THINKING_LEVELS.find((level) => level === raw);
  if (match === undefined) {
    configError("power_thinking_level_invalid");
  }
  return match;
}

function boundedInteger(raw: string | undefined, fallback: number, name: string, minimum: number, maximum: number): number {
  if (raw === undefined || raw === "") {
    return fallback;
  }
  if (!/^[0-9]+$/.test(raw)) {
    configError(`${name}_invalid`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    configError(`${name}_invalid`);
  }
  return value;
}

function configuredPath(raw: string | undefined, fallback: string, name: string): string {
  const value = raw?.trim() || fallback;
  if (!value.startsWith("/")) {
    configError(`${name}_must_be_absolute`);
  }
  return resolve(value);
}

function controlUrl(raw: string | undefined): string {
  const configured = raw?.trim() || "http://api:8000";
  let parsed: URL;
  try {
    parsed = new URL(configured);
  } catch {
    configError("control_base_url_invalid");
  }
  // The runner is intentionally not a general HTTP client. These are the only
  // names it may reach: Docker's internal API alias and test-local loopback.
  if (
    parsed.protocol !== "http:"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
    || !["api", "localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
  ) {
    configError("control_base_url_not_allowlisted");
  }
  return parsed.toString().replace(/\/$/, "");
}

function credentialBrokerHost(raw: string | undefined): string {
  const host = raw?.trim() || "0.0.0.0";
  if (!CREDENTIAL_BROKER_HOSTS.has(host)) {
    configError("credential_broker_bind_host_invalid");
  }
  return host;
}

/**
 * Read service configuration only. Provider credentials are deliberately not
 * read or represented here. Live sessions receive a short-lived, in-memory
 * credential lease over the authenticated private broker instead of process
 * environment variables.
 */
export function loadRunnerConfig(environment: NodeJS.ProcessEnv = process.env): RunnerConfig {
  const modeRaw = environment.CTFMESH_PI_RUNNER_MODE ?? "fixture";
  if (modeRaw !== "fixture" && modeRaw !== "live") {
    configError("runner_mode_invalid");
  }
  const runnerId = environment.CTFMESH_PI_RUNNER_ID ?? "pi-runner-1";
  if (!RUNNER_ID.test(runnerId)) {
    configError("runner_id_invalid");
  }
  const controlToken = environment.CTFMESH_INTERNAL_RUNNER_TOKEN ?? "";
  if (controlToken.length < 16 || controlToken.length > 512 || !controlToken.trim()) {
    configError("internal_runner_token_invalid");
  }
  for (const name of FORBIDDEN_PROVIDER_KEY_ENVIRONMENTS) {
    if (environment[name]?.trim()) {
      // Failing closed prevents Pi's SDK from silently discovering a key that
      // was injected into the process by an older Compose profile.
      configError("provider_api_key_environment_forbidden");
    }
  }
  const provider = environment.CTFMESH_PI_MODEL_PROVIDER?.trim() || null;
  const modelId = environment.CTFMESH_PI_MODEL_ID?.trim() || null;
  if ((provider === null) !== (modelId === null)) {
    configError("runner_model_pair_required");
  }
  if ((provider !== null && !MODEL_PART.test(provider)) || (modelId !== null && !MODEL_PART.test(modelId))) {
    configError("runner_model_identifier_invalid");
  }
  const trustedCwd = configuredPath(
    environment.CTFMESH_PI_TRUSTED_CWD,
    "/opt/ctfmesh/empty-cwd",
    "trusted_cwd",
  );
  const trustedAgentDir = configuredPath(
    environment.CTFMESH_PI_AGENT_DIR,
    "/opt/ctfmesh/agent",
    "trusted_agent_dir",
  );
  const sessionRoot = configuredPath(
    environment.CTFMESH_PI_SESSION_ROOT,
    "/data/pi-sessions",
    "session_root",
  );
  if (new Set([trustedCwd, trustedAgentDir, sessionRoot]).size !== 3) {
    configError("runner_paths_must_be_distinct");
  }
  return {
    runnerId,
    controlBaseUrl: controlUrl(environment.CTFMESH_CONTROL_BASE_URL),
    controlToken,
    trustedCwd,
    trustedAgentDir,
    sessionRoot,
    mode: modeRaw,
    pollIntervalMs: boundedInteger(
      environment.CTFMESH_PI_POLL_INTERVAL_MS,
      750,
      "poll_interval_ms",
      100,
      60_000,
    ),
    requestTimeoutMs: boundedInteger(
      environment.CTFMESH_PI_REQUEST_TIMEOUT_MS,
      5_000,
      "request_timeout_ms",
      500,
      30_000,
    ),
    credentialBrokerBindHost: credentialBrokerHost(environment.CTFMESH_PI_CREDENTIAL_BIND_HOST),
    credentialBrokerBindPort: boundedInteger(
      environment.CTFMESH_PI_CREDENTIAL_BIND_PORT,
      8090,
      "credential_broker_bind_port",
      1,
      65_535,
    ),
    credentialLeaseMaxTtlSeconds: boundedInteger(
      environment.CTFMESH_PI_CREDENTIAL_MAX_TTL_SECONDS,
      900,
      "credential_lease_max_ttl_seconds",
      30,
      3_600,
    ),
    credentialLeaseWaitMs: boundedInteger(
      environment.CTFMESH_PI_CREDENTIAL_WAIT_MS,
      10_000,
      "credential_lease_wait_ms",
      0,
      30_000,
    ),
    powerThinkingLevel: thinkingLevel(environment.CTFMESH_PI_POWER_THINKING_LEVEL),
    powerRacerMaxSolveBatches: boundedInteger(
      environment.CTFMESH_PI_POWER_MAX_SOLVE_BATCHES,
      200,
      "power_racer_max_solve_batches",
      1,
      10_000,
    ),
    modelProvider: provider,
    modelId,
  };
}
