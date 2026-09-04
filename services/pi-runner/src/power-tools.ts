/**
 * Pi-native Power tools.
 *
 * The runner deliberately owns only Pi session state. Every operation below
 * crosses a typed control seam that M-PI-2 binds to the reviewed Power
 * control-plane routes. The adapter never imports `child_process`, opens a
 * socket, reads a challenge file, or contacts sandboxd/flag-router directly.
 */

import {
  defineTool,
  type AgentToolResult,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import { ControlProtocolError } from "./contracts.js";
import type { PowerToolTranscript } from "./power-activity.js";
import type { TurnLease } from "./tools.js";

/** The maximum text visible to Pi for one Power observation. */
export const POWER_TOOL_CONTEXT_MAX_CHARS = 4_000;

export const POWER_TOOL_NAMES = [
  "ctf_artifact_read",
  "ctf_shell_exec",
  "ctf_fs_list",
  "ctf_fs_read",
  "ctf_fs_write",
  "ctf_pty_start",
  "ctf_pty_send",
  "ctf_pty_read",
  "ctf_pty_close",
  "ctf_gdb_start",
  "ctf_gdb_cmd",
  "ctf_gdb_read",
  "ctf_gdb_close",
  "ctf_tube_connect",
  "ctf_tube_send",
  "ctf_tube_recv",
  "ctf_tube_close",
  "ctf_flag_submit",
] as const;

export type PowerToolName = (typeof POWER_TOOL_NAMES)[number];
export type PowerToolRole = "autoprompter" | "racer";
export type PowerInteractiveKind = "pty" | "gdb" | "tube";

/**
 * AutoPrompter establishes only a compact evidence baseline.  Giving it PTY,
 * GDB, and remote-tube control made it compete with the racers for the same
 * budget while frequently repeating their first observations.
 */
const AUTOPROMPTER_TOOL_NAMES = [
  "ctf_fs_list",
  "ctf_fs_read",
  "ctf_shell_exec",
] as const satisfies readonly PowerToolName[];

/** A short tool batch keeps a long Pi turn observable and steerable. */
export const POWER_RACER_TOOL_BATCH_LIMIT = 10;
export const POWER_AUTOPROMPTER_TOOL_BATCH_LIMIT = 6;
const WORKSPACE_ID = /^ws_[0-9a-f]{32}$/;
const CHANNEL_ID = {
  pty: /^pty_[0-9a-f]{32}$/,
  tube: /^tube_[0-9a-f]{32}$/,
} as const;
const ARTIFACT_ID = /^sha256:[0-9a-f]{64}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const OBSERVATION_HANDLE = /^obs_[1-9][0-9]{0,5}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export interface PowerArtifactReference {
  readonly id: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

/** A CAS-backed observation returned by sandboxd through the control plane. */
export interface PowerToolObservation {
  readonly artifact: PowerArtifactReference;
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number | null;
  readonly timedOut: boolean;
  readonly outputTruncated: boolean;
  /**
   * A manifest-format candidate was observed. It carries no candidate bytes;
   * Pi must end the native turn and wait for the local operator's review.
   */
  readonly candidateReviewRequired?: boolean;
  /** Count of configured-format values found in this one observation. */
  readonly candidateCount?: number;
  readonly interactiveId?: string;
  readonly interactiveKind?: PowerInteractiveKind;
}

export interface PowerChannelReceipt {
  readonly state: "open" | "closed";
}

export interface PowerFlagSubmissionReceipt {
  /** This acknowledges a router decision, never a run state transition. */
  readonly accepted: boolean;
}

export interface PowerExecRequest {
  readonly workspaceId: string;
  readonly command: readonly string[];
  readonly timeoutSeconds: number;
  readonly workingDirectory: "/challenge" | "/work";
  /**
   * Fixed adapter identity for coordination only.  It is never model input
   * and lets the API fingerprint an fs_read path without recording the path.
   */
  readonly toolName?: PowerToolName;
}

export interface PowerPtyStartRequest extends PowerExecRequest {}

export interface PowerPtySendRequest {
  readonly workspaceId: string;
  readonly ptyId: string;
  readonly data: string;
}

export interface PowerPtyReadRequest {
  readonly workspaceId: string;
  readonly ptyId: string;
  readonly maxBytes: number;
  readonly waitMs: number;
  readonly kind: "pty" | "gdb";
}

export interface PowerPtyCloseRequest {
  readonly workspaceId: string;
  readonly ptyId: string;
}

export interface PowerTubeConnectRequest {
  readonly workspaceId: string;
  readonly host: string;
  readonly port: number;
  readonly timeoutSeconds: number;
}

export interface PowerTubeSendRequest {
  readonly workspaceId: string;
  readonly tubeId: string;
  readonly dataBase64: string;
}

export interface PowerTubeReceiveRequest {
  readonly workspaceId: string;
  readonly tubeId: string;
  readonly delimiterBase64: string;
  readonly maxBytes: number;
  readonly timeoutSeconds: number;
}

export interface PowerTubeCloseRequest {
  readonly workspaceId: string;
  readonly tubeId: string;
}

export interface PowerArtifactReadRequest {
  readonly artifactId: string;
  readonly offset: number;
  readonly length: number;
}

/** One window of an already stored observation, plus its true total size. */
export interface PowerArtifactWindow {
  readonly artifactId: string;
  readonly offset: number;
  readonly totalBytes: number;
  readonly returnedBytes: number;
  readonly text: string;
}

export interface PowerFlagSubmissionRequest {
  readonly runId: string;
  /** Transient candidate sent only to the independent flag-router boundary. */
  readonly candidate: string;
  readonly observationArtifactId: string;
  readonly observationSha256: string;
}

/**
 * M-PI-2 implements this at the Pi runner's typed control client. Method
 * names map one-to-one to static, authenticated control routes; a model never
 * supplies a URL, workspace ID, or service capability token.
 */
export interface PowerToolControl {
  exec(lease: TurnLease, request: PowerExecRequest): Promise<PowerToolObservation>;
  readArtifact(lease: TurnLease, request: PowerArtifactReadRequest): Promise<PowerArtifactWindow>;
  ptyStart(lease: TurnLease, request: PowerPtyStartRequest): Promise<PowerToolObservation>;
  ptySend(lease: TurnLease, request: PowerPtySendRequest): Promise<PowerChannelReceipt>;
  ptyRead(lease: TurnLease, request: PowerPtyReadRequest): Promise<PowerToolObservation>;
  ptyClose(lease: TurnLease, request: PowerPtyCloseRequest): Promise<PowerChannelReceipt>;
  tubeConnect(lease: TurnLease, request: PowerTubeConnectRequest): Promise<PowerToolObservation>;
  tubeSend(lease: TurnLease, request: PowerTubeSendRequest): Promise<PowerChannelReceipt>;
  tubeReceive(lease: TurnLease, request: PowerTubeReceiveRequest): Promise<PowerToolObservation>;
  tubeClose(lease: TurnLease, request: PowerTubeCloseRequest): Promise<PowerChannelReceipt>;
  submitFlag(lease: TurnLease, request: PowerFlagSubmissionRequest): Promise<PowerFlagSubmissionReceipt>;
}

export interface PowerToolAuthority {
  require(sessionId: string): TurnLease;
}

/**
 * Local-only turn boundary controller. It never authorizes a tool: the typed
 * control plane still owns that decision. When a model tries to exceed the
 * evidence batch, the bound Pi session receives a focused steer at the next
 * safe tool boundary and the runner can begin a new checkpointed turn.
 */
export class PowerToolBatchLimiter {
  private calls = 0;
  private exhaustedValue = false;
  private candidateReviewRequiredValue = false;
  private steerCurrentTurn: ((reason: "batch" | "candidate_review") => void) | undefined;

  public constructor(private readonly maximumCalls: number) {
    if (!Number.isSafeInteger(maximumCalls) || maximumCalls < 1 || maximumCalls > 128) {
      throw new Error("power_tool_batch_limit_invalid");
    }
  }

  public beginTurn(): void {
    this.calls = 0;
    this.exhaustedValue = false;
    this.candidateReviewRequiredValue = false;
  }

  public bindSteer(callback: (reason: "batch" | "candidate_review") => void): void {
    this.steerCurrentTurn = callback;
  }

  public get exhausted(): boolean {
    return this.exhaustedValue;
  }

  public get callsInTurn(): number {
    return this.calls;
  }

  /** Stop at the next Pi boundary until the browser accepts or rejects it. */
  public get candidateReviewRequired(): boolean {
    return this.candidateReviewRequiredValue;
  }

  public requestCandidateReview(): void {
    if (this.candidateReviewRequiredValue) {
      return;
    }
    this.candidateReviewRequiredValue = true;
    this.exhaustedValue = true;
    queueMicrotask(() => this.steerCurrentTurn?.("candidate_review"));
  }

  /** Flag submission remains available after a final evidence observation. */
  public consume(): boolean {
    if (this.exhaustedValue) {
      return false;
    }
    this.calls += 1;
    if (this.calls <= this.maximumCalls) {
      return true;
    }
    this.exhaustedValue = true;
    // Do not await SDK work inside a custom tool invocation. Pi inserts the
    // steer before its next model request and preserves this session's
    // transcript for the focused continuation batch.
    queueMicrotask(() => this.steerCurrentTurn?.("batch"));
    return false;
  }
}

export interface PowerToolScope {
  readonly role: PowerToolRole;
  readonly runId: string;
  readonly sessionId: string;
  /** Injected by trusted orchestration; never a custom-tool parameter. */
  readonly workspaceId: string;
  readonly authority: PowerToolAuthority;
  readonly control: PowerToolControl;
  /** Shared only by the local Pi session; never sent to control or sandboxd. */
  readonly toolBatch?: PowerToolBatchLimiter;
  /** Best-effort flush of safe operator activity before a tool receipt. */
  readonly beforeAction?: (lease: TurnLease) => Promise<void>;
  /**
   * Best-effort terminal record for a completed reviewed tool operation.
   * The callback must never become part of a tool's authoritative outcome.
   */
  readonly onToolTranscript?: (lease: TurnLease, transcript: PowerToolTranscript) => Promise<void>;
}

export interface TruncatedPowerToolText {
  readonly text: string;
  readonly truncated: boolean;
}

class PowerToolError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "PowerToolError";
  }
}

function powerToolError(code: string): never {
  throw new PowerToolError(code);
}

function toolResult(text: string, details: Record<string, unknown>): AgentToolResult<Record<string, unknown>> {
  return { content: [{ type: "text", text }], details };
}

/**
 * What a racer should do differently, keyed by rejection code.
 *
 * A bare "not accepted" plus an opaque code gives a model nothing to act on:
 * an observed racer retried one malformed call five times and then reported
 * that it could make no further observation, losing the rest of its run. The
 * codes stay stable for the control plane; this text is the model-facing half
 * and describes only the caller's own arguments, never workspace content.
 */
const POWER_TOOL_REMEDIATION: Readonly<Record<string, string>> = {
  power_tool_command_invalid:
    "`command` must be an argv array of 1-128 non-empty strings, not one shell string. "
    + 'For a pipeline or redirect, pass ["bash", "-lc", "<script>"].',
  power_tool_workspace_path_invalid:
    "A path must be absolute and inside /challenge or /work, with no `..` segment and no backslash.",
  power_tool_working_directory_invalid:
    "`working_directory` accepts only the literal \"/challenge\" or \"/work\".",
  power_tool_timeout_invalid: "`timeout_seconds` must be a whole number between 1 and 120.",
  power_tool_read_limit_invalid: "`max_bytes` must be a whole number between 1 and 65536.",
  power_tool_wait_invalid: "`wait_ms` must be a whole number between 1 and 2000.",
  power_tool_write_content_invalid:
    "`content` must be at most 65536 characters and contain no NUL byte.",
  power_tool_gdb_path_invalid: "ctf_gdb_start accepts only a normalized path under /challenge.",
  power_tool_gdb_command_invalid:
    "`command` must be a non-empty GDB command of at most 8192 characters.",
  power_tool_interactive_channel_not_owned:
    "That interactive ID was not created by this session, or belongs to a different channel kind. "
    + "Use the ID returned by your own ctf_pty_start, ctf_gdb_start, or ctf_tube_connect.",
  power_tool_pty_id_invalid: "`pty_id` must be the exact 36-character ID returned when you started it.",
  power_tool_tube_id_invalid: "`tube_id` must be the exact 36-character ID returned by ctf_tube_connect.",
  power_tool_tube_host_invalid: "`host` must be an exact declared IP address or DNS name.",
  power_tool_tube_port_invalid: "`port` must be a whole number between 1 and 65535.",
  power_tool_tube_delimiter_invalid: "`until` must be a non-empty delimiter of at most 64 bytes.",
  power_tool_flag_observation_handle_unknown:
    "Use the exact Evidence handle printed by the observation that contains the candidate; "
    + "a handle from another turn or another racer is not accepted.",
  power_tool_flag_candidate_invalid:
    "A candidate must be 1-1024 characters and must appear verbatim in the cited observation.",
  power_tool_batch_exhausted:
    "This model turn has used its tool budget. Summarize what the observations established "
    + "and continue in the next batch.",
};

function rejected(code: string): AgentToolResult<Record<string, unknown>> {
  const remediation = POWER_TOOL_REMEDIATION[code];
  const text = remediation === undefined
    ? `The requested Power tool action was not accepted (${code}).`
    : `The requested Power tool action was not accepted (${code}). ${remediation}`;
  return toolResult(text, { accepted: false, code });
}

function safeFailure(error: unknown): string {
  return error instanceof PowerToolError ? error.code : "power_tool_control_failed";
}

/**
 * Keep both the beginning and the end of a command observation. CTF command
 * output often identifies a binary or endpoint at the head and exposes the
 * interesting result at the tail; the full bytes remain in sandboxd's CAS.
 */
export function truncatePowerToolText(
  text: string,
  maximumCharacters = POWER_TOOL_CONTEXT_MAX_CHARS,
): TruncatedPowerToolText {
  if (!Number.isSafeInteger(maximumCharacters) || maximumCharacters < 64) {
    powerToolError("power_tool_context_limit_invalid");
  }
  if (text.length <= maximumCharacters) {
    return { text, truncated: false };
  }
  const marker = "\n…[truncated; full output is in the immutable observation artifact]…\n";
  const preserved = maximumCharacters - marker.length;
  const headLength = Math.ceil(preserved / 2);
  const tailLength = Math.floor(preserved / 2);
  return {
    text: `${text.slice(0, headLength)}${marker}${text.slice(-tailLength)}`,
    truncated: true,
  };
}

function record(value: unknown, code: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    powerToolError(code);
  }
  return value as Record<string, unknown>;
}

function requiredText(value: unknown, code: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.includes("\0")) {
    powerToolError(code);
  }
  return value;
}

function boundedInteger(value: unknown, fallback: number, code: string, minimum: number, maximum: number): number {
  const candidate = value === undefined ? fallback : value;
  if (
    typeof candidate !== "number"
    || !Number.isSafeInteger(candidate)
    || candidate < minimum
    || candidate > maximum
  ) {
    powerToolError(code);
  }
  return candidate;
}

function command(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 128) {
    powerToolError("power_tool_command_invalid");
  }
  return value.map((entry) => requiredText(entry, "power_tool_command_invalid", 4_096));
}

function workingDirectory(value: unknown, fallback: "/challenge" | "/work" = "/work"): "/challenge" | "/work" {
  const candidate = value === undefined ? fallback : value;
  if (candidate !== "/challenge" && candidate !== "/work") {
    powerToolError("power_tool_working_directory_invalid");
  }
  return candidate;
}

/** Validate path again even if a malformed provider bypasses Pi's TypeBox schema. */
function workspacePath(value: unknown, fallback?: "/challenge" | "/work"): string {
  const candidate = value === undefined ? fallback : value;
  const raw = requiredText(candidate, "power_tool_workspace_path_invalid", 4_096);
  if (
    !raw.startsWith("/")
    || raw.includes("\\")
    || raw.split("/").includes("..")
    || !(
      raw === "/challenge"
      || raw === "/work"
      || raw.startsWith("/challenge/")
      || raw.startsWith("/work/")
    )
  ) {
    powerToolError("power_tool_workspace_path_invalid");
  }
  return raw === "/" ? raw : raw.replace(/\/+$/, "");
}

function ptyId(value: unknown): string {
  const candidate = requiredText(value, "power_tool_pty_id_invalid", 36);
  if (!CHANNEL_ID.pty.test(candidate)) {
    powerToolError("power_tool_pty_id_invalid");
  }
  return candidate;
}

function tubeId(value: unknown): string {
  const candidate = requiredText(value, "power_tool_tube_id_invalid", 37);
  if (!CHANNEL_ID.tube.test(candidate)) {
    powerToolError("power_tool_tube_id_invalid");
  }
  return candidate;
}

function host(value: unknown): string {
  const candidate = requiredText(value, "power_tool_tube_host_invalid", 253).toLowerCase().replace(/\.$/, "");
  if (!HOST.test(candidate)) {
    powerToolError("power_tool_tube_host_invalid");
  }
  return candidate;
}

function base64(value: unknown, code: string, maximum: number): string {
  const candidate = requiredText(value, code, maximum);
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(candidate)
  ) {
    powerToolError(code);
  }
  return candidate;
}

function validateScope(scope: PowerToolScope): void {
  if (!IDENTIFIER.test(scope.runId) || !IDENTIFIER.test(scope.sessionId) || !WORKSPACE_ID.test(scope.workspaceId)) {
    powerToolError("power_tool_scope_invalid");
  }
}

function validateObservation(value: unknown): PowerToolObservation {
  const candidate = record(value, "power_tool_observation_invalid");
  const artifact = record(candidate.artifact, "power_tool_observation_invalid");
  const id = requiredText(artifact.id, "power_tool_observation_invalid", 71);
  const sha256 = requiredText(artifact.sha256, "power_tool_observation_invalid", 64);
  const sizeBytes = artifact.sizeBytes;
  const stdout = typeof candidate.stdout === "string" && candidate.stdout.length <= 64 * 1024 && !candidate.stdout.includes("\0")
    ? candidate.stdout
    : powerToolError("power_tool_observation_invalid");
  const stderr = typeof candidate.stderr === "string" && candidate.stderr.length <= 64 * 1024 && !candidate.stderr.includes("\0")
    ? candidate.stderr
    : powerToolError("power_tool_observation_invalid");
  const exitCode = candidate.exitCode;
  if (
    !ARTIFACT_ID.test(id)
    || !SHA256.test(sha256)
    || typeof sizeBytes !== "number"
    || !Number.isSafeInteger(sizeBytes)
    || sizeBytes < 0
    || sizeBytes > 64 * 1024
    || (exitCode !== null && (typeof exitCode !== "number" || !Number.isSafeInteger(exitCode)))
    || typeof candidate.timedOut !== "boolean"
    || typeof candidate.outputTruncated !== "boolean"
  ) {
    powerToolError("power_tool_observation_invalid");
  }
  const interactiveId = candidate.interactiveId;
  const interactiveKind = candidate.interactiveKind;
  const rawCandidateReviewRequired = candidate.candidateReviewRequired;
  const rawCandidateCount = candidate.candidateCount;
  if (
    (interactiveId !== undefined && typeof interactiveId !== "string")
    || (interactiveKind !== undefined && interactiveKind !== "pty" && interactiveKind !== "gdb" && interactiveKind !== "tube")
    || ((interactiveId === undefined) !== (interactiveKind === undefined))
    || (rawCandidateReviewRequired !== undefined && typeof rawCandidateReviewRequired !== "boolean")
    || (rawCandidateCount !== undefined
      && (typeof rawCandidateCount !== "number"
        || !Number.isSafeInteger(rawCandidateCount)
        || rawCandidateCount < 0
        || rawCandidateCount > 1_024))
  ) {
    powerToolError("power_tool_observation_invalid");
  }
  const candidateReviewRequired = rawCandidateReviewRequired === undefined
    ? false
    : rawCandidateReviewRequired as boolean;
  const candidateCount = rawCandidateCount === undefined ? 0 : rawCandidateCount as number;
  if (candidateReviewRequired !== (candidateCount > 0)) {
    powerToolError("power_tool_observation_invalid");
  }
  return {
    artifact: { id, sha256, sizeBytes },
    stdout,
    stderr,
    exitCode: exitCode as number | null,
    timedOut: candidate.timedOut,
    outputTruncated: candidate.outputTruncated,
    candidateReviewRequired,
    candidateCount,
    ...(interactiveId === undefined ? {} : { interactiveId }),
    ...(interactiveKind === undefined ? {} : { interactiveKind }),
  };
}

function validateChannelReceipt(value: unknown): PowerChannelReceipt {
  const candidate = record(value, "power_tool_channel_receipt_invalid");
  if (candidate.state !== "open" && candidate.state !== "closed") {
    powerToolError("power_tool_channel_receipt_invalid");
  }
  return { state: candidate.state };
}

function validateFlagReceipt(value: unknown): PowerFlagSubmissionReceipt {
  const candidate = record(value, "power_tool_flag_receipt_invalid");
  if (typeof candidate.accepted !== "boolean") {
    powerToolError("power_tool_flag_receipt_invalid");
  }
  return { accepted: candidate.accepted };
}

/**
 * Allocate a local-only reference for an immutable observation.
 *
 * A model may see a CAS ID in tool text, but asking it to copy that long
 * value and a second SHA-256 field caused provenance drift in real Power
 * runs.  This handle is minted only after typed control returns an observed
 * artifact and is resolved again by the runner before flag-router is called.
 */
type ObservationRecorder = (observation: PowerToolObservation) => string;

function observationResult(
  action: PowerToolName,
  observationValue: unknown,
  recordObservation: ObservationRecorder,
): AgentToolResult<Record<string, unknown>> {
  const observation = validateObservation(observationValue);
  const handle = recordObservation(observation);
  const body = [
    `Observed ${action}.`,
    `Evidence handle: ${handle}. Use this exact handle with ctf_flag_submit.`,
    `Artifact: ${observation.artifact.id}`,
    `Exit code: ${observation.exitCode === null ? "not applicable" : observation.exitCode}`,
    `Timed out: ${observation.timedOut ? "yes" : "no"}`,
    "stdout:",
    observation.stdout,
    "stderr:",
    observation.stderr,
  ].join("\n");
  const bounded = truncatePowerToolText(body);
  return toolResult(bounded.text, {
    accepted: true,
    action,
    observation_handle: handle,
    artifact_id: observation.artifact.id,
    artifact_sha256: observation.artifact.sha256,
    exit_code: observation.exitCode,
    timed_out: observation.timedOut,
    sandbox_output_truncated: observation.outputTruncated,
    truncated: bounded.truncated || observation.outputTruncated,
    ...(observation.interactiveId === undefined
      ? {}
      : { interactive_id: observation.interactiveId, interactive_kind: observation.interactiveKind }),
  });
}

/** Render reviewed argv without ever evaluating it as a shell command. */
function displayArgv(argv: readonly string[]): string {
  return argv.map((argument) => (
    /^[A-Za-z0-9_./:=+,-]+$/.test(argument) ? argument : JSON.stringify(argument)
  )).join(" ");
}

function byteCount(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function observationTranscriptOutput(observation: PowerToolObservation): string {
  const parts: string[] = [];
  if (observation.stdout) {
    parts.push(observation.stdout);
  }
  if (observation.stderr) {
    parts.push(`stderr:\n${observation.stderr}`);
  }
  return parts.join("\n") || "(no stdout or stderr)";
}

/**
 * The browser feed is useful but not authoritative. A failed append must not
 * turn an already completed sandbox command into a retry or a tool failure.
 */
async function reportToolTranscript(
  scope: PowerToolScope,
  lease: TurnLease,
  transcript: PowerToolTranscript,
): Promise<void> {
  try {
    await scope.onToolTranscript?.(lease, transcript);
  } catch {
    // Deliberately best-effort: the immutable observation remains available.
  }
}

async function observedResult(
  scope: PowerToolScope,
  lease: TurnLease,
  action: PowerToolName,
  commandText: string,
  observationValue: unknown,
  recordObservation: ObservationRecorder,
): Promise<AgentToolResult<Record<string, unknown>>> {
  const observation = validateObservation(observationValue);
  await reportToolTranscript(scope, lease, {
    tool: action,
    command: commandText,
    output: observationTranscriptOutput(observation),
    exitCode: observation.exitCode,
    timedOut: observation.timedOut,
    outputTruncated: observation.outputTruncated,
    artifactId: observation.artifact.id,
  });
  if (observation.candidateReviewRequired) {
    // The API has already durably paused the run. Finish this native model
    // turn before it can try another tool or submit the syntactic match; the
    // explicit browser review is the only continuation decision.
    scope.toolBatch?.requestCandidateReview();
  }
  // Flag-shaped text may be a decoy, an encoded intermediate, or even text
  // emitted by the model's own command.  Automatically submitting it used to
  // let the first syntactic match end a race. The local UI automatically loads
  // every value from the immutable observation that opened the durable gate;
  // a human-reviewed candidate may reach the independent flag router.
  return observationResult(action, observation, recordObservation);
}

async function reportedReceipt(
  scope: PowerToolScope,
  lease: TurnLease,
  tool: PowerToolName,
  commandText: string,
  output: string,
): Promise<void> {
  await reportToolTranscript(scope, lease, {
    tool,
    command: commandText,
    output,
    exitCode: null,
    timedOut: false,
    outputTruncated: false,
  });
}

function requireOwnedChannel(
  channels: ReadonlyMap<string, PowerInteractiveKind>,
  identifier: string,
  expected: PowerInteractiveKind,
): void {
  if (channels.get(identifier) !== expected) {
    powerToolError("power_tool_interactive_channel_not_owned");
  }
}

async function rememberChannel(
  scope: PowerToolScope,
  lease: TurnLease,
  channels: Map<string, PowerInteractiveKind>,
  action: "ctf_pty_start" | "ctf_gdb_start" | "ctf_tube_connect",
  commandText: string,
  observationValue: unknown,
  expected: PowerInteractiveKind,
  recordObservation: ObservationRecorder,
): Promise<AgentToolResult<Record<string, unknown>>> {
  const observation = validateObservation(observationValue);
  const identifier = observation.interactiveId;
  if (
    identifier === undefined
    || observation.interactiveKind !== expected
    || (expected === "tube" ? !CHANNEL_ID.tube.test(identifier) : !CHANNEL_ID.pty.test(identifier))
  ) {
    powerToolError("power_tool_interactive_observation_invalid");
  }
  channels.set(identifier, expected);
  return observedResult(
    scope,
    lease,
    action,
    commandText,
    observation,
    recordObservation,
  );
}

type PowerToolAction = (lease: TurnLease) => Promise<AgentToolResult<Record<string, unknown>>>;

async function withLease(
  scope: PowerToolScope,
  signal: AbortSignal | undefined,
  action: PowerToolAction,
): Promise<AgentToolResult<Record<string, unknown>>>;
async function withLease(
  scope: PowerToolScope,
  signal: AbortSignal | undefined,
  options: { readonly countAgainstBatch: false },
  action: PowerToolAction,
): Promise<AgentToolResult<Record<string, unknown>>>;
async function withLease(
  scope: PowerToolScope,
  signal: AbortSignal | undefined,
  actionOrOptions: PowerToolAction | { readonly countAgainstBatch: false },
  optionalAction?: PowerToolAction,
): Promise<AgentToolResult<Record<string, unknown>>> {
  if (signal?.aborted) {
    return rejected("tool_cancelled");
  }
  try {
    const action = typeof actionOrOptions === "function" ? actionOrOptions : optionalAction;
    const countAgainstBatch = typeof actionOrOptions === "function"
      ? true
      : actionOrOptions.countAgainstBatch;
    if (action === undefined) {
      return rejected("power_tool_action_missing");
    }
    const lease = scope.authority.require(scope.sessionId);
    try {
      await scope.beforeAction?.(lease);
    } catch {
      // The tool path remains authoritative when the optional display feed is
      // temporarily unavailable. Do not turn a completed sandbox action into
      // an accidental second attempt just to refresh the UI.
    }
    if (countAgainstBatch && scope.toolBatch?.consume() === false) {
      return rejected("power_tool_batch_exhausted");
    }
    return await action(lease);
  } catch (error) {
    if (
      error instanceof ControlProtocolError
      && error.code === "control_power_candidate_review_required"
    ) {
      // A sibling reached the durable gate first. This tool has not run, and
      // no raw candidate crossed this error path; stop this Pi batch too.
      scope.toolBatch?.requestCandidateReview();
      return rejected("power_candidate_review_required");
    }
    return rejected(safeFailure(error));
  }
}

const commandParameters = Type.Object(
  {
    command: Type.Array(Type.String({ minLength: 1, maxLength: 4_096 }), { minItems: 1, maxItems: 128 }),
    timeout_seconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 120 })),
    working_directory: Type.Optional(Type.Union([Type.Literal("/challenge"), Type.Literal("/work")])),
  },
  { additionalProperties: false },
);

const pathParameters = Type.Object(
  { path: Type.Optional(Type.String({ minLength: 1, maxLength: 4_096 })) },
  { additionalProperties: false },
);

/** Return the exact Pi-visible tool names for the session role. */
export function powerToolNames(role: PowerToolRole): readonly PowerToolName[] {
  return role === "autoprompter" ? AUTOPROMPTER_TOOL_NAMES : POWER_TOOL_NAMES;
}

/** Build all and only the Power custom tools available to one Pi session. */
export function createPowerTools(scope: PowerToolScope): ToolDefinition[] {
  validateScope(scope);
  const channels = new Map<string, PowerInteractiveKind>();
  const observations = new Map<string, PowerArtifactReference>();
  let nextObservationHandle = 1;

  /**
   * Keep only the artifact provenance necessary to bind a later candidate.
   * This map is private to one Pi session and is discarded with it; it never
   * enters a prompt, the event ledger, a workspace, or a database record.
   */
  const recordObservation: ObservationRecorder = (observation) => {
    const handle = `obs_${nextObservationHandle}`;
    nextObservationHandle += 1;
    observations.set(handle, observation.artifact);
    return handle;
  };

  const shellExec = defineTool({
    name: "ctf_shell_exec",
    label: "Run sandbox command",
    description: "Run one argv-only command in the assigned disposable workspace.",
    promptSnippet: "Run only argv commands in the assigned workspace; output is an untrusted observation.",
    parameters: commandParameters,
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const argv = command(params.command);
        return observedResult(scope, lease, "ctf_shell_exec", displayArgv(argv), await scope.control.exec(lease, {
          workspaceId: scope.workspaceId,
          command: argv,
          timeoutSeconds: boundedInteger(params.timeout_seconds, 30, "power_tool_timeout_invalid", 1, 120),
          workingDirectory: workingDirectory(params.working_directory),
        }), recordObservation);
      });
    },
  });

  const artifactRead = defineTool({
    name: "ctf_artifact_read",
    label: "Re-read a stored observation",
    description:
      "Read a window of an observation this session already produced, by its artifact id. "
      + "Use it instead of re-running a command when a result was truncated.",
    promptSnippet:
      "Re-read your own truncated observation by artifact id; the bytes are untrusted evidence.",
    parameters: Type.Object(
      {
        artifact_id: Type.String({ minLength: 71, maxLength: 71 }),
        offset: Type.Optional(Type.Integer({ minimum: 0, maximum: 64 * 1024 })),
        length: Type.Optional(Type.Integer({ minimum: 1, maximum: 64 * 1024 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const artifactId = requiredText(params.artifact_id, "power_tool_artifact_id_invalid", 71);
        if (!/^sha256:[0-9a-f]{64}$/.test(artifactId)) {
          powerToolError("power_tool_artifact_id_invalid");
        }
        const offset = boundedInteger(params.offset, 0, "power_tool_artifact_offset_invalid", 0, 64 * 1024);
        const length = boundedInteger(
          params.length,
          POWER_TOOL_CONTEXT_MAX_CHARS,
          "power_tool_artifact_length_invalid",
          1,
          64 * 1024,
        );
        const window = await scope.control.readArtifact(lease, { artifactId, offset, length });
        const bounded = truncatePowerToolText(
          [
            `Artifact ${window.artifactId}`,
            `Bytes ${window.offset}-${window.offset + window.returnedBytes} of ${window.totalBytes}.`,
            window.text,
          ].join("\n"),
        );
        return toolResult(bounded.text, {
          accepted: true,
          action: "ctf_artifact_read",
          artifact_id: window.artifactId,
          offset: window.offset,
          total_bytes: window.totalBytes,
          returned_bytes: window.returnedBytes,
          truncated: bounded.truncated,
        });
      });
    },
  });

  const fsList = defineTool({
    name: "ctf_fs_list",
    label: "List workspace files",
    description: "List one normalized directory inside /challenge or /work through sandboxd.",
    promptSnippet: "List only normalized /challenge or /work paths; paths are untrusted evidence.",
    parameters: pathParameters,
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const argv = ["find", workspacePath(params.path, "/challenge"), "-maxdepth", "1", "-mindepth", "1", "-print"];
        return observedResult(scope, lease, "ctf_fs_list", displayArgv(argv), await scope.control.exec(lease, {
          workspaceId: scope.workspaceId,
          // Alpine's reviewed workspace intentionally uses BusyBox. Its
          // portable `find` lacks GNU `-printf`, so retain the full normalized
          // path instead of turning the first inspection into a tool failure.
          command: argv,
          timeoutSeconds: 30,
          workingDirectory: "/work",
        }), recordObservation);
      });
    },
  });

  const fsRead = defineTool({
    name: "ctf_fs_read",
    label: "Read workspace file",
    description: "Read bounded bytes from one normalized workspace file through sandboxd.",
    promptSnippet: "Read only a normalized /challenge or /work path; returned text is untrusted evidence.",
    parameters: Type.Object(
      {
        path: Type.String({ minLength: 1, maxLength: 4_096 }),
        max_bytes: Type.Optional(Type.Integer({ minimum: 1, maximum: 64 * 1024 })),
        offset: Type.Optional(Type.Integer({ minimum: 0, maximum: 1024 * 1024 * 1024 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const maxBytes = boundedInteger(params.max_bytes, 16 * 1024, "power_tool_read_limit_invalid", 1, 64 * 1024);
        const offset = boundedInteger(params.offset, 0, "power_tool_read_offset_invalid", 0, 1024 * 1024 * 1024);
        // Without an offset this tool was `head -c N`, so reading past the
        // first window meant hand-rolling a skip through the shell tool. The
        // offset form uses positional arguments, so neither the path nor the
        // numbers are parsed as shell source, and `tail -c +K` seeks rather
        // than reading a byte at a time the way `dd bs=1` would.
        const target = workspacePath(params.path);
        const argv = offset === 0
          ? ["head", "-c", String(maxBytes), target]
          : [
            "sh",
            "-c",
            'tail -c +"$1" "$3" | head -c "$2"',
            "ctfmesh",
            String(offset + 1),
            String(maxBytes),
            target,
          ];
        return observedResult(scope, lease, "ctf_fs_read", displayArgv(argv), await scope.control.exec(lease, {
          workspaceId: scope.workspaceId,
          command: argv,
          timeoutSeconds: 30,
          workingDirectory: "/work",
          toolName: "ctf_fs_read",
        }), recordObservation);
      });
    },
  });

  const fsWrite = defineTool({
    name: "ctf_fs_write",
    label: "Write workspace file",
    description:
      "Write bounded content to a normalized /work or /challenge path in the assigned workspace. "
      + "The file is read back, so the observation artifact holds exactly the bytes that landed.",
    promptSnippet:
      "Write only a normalized workspace path. Content is data, never Pi-host shell source. "
      + "The observation returns the file as written, which is how a proof of concept is retained.",
    parameters: Type.Object(
      {
        path: Type.String({ minLength: 1, maxLength: 4_096 }),
        content: Type.String({ maxLength: 64 * 1024 }),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const content = typeof params.content === "string" && params.content.length <= 64 * 1024 && !params.content.includes("\0")
          ? params.content
          : powerToolError("power_tool_write_content_invalid");
        // sandboxd currently exposes argv-only exec. This fixed command uses
        // positional arguments, so model content is not parsed as shell
        // source. It executes only inside the disposable workspace, never on
        // the Pi runner host.
        const path = workspacePath(params.path);
        // Read the file back in the same command. `/work` is a tmpfs that dies
        // with its workspace and no route exports a file, so a write whose
        // observation held only an empty stdout left the bytes unrecoverable:
        // a racer could build and verify a working proof of concept and still
        // leave the operator nothing to reproduce it with. Reading back also
        // makes the observation evidence of what actually landed rather than
        // an echo of what was requested.
        const script = 'printf %s "$1" > "$2" && cat "$2"';
        const argv = ["sh", "-c", script, "ctfmesh", content, path];
        // Show the genuine write mechanism but replace data with its byte
        // count: a generated payload can itself contain a flag or credential.
        const display = displayArgv(["sh", "-c", script, "ctfmesh", `[${byteCount(content)} byte write payload]`, path]);
        return observedResult(scope, lease, "ctf_fs_write", display, await scope.control.exec(lease, {
            workspaceId: scope.workspaceId,
            command: argv,
            timeoutSeconds: 30,
            workingDirectory: "/work",
          }), recordObservation);
      });
    },
  });

  const ptyStart = defineTool({
    name: "ctf_pty_start",
    label: "Start interactive terminal",
    description: "Start one bounded interactive command in the assigned workspace.",
    promptSnippet: "Start an argv-only terminal inside the assigned workspace; keep its returned ID private to this session.",
    parameters: commandParameters,
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const argv = command(params.command);
        const observation = await scope.control.ptyStart(lease, {
          workspaceId: scope.workspaceId,
          command: argv,
          timeoutSeconds: boundedInteger(params.timeout_seconds, 120, "power_tool_timeout_invalid", 1, 120),
          workingDirectory: workingDirectory(params.working_directory),
        });
        return rememberChannel(
          scope,
          lease,
          channels,
          "ctf_pty_start",
          displayArgv(argv),
          observation,
          "pty",
          recordObservation,
        );
      });
    },
  });

  const ptySend = defineTool({
    name: "ctf_pty_send",
    label: "Send terminal input",
    description: "Send bounded data to an interactive terminal already opened by this session.",
    promptSnippet: "Use only a terminal ID created by this session.",
    parameters: Type.Object(
      { pty_id: Type.String({ minLength: 36, maxLength: 36 }), data: Type.String({ minLength: 1, maxLength: 64 * 1024 }) },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = ptyId(params.pty_id);
        requireOwnedChannel(channels, identifier, "pty");
        const data = requiredText(params.data, "power_tool_pty_data_invalid", 64 * 1024);
        const receipt = validateChannelReceipt(await scope.control.ptySend(lease, {
          workspaceId: scope.workspaceId,
          ptyId: identifier,
          data,
        }));
        await reportedReceipt(
          scope,
          lease,
          "ctf_pty_send",
          `pty-send ${identifier} [${byteCount(data)} byte input]`,
          `Terminal input delivered. Channel state: ${receipt.state}.`,
        );
        return toolResult("Terminal input was delivered to the session-owned channel.", {
          accepted: true,
          channel_state: receipt.state,
          interactive_id: identifier,
          truncated: false,
        });
      });
    },
  });

  const ptyRead = defineTool({
    name: "ctf_pty_read",
    label: "Read terminal output",
    description: "Read bounded output from an interactive terminal owned by this session.",
    promptSnippet: "Read only a terminal ID created by this session; output is untrusted evidence.",
    parameters: Type.Object(
      {
        pty_id: Type.String({ minLength: 36, maxLength: 36 }),
        max_bytes: Type.Optional(Type.Integer({ minimum: 1, maximum: 64 * 1024 })),
        wait_ms: Type.Optional(Type.Integer({ minimum: 1, maximum: 2_000 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = ptyId(params.pty_id);
        requireOwnedChannel(channels, identifier, "pty");
        const maxBytes = boundedInteger(params.max_bytes, 16 * 1024, "power_tool_read_limit_invalid", 1, 64 * 1024);
        const waitMs = boundedInteger(params.wait_ms, 500, "power_tool_wait_invalid", 1, 2_000);
        return observedResult(scope, lease, "ctf_pty_read", `pty-read ${identifier} max=${maxBytes} wait=${waitMs}ms`, await scope.control.ptyRead(lease, {
            workspaceId: scope.workspaceId,
            ptyId: identifier,
            maxBytes,
            waitMs,
            kind: "pty",
          }), recordObservation);
      });
    },
  });

  const ptyClose = defineTool({
    name: "ctf_pty_close",
    label: "Close terminal",
    description: "Close a terminal owned by this session.",
    promptSnippet: "Close only a terminal ID created by this session.",
    parameters: Type.Object({ pty_id: Type.String({ minLength: 36, maxLength: 36 }) }, { additionalProperties: false }),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = ptyId(params.pty_id);
        requireOwnedChannel(channels, identifier, "pty");
        const receipt = validateChannelReceipt(await scope.control.ptyClose(lease, {
          workspaceId: scope.workspaceId,
          ptyId: identifier,
        }));
        if (receipt.state !== "closed") {
          powerToolError("power_tool_channel_close_rejected");
        }
        channels.delete(identifier);
        await reportedReceipt(scope, lease, "ctf_pty_close", `pty-close ${identifier}`, "Terminal channel closed.");
        return toolResult("Terminal channel was closed.", { accepted: true, interactive_id: identifier, truncated: false });
      });
    },
  });

  const gdbStart = defineTool({
    name: "ctf_gdb_start",
    label: "Start GDB",
    description: "Start GDB without user init files for one /challenge target.",
    promptSnippet: "Start GDB only for a normalized /challenge file; output is untrusted evidence.",
    parameters: Type.Object(
      {
        path: Type.String({ minLength: 1, maxLength: 4_096 }),
        timeout_seconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 120 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const path = workspacePath(params.path);
        if (path !== "/challenge" && !path.startsWith("/challenge/")) {
          powerToolError("power_tool_gdb_path_invalid");
        }
        const argv = ["gdb", "--quiet", "--nx", path];
        const observation = await scope.control.ptyStart(lease, {
            workspaceId: scope.workspaceId,
            command: argv,
            timeoutSeconds: boundedInteger(params.timeout_seconds, 120, "power_tool_timeout_invalid", 1, 120),
            workingDirectory: "/challenge",
          });
        return rememberChannel(
          scope,
          lease,
          channels,
          "ctf_gdb_start",
          displayArgv(argv),
          observation,
          "gdb",
          recordObservation,
        );
      });
    },
  });

  const gdbCommand = defineTool({
    name: "ctf_gdb_cmd",
    label: "Run GDB command",
    description: "Send one bounded command to a session-owned GDB terminal, then return its observation.",
    promptSnippet: "Use only a GDB ID created by this session; output is untrusted evidence.",
    parameters: Type.Object(
      {
        gdb_id: Type.String({ minLength: 36, maxLength: 36 }),
        command: Type.String({ minLength: 1, maxLength: 8 * 1024 }),
        wait_ms: Type.Optional(Type.Integer({ minimum: 1, maximum: 2_000 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = ptyId(params.gdb_id);
        requireOwnedChannel(channels, identifier, "gdb");
        const commandText = requiredText(params.command, "power_tool_gdb_command_invalid", 8 * 1024);
        await scope.control.ptySend(lease, {
          workspaceId: scope.workspaceId,
          ptyId: identifier,
          data: `${commandText}\n`,
        });
        const waitMs = boundedInteger(params.wait_ms, 1_000, "power_tool_wait_invalid", 1, 2_000);
        return observedResult(scope, lease, "ctf_gdb_cmd", `gdb ${identifier}: ${commandText}`, await scope.control.ptyRead(lease, {
            workspaceId: scope.workspaceId,
            ptyId: identifier,
            maxBytes: 16 * 1024,
            waitMs,
            kind: "gdb",
          }), recordObservation);
      });
    },
  });

  const gdbRead = defineTool({
    name: "ctf_gdb_read",
    label: "Read more GDB output",
    description:
      "Drain further output from a session-owned GDB terminal without sending another command.",
    promptSnippet:
      "Use after a GDB command that ran longer than its read window; output is untrusted evidence.",
    parameters: Type.Object(
      {
        gdb_id: Type.String({ minLength: 36, maxLength: 36 }),
        max_bytes: Type.Optional(Type.Integer({ minimum: 1, maximum: 64 * 1024 })),
        wait_ms: Type.Optional(Type.Integer({ minimum: 1, maximum: 2_000 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        // `ctf_gdb_cmd` sends and reads exactly once, so a `run`, `continue`
        // or large `disassemble` that outlives its window previously lost the
        // rest of its output: `ctf_pty_read` rejects a gdb channel, and the
        // only way to drain one was to send another gdb command, which
        // changes the debuggee's state.
        const identifier = ptyId(params.gdb_id);
        requireOwnedChannel(channels, identifier, "gdb");
        const maxBytes = boundedInteger(params.max_bytes, 16 * 1024, "power_tool_read_limit_invalid", 1, 64 * 1024);
        const waitMs = boundedInteger(params.wait_ms, 1_000, "power_tool_wait_invalid", 1, 2_000);
        return observedResult(scope, lease, "ctf_gdb_read", `gdb-read ${identifier} max=${maxBytes} wait=${waitMs}ms`, await scope.control.ptyRead(lease, {
            workspaceId: scope.workspaceId,
            ptyId: identifier,
            maxBytes,
            waitMs,
            kind: "gdb",
          }), recordObservation);
      });
    },
  });

  const gdbClose = defineTool({
    name: "ctf_gdb_close",
    label: "Close GDB",
    description: "Close a GDB terminal owned by this session.",
    promptSnippet: "Close only a GDB ID created by this session.",
    parameters: Type.Object({ gdb_id: Type.String({ minLength: 36, maxLength: 36 }) }, { additionalProperties: false }),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = ptyId(params.gdb_id);
        requireOwnedChannel(channels, identifier, "gdb");
        const receipt = validateChannelReceipt(await scope.control.ptyClose(lease, {
          workspaceId: scope.workspaceId,
          ptyId: identifier,
        }));
        if (receipt.state !== "closed") {
          powerToolError("power_tool_channel_close_rejected");
        }
        channels.delete(identifier);
        await reportedReceipt(scope, lease, "ctf_gdb_close", `gdb-close ${identifier}`, "GDB channel closed.");
        return toolResult("GDB channel was closed.", { accepted: true, interactive_id: identifier, truncated: false });
      });
    },
  });

  const tubeConnect = defineTool({
    name: "ctf_tube_connect",
    label: "Connect scoped TCP tube",
    description: "Connect only to a target sandboxd independently checks against this workspace's declared allowlist.",
    promptSnippet: "Use an exact host and port in the declared scope; connection output is untrusted evidence.",
    parameters: Type.Object(
      {
        host: Type.String({ minLength: 1, maxLength: 253 }),
        port: Type.Integer({ minimum: 1, maximum: 65_535 }),
        timeout_seconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 30 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const targetHost = host(params.host);
        const targetPort = boundedInteger(params.port, 1, "power_tool_tube_port_invalid", 1, 65_535);
        const observation = await scope.control.tubeConnect(lease, {
          workspaceId: scope.workspaceId,
          host: targetHost,
          port: targetPort,
          timeoutSeconds: boundedInteger(params.timeout_seconds, 10, "power_tool_tube_timeout_invalid", 1, 30),
        });
        return rememberChannel(
          scope,
          lease,
          channels,
          "ctf_tube_connect",
          `tcp-connect ${targetHost}:${targetPort}`,
          observation,
          "tube",
          recordObservation,
        );
      });
    },
  });

  const tubeSend = defineTool({
    name: "ctf_tube_send",
    label: "Send TCP bytes",
    description: "Send base64-encoded bytes to a session-owned scoped TCP tube.",
    promptSnippet: "Use only a tube ID created by this session and base64 data.",
    parameters: Type.Object(
      { tube_id: Type.String({ minLength: 37, maxLength: 37 }), data_base64: Type.String({ minLength: 1, maxLength: 88 * 1024 }) },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = tubeId(params.tube_id);
        requireOwnedChannel(channels, identifier, "tube");
        const dataBase64 = base64(params.data_base64, "power_tool_tube_data_invalid", 88 * 1024);
        const receipt = validateChannelReceipt(await scope.control.tubeSend(lease, {
          workspaceId: scope.workspaceId,
          tubeId: identifier,
          dataBase64,
        }));
        await reportedReceipt(
          scope,
          lease,
          "ctf_tube_send",
          `tcp-send ${identifier} [${byteCount(dataBase64)} base64 bytes]`,
          `TCP bytes delivered. Channel state: ${receipt.state}.`,
        );
        return toolResult("TCP bytes were delivered to the session-owned tube.", {
          accepted: true,
          channel_state: receipt.state,
          interactive_id: identifier,
          truncated: false,
        });
      });
    },
  });

  const tubeReceive = defineTool({
    name: "ctf_tube_recv",
    label: "Receive TCP bytes",
    description: "Receive bounded bytes from a session-owned scoped TCP tube.",
    promptSnippet: "Use only a tube ID created by this session; received bytes are untrusted evidence.",
    parameters: Type.Object(
      {
        tube_id: Type.String({ minLength: 37, maxLength: 37 }),
        delimiter_base64: Type.String({ minLength: 1, maxLength: 4 * 1024 }),
        max_bytes: Type.Optional(Type.Integer({ minimum: 1, maximum: 64 * 1024 })),
        timeout_seconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 30 })),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = tubeId(params.tube_id);
        requireOwnedChannel(channels, identifier, "tube");
        const delimiterBase64 = base64(params.delimiter_base64, "power_tool_tube_delimiter_invalid", 4 * 1024);
        const maxBytes = boundedInteger(params.max_bytes, 16 * 1024, "power_tool_read_limit_invalid", 1, 64 * 1024);
        const timeoutSeconds = boundedInteger(params.timeout_seconds, 10, "power_tool_tube_timeout_invalid", 1, 30);
        return observedResult(scope, lease, "ctf_tube_recv", `tcp-recv ${identifier} delimiter=[${byteCount(delimiterBase64)} base64 bytes] max=${maxBytes} timeout=${timeoutSeconds}s`, await scope.control.tubeReceive(lease, {
            workspaceId: scope.workspaceId,
            tubeId: identifier,
            delimiterBase64,
            maxBytes,
            timeoutSeconds,
          }), recordObservation);
      });
    },
  });

  const tubeClose = defineTool({
    name: "ctf_tube_close",
    label: "Close TCP tube",
    description: "Close a scoped TCP tube owned by this session.",
    promptSnippet: "Close only a tube ID created by this session.",
    parameters: Type.Object({ tube_id: Type.String({ minLength: 37, maxLength: 37 }) }, { additionalProperties: false }),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, async (lease) => {
        const identifier = tubeId(params.tube_id);
        requireOwnedChannel(channels, identifier, "tube");
        const receipt = validateChannelReceipt(await scope.control.tubeClose(lease, {
          workspaceId: scope.workspaceId,
          tubeId: identifier,
        }));
        if (receipt.state !== "closed") {
          powerToolError("power_tool_channel_close_rejected");
        }
        channels.delete(identifier);
        await reportedReceipt(scope, lease, "ctf_tube_close", `tcp-close ${identifier}`, "TCP tube closed.");
        return toolResult("TCP tube was closed.", { accepted: true, interactive_id: identifier, truncated: false });
      });
    },
  });

  const flagSubmit = defineTool({
    name: "ctf_flag_submit",
    label: "Hold flag candidate for review",
    description: "Keep a candidate associated with its evidence handle; the local operator alone can send a reviewed value to the independent flag-router.",
    promptSnippet: "Do not submit flags. A configured-format candidate pauses the run for local operator review.",
    parameters: Type.Object(
      {
        candidate: Type.String({ minLength: 1, maxLength: 1_024 }),
        observation_handle: Type.String({ minLength: 5, maxLength: 10, pattern: "^obs_[1-9][0-9]{0,5}$" }),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      return withLease(scope, signal, { countAgainstBatch: false }, async (lease) => {
        // Validate the opaque value without retaining or forwarding it. A
        // Power run can complete only when the local operator confirms a
        // candidate through the separate browser review flow.
        requiredText(params.candidate, "power_tool_flag_candidate_invalid", 1_024);
        const handle = requiredText(params.observation_handle, "power_tool_flag_observation_handle_invalid", 10);
        if (!OBSERVATION_HANDLE.test(handle)) {
          powerToolError("power_tool_flag_observation_handle_invalid");
        }
        const observation = observations.get(handle);
        if (observation === undefined) {
          return toolResult(
            "Flag candidate was not sent. Read the candidate source again and use its exact Evidence handle.",
            { accepted: false, code: "power_tool_flag_observation_handle_unknown", truncated: false },
          );
        }
        // This deliberately does not contact flag-router. A model-generated
        // submission would bypass the candidate gate, so it is held until the
        // browser presents the complete runtime review queue to the operator.
        await reportedReceipt(
          scope,
          lease,
          "ctf_flag_submit",
          `flag-candidate-held evidence=${handle}`,
          "Candidate held for local operator review.",
        );
        return toolResult(
          "Candidate held. Stop tool use and wait for the local operator to review runtime candidates.",
          { accepted: false, code: "power_candidate_operator_review_required", truncated: false },
        );
      });
    },
  });

  const tools = new Map<PowerToolName, ToolDefinition>([
    ["ctf_artifact_read", artifactRead],
    ["ctf_shell_exec", shellExec],
    ["ctf_fs_list", fsList],
    ["ctf_fs_read", fsRead],
    ["ctf_fs_write", fsWrite],
    ["ctf_pty_start", ptyStart],
    ["ctf_pty_send", ptySend],
    ["ctf_pty_read", ptyRead],
    ["ctf_pty_close", ptyClose],
    ["ctf_gdb_start", gdbStart],
    ["ctf_gdb_cmd", gdbCommand],
    ["ctf_gdb_read", gdbRead],
    ["ctf_gdb_close", gdbClose],
    ["ctf_tube_connect", tubeConnect],
    ["ctf_tube_send", tubeSend],
    ["ctf_tube_recv", tubeReceive],
    ["ctf_tube_close", tubeClose],
    ["ctf_flag_submit", flagSubmit],
  ]);
  return powerToolNames(scope.role).map((name) => tools.get(name) as ToolDefinition);
}
