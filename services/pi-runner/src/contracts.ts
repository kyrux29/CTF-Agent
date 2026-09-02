/**
 * Strict, version-local contracts for the Pi Runner control protocol.
 *
 * Python remains the canonical authority for these payloads.  The runner
 * validates every response again before it can influence an SDK session, so a
 * compromised or accidentally incompatible control service cannot turn into
 * unrestricted local behaviour.
 */

export const CONTROL_PROTOCOL_VERSION = 1;

export const AGENT_JOB_KINDS = [
  "start_session",
  "run_turn",
  "steer",
  "abort",
  "dispose",
  "power_session_start",
  "power_steer",
  "power_abort",
] as const;

export type AgentJobKind = (typeof AGENT_JOB_KINDS)[number];

export const AGENT_ROLES = [
  "master",
  "source_auditor",
  "http_tester",
  "exploit_builder",
  "falsifier",
] as const;

export type AgentRole = (typeof AGENT_ROLES)[number];

export const AGENT_SESSION_STATES = [
  "starting",
  "ready",
  "running",
  "aborting",
  "disposed",
  "failed",
] as const;

export type AgentSessionState = (typeof AGENT_SESSION_STATES)[number];

export const AGENT_EVENT_TYPES = [
  "agent.session.started",
  "agent.session.ready",
  "agent.turn.started",
  "agent.turn.completed",
  "agent.tool.started",
  "agent.tool.completed",
  "agent.session.retry",
  "agent.session.compacted",
  "agent.error",
] as const;

export type AgentEventType = (typeof AGENT_EVENT_TYPES)[number];

export interface AgentJob {
  readonly id: string;
  readonly run_id: string;
  readonly kind: AgentJobKind;
  readonly payload_ref: string | null;
  readonly payload_digest: string | null;
  readonly state: "queued" | "leased" | "completed" | "failed";
  readonly lease_owner: string | null;
  readonly lease_version: number;
  readonly lease_expires_at: string | null;
  readonly attempts: number;
  readonly deadline_at: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface ContextEvidenceRef {
  readonly observation_id: string;
  readonly artifact_id: string;
  readonly digest: string;
}

/** The target-free subset of a sealed ContextManifest the runner is allowed to see. */
export interface ContextManifest {
  readonly schema: "ctfmesh.context-manifest";
  readonly schema_version: 1;
  readonly id: string;
  readonly run_id: string;
  readonly task_id: string;
  readonly challenge_digest: string;
  readonly role: AgentRole;
  readonly objective: string;
  readonly allowed_tool_ids: readonly string[];
  readonly evidence_refs: readonly ContextEvidenceRef[];
  readonly hypothesis_refs: readonly string[];
  readonly active_hint_refs: readonly string[];
  readonly attempt_fingerprints: readonly string[];
  readonly budget_slice: {
    readonly tool_calls: number;
    readonly input_tokens: number;
    readonly output_tokens: number;
  };
  readonly created_at: string;
  readonly expires_at: string;
  readonly digest: string;
}

export interface WorkerTask {
  readonly id: string;
  readonly run_id: string;
  readonly branch_id: string;
  readonly role: AgentRole;
  readonly objective: string;
  readonly required_evidence: readonly string[];
  readonly context_manifest_id: string;
  readonly state: "queued" | "leased" | "completed" | "failed" | "cancelled";
  readonly lease_owner: string | null;
  readonly lease_version: number;
  readonly lease_expires_at: string | null;
  readonly attempts: number;
  readonly deadline_at: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface AgentSession {
  readonly id: string;
  readonly run_id: string;
  readonly start_job_id: string;
  readonly task_id: string;
  readonly context_manifest_id: string;
  readonly role: AgentRole;
  readonly state: AgentSessionState;
  readonly session_store_key: string;
  readonly runner_id: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface AgentSteer {
  readonly id: string;
  readonly run_id: string;
  readonly session_id: string;
  /** Sanitized operator text, returned only across the authenticated runner boundary. */
  readonly message: string;
  readonly message_digest: string;
  readonly state: "queued" | "applied";
  readonly created_at: string;
  readonly applied_at: string | null;
}

export interface AgentBridgeEvent {
  readonly sequence: number;
  readonly type: AgentEventType;
  readonly session_id: string;
  readonly occurred_at: string;
  readonly message_digest?: string;
  readonly preview?: string;
  readonly tool_name?: string;
  readonly input_digest?: string;
  readonly output_digest?: string;
  readonly input_tokens?: number;
  readonly output_tokens?: number;
  readonly cost_usd?: number;
  readonly retry_attempt?: number;
  readonly error_code?: string;
  readonly prompt_contract_version?: number;
  readonly prompt_contract_digest?: string;
}

export interface FindingSubmission {
  readonly session_id: string;
  readonly tool_call_id: string;
  readonly statement: string;
  readonly evidence_ids: readonly string[];
  readonly confidence: number;
  /** Labels an unverified observation only; it never promotes a fact/solve. */
  readonly disposition: "supports" | "contradicts" | "inconclusive";
}

export interface TaskDelegationRequest {
  readonly tool_call_id: string;
  readonly role: Exclude<AgentRole, "master">;
  readonly technique_id: "general.review" | "web.path_traversal" | "web.authz_boundary" | "web.sqli_basic";
  readonly objective: string;
  readonly evidence_ids: readonly string[];
}

/**
 * Pi submits this digest-free draft; the Python kernel canonicalizes and
 * content-addresses it before it is ever eligible for verifier replay.
 * Deliberately absent: URL, host, shell, script, file, body and redirect.
 */
export type ExploitPlanHeaders = Readonly<
  Partial<Record<"accept" | "content-type" | "x-ctfmesh-user", string>>
>;

export interface ExploitPlanDraftV1 {
  readonly schema_version: "ctfmesh.exploit-plan.v1";
  readonly challenge_digest: string;
  readonly technique_id: "web.path_traversal" | "web.authz_boundary" | "web.sqli_basic";
  readonly variables?: Readonly<Record<string, string>>;
  readonly steps: readonly {
    readonly op: "http.request";
    readonly method?: "GET";
    readonly path: string;
    readonly query?: Readonly<Record<string, string>>;
    readonly headers?: ExploitPlanHeaders;
    readonly capture?: Readonly<{ flag: string }>;
  }[];
  readonly assertions: readonly ["capture.flag exists"];
  readonly evidence_refs: readonly string[];
}

export interface ExploitCandidateSubmission {
  readonly session_id: string;
  readonly tool_call_id: string;
  readonly idempotency_key: string;
  readonly plan: ExploitPlanDraftV1;
}

/** Closed M3 operations accepted by the generic Pi gateway tool. */
export const GATEWAY_TOOL_NAMES = [
  "source.list",
  "source.read",
  "source.search",
  "source.manifest",
  "artifacts.inspect",
  "transform.apply",
  "http.request",
] as const;

export type GatewayToolName = (typeof GATEWAY_TOOL_NAMES)[number];

/**
 * Pi never chooses a slot, filesystem root, or target URL.  Its custom tool
 * supplies this closed-world shape and the control client binds the call ID
 * as the durable idempotency key before POSTing to the static API route.
 */
export interface GatewayToolCall {
  readonly schema_version: 1;
  readonly tool_call_id: string;
  readonly idempotency_key: string;
  readonly tool_name: GatewayToolName;
  readonly tool_version: "1.0.0";
  readonly arguments: Readonly<Record<string, unknown>>;
}

export interface GatewayToolRequest {
  readonly session_id: string;
  readonly call: GatewayToolCall;
}

export interface ToolObservationArtifact {
  readonly artifact_id: string;
  readonly digest: string;
  readonly size_bytes: number;
  readonly summary: string;
}

export interface AcceptedToolGatewayResponse {
  readonly schema_version: 1;
  readonly accepted: true;
  readonly invocation_id: string;
  readonly tool_call_id: string;
  readonly tool_name: GatewayToolName;
  readonly tool_version: "1.0.0";
  readonly cached: boolean;
  readonly artifact: ToolObservationArtifact;
  /** Python has already checked the specific output schema and redacted it. */
  readonly result: Readonly<Record<string, unknown>>;
}

export interface RejectedToolGatewayResponse {
  readonly schema_version: 1;
  readonly accepted: false;
  readonly tool_call_id: string;
  readonly tool_name: GatewayToolName;
  readonly code: string;
  readonly invocation_id: string | null;
  readonly cached: boolean;
}

export type ToolGatewayResponse = AcceptedToolGatewayResponse | RejectedToolGatewayResponse;

export interface StartSessionWork {
  readonly job: AgentJob;
  readonly task: WorkerTask;
  readonly context_manifest: ContextManifest;
}

export interface TurnWork {
  readonly job: AgentJob;
  readonly session: AgentSession;
  readonly task: WorkerTask;
  readonly context_manifest: ContextManifest;
}

export interface SteerWork {
  readonly job: AgentJob;
  readonly session: AgentSession;
  readonly steer: AgentSteer;
  /**
   * Reopening a durable Pi transcript after a runner restart still requires
   * the sealed context that created it.  Returning this verified envelope is
   * safer than acknowledging and silently losing a queued operator message.
   */
  readonly context_manifest: ContextManifest;
}

export interface SessionWork {
  readonly job: AgentJob;
  readonly session: AgentSession;
}

/**
 * Power sessions are intentionally separate from v0.1 AgentSession.  They
 * carry only the runner-facing workspace descriptor and a short reviewed
 * brief—never an API key, transcript, raw flag, Docker capability or target
 * URL.  The API maps custom-tool calls back to this durable session.
 */
export interface PowerPiSession {
  readonly id: string;
  readonly run_id: string;
  readonly start_job_id: string;
  readonly label: "auto" | "A" | "B" | "C";
  readonly role: "autoprompter" | "racer";
  readonly provider: "openai" | "google" | "deepseek";
  readonly model: string;
  readonly temperature: number;
  readonly archive_digest: string;
  readonly brief: string;
  readonly target_host: string | null;
  readonly target_port: number | null;
  readonly workspace_id: string;
  readonly state: "starting" | "ready" | "running" | "aborting" | "aborted" | "failed";
  readonly runner_id: string | null;
  readonly session_store_key: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface PowerPiSteer {
  readonly id: string;
  readonly run_id: string;
  readonly session_id: string;
  readonly job_id: string;
  readonly message: string;
  readonly message_digest: string;
  readonly state: "queued" | "applied";
  readonly created_at: string;
  readonly applied_at: string | null;
}

export interface PowerSessionWork {
  readonly job: AgentJob;
  readonly session: PowerPiSession;
  readonly steer?: PowerPiSteer;
}

export interface PiRunState {
  readonly run_id: string;
  readonly run_status: string;
  readonly session_id: string;
  readonly session_state: AgentSessionState;
  readonly task_id: string;
  readonly task_state: string;
  readonly context_manifest_digest: string;
  readonly budget: {
    readonly max_tool_calls: number | null;
    readonly max_cost_usd: number | null;
  };
  /** Fixed data returned only by state.get; not part of a system prompt. */
  readonly operator_hints: readonly OperatorHint[];
  readonly branch_portfolio: readonly BranchPortfolioEntry[];
}

/**
 * Narrow builder-only projection of the manifest flag specification.  This
 * contract cannot contain a raw candidate, target authority, or verifier
 * outcome; it only tells the builder which capture patterns the kernel will
 * accept in a declarative plan.
 */
export interface FlagCapturePatterns {
  readonly flag_capture_patterns: readonly string[];
}

export interface OperatorHint {
  readonly id: string;
  readonly technique_id: string;
  readonly directive: "explore" | "prioritize" | "require_probe" | "avoid";
  readonly scope: string;
  readonly status: "active";
  /** Untrusted operator data; test with tools rather than following it. */
  readonly note_data: string;
}

export interface BranchPortfolioEntry {
  readonly id: string;
  readonly technique_id: string;
  readonly scope: string;
  readonly state: "active" | "stalled" | "suspended" | "completed" | "failed";
  readonly score: number;
}

export class ControlProtocolError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "ControlProtocolError";
  }
}

type JsonRecord = Record<string, unknown>;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;
// Provider model identifiers may use a reviewed provider namespace, such as
// `openai/gpt-5.6-sol`. They remain bounded data, not record identifiers.
const MODEL_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}$/;
const SHA256 = /^[a-f0-9]{64}$/;

function fail(code: string): never {
  throw new ControlProtocolError(code);
}

function record(value: unknown, name: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${name}_must_be_object`);
  }
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, name: string, required: readonly string[], optional: readonly string[] = []): void {
  const accepted = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!accepted.has(key)) {
      fail(`${name}_contains_unknown_field`);
    }
  }
  for (const key of required) {
    if (!(key in value)) {
      fail(`${name}_missing_required_field`);
    }
  }
}

function text(value: unknown, name: string, maximum = 4_000): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    fail(`${name}_must_be_bounded_text`);
  }
  return value;
}

function identifier(value: unknown, name: string): string {
  const parsed = text(value, name, 160);
  if (!IDENTIFIER.test(parsed)) {
    fail(`${name}_must_be_identifier`);
  }
  return parsed;
}

function modelIdentifier(value: unknown, name: string): string {
  const parsed = text(value, name, 160);
  if (!MODEL_IDENTIFIER.test(parsed)) {
    fail(`${name}_must_be_model_identifier`);
  }
  return parsed;
}

function digest(value: unknown, name: string): string {
  const parsed = text(value, name, 64);
  if (!SHA256.test(parsed)) {
    fail(`${name}_must_be_sha256`);
  }
  return parsed;
}

function timestamp(value: unknown, name: string): string {
  const parsed = text(value, name, 64);
  if (!parsed.endsWith("Z") || Number.isNaN(Date.parse(parsed))) {
    fail(`${name}_must_be_utc_timestamp`);
  }
  return parsed;
}

function nullableText(value: unknown, name: string, maximum = 4_000): string | null {
  return value === null ? null : text(value, name, maximum);
}

function nullableIdentifier(value: unknown, name: string): string | null {
  return value === null ? null : identifier(value, name);
}

function nullableTimestamp(value: unknown, name: string): string | null {
  return value === null ? null : timestamp(value, name);
}

function integer(value: unknown, name: string, minimum = 0, maximum = 10_000_000): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail(`${name}_must_be_bounded_integer`);
  }
  return value as number;
}

function finiteNumber(value: unknown, name: string, minimum = 0, maximum = 1_000_000): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) {
    fail(`${name}_must_be_bounded_number`);
  }
  return value;
}

function oneOf<T extends readonly string[]>(value: unknown, choices: T, name: string): T[number] {
  if (typeof value !== "string" || !choices.includes(value)) {
    fail(`${name}_is_invalid`);
  }
  return value as T[number];
}

function identifierArray(value: unknown, name: string, maximum = 128): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    fail(`${name}_must_be_bounded_array`);
  }
  const parsed = value.map((entry, index) => identifier(entry, `${name}_${index}`));
  if (new Set(parsed).size !== parsed.length) {
    fail(`${name}_cannot_contain_duplicates`);
  }
  return parsed;
}

function boolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    fail(`${name}_must_be_boolean`);
  }
  return value;
}

function optionalText(value: unknown, name: string, maximum = 4_096): string | undefined {
  return value === undefined ? undefined : text(value, name, maximum);
}

function optionalInteger(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): number | undefined {
  return value === undefined ? undefined : integer(value, name, minimum, maximum);
}

function optionalBoolean(value: unknown, name: string): boolean | undefined {
  return value === undefined ? undefined : boolean(value, name);
}

function stringRecord(
  value: unknown,
  name: string,
  maximumEntries: number,
  maximumKeyLength: number,
  maximumValueLength: number,
): Readonly<Record<string, string>> {
  const parsed = record(value, name);
  const entries = Object.entries(parsed);
  if (entries.length > maximumEntries) {
    fail(`${name}_too_large`);
  }
  const result: Record<string, string> = {};
  for (const [key, entry] of entries) {
    if (!key || key.length > maximumKeyLength || /[\r\n\0]/.test(key)) {
      fail(`${name}_key_invalid`);
    }
    const parsedValue = text(entry, `${name}_${key}`, maximumValueLength);
    if (/[\r\n\0]/.test(parsedValue)) {
      fail(`${name}_value_invalid`);
    }
    result[key] = parsedValue;
  }
  return result;
}

function httpPath(value: unknown): string {
  const path = value === undefined ? "/" : text(value, "http_request_path", 4_096);
  if (!path.startsWith("/") || path.startsWith("//") || /[\r\n\t\0\\?#]/.test(path)) {
    fail("http_request_path_invalid");
  }
  return path;
}

function httpHeaders(value: unknown): Readonly<Record<string, string>> {
  if (value === undefined) {
    return {};
  }
  const parsed = stringRecord(value, "http_request_headers", 16, 128, 4_096);
  const allowed = new Set([
    "accept",
    "accept-language",
    "content-type",
    "if-match",
    "if-none-match",
    "referer",
    "user-agent",
    "x-csrf-token",
    "x-requested-with",
  ]);
  const normalized: Record<string, string> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const name = key.toLowerCase();
    if (!allowed.has(name) || name in normalized) {
      fail("http_request_header_not_allowed");
    }
    normalized[name] = entry;
  }
  return normalized;
}

function httpJsonBody(value: unknown): unknown {
  const parsed = boundedJson(value, "http_request_json_body");
  let serialized: string;
  try {
    serialized = JSON.stringify(parsed);
  } catch {
    fail("http_request_json_invalid");
  }
  if (new TextEncoder().encode(serialized).length > 64 * 1024) {
    fail("http_request_json_too_large");
  }
  return parsed;
}

/**
 * Parse an untrusted JSON value without turning it into an arbitrary object
 * graph. The source tool contracts return data only; their exact semantic
 * schema is independently enforced by Python before this response exists.
 */
function boundedJson(value: unknown, name: string, depth = 0): unknown {
  if (depth > 12) {
    fail(`${name}_too_deep`);
  }
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail(`${name}_number_invalid`);
    }
    return value;
  }
  if (typeof value === "string") {
    return text(value, name, 32_768);
  }
  if (Array.isArray(value)) {
    if (value.length > 10_000) {
      fail(`${name}_array_too_large`);
    }
    return value.map((item, index) => boundedJson(item, `${name}_${index}`, depth + 1));
  }
  const parsed = record(value, name);
  const keys = Object.keys(parsed);
  if (keys.length > 10_000) {
    fail(`${name}_object_too_large`);
  }
  const result: JsonRecord = {};
  for (const key of keys) {
    if (key.length === 0 || key.length > 160) {
      fail(`${name}_key_invalid`);
    }
    result[key] = boundedJson(parsed[key], `${name}_${key}`, depth + 1);
  }
  return result;
}

function parseGatewayArguments(toolName: GatewayToolName, value: unknown): Readonly<Record<string, unknown>> {
  const parsed = record(value, "tool_request_arguments");
  const path = optionalText(parsed.path, "tool_request_path");
  switch (toolName) {
    case "source.list": {
      exactKeys(parsed, "source_list_arguments", [], ["path", "recursive", "max_entries"]);
      const recursive = optionalBoolean(parsed.recursive, "source_list_recursive");
      const maxEntries = optionalInteger(parsed.max_entries, "source_list_max_entries", 1, 10_000);
      return {
        ...(path === undefined ? {} : { path }),
        ...(recursive === undefined ? {} : { recursive }),
        ...(maxEntries === undefined ? {} : { max_entries: maxEntries }),
      };
    }
    case "source.read": {
      exactKeys(
        parsed,
        "source_read_arguments",
        ["path"],
        ["start_line", "end_line", "max_file_bytes", "max_output_bytes"],
      );
      const requiredPath = text(parsed.path, "source_read_path", 4_096);
      const startLine = optionalInteger(parsed.start_line, "source_read_start_line", 1, 10_000_000);
      const endLine = optionalInteger(parsed.end_line, "source_read_end_line", 1, 10_000_000);
      if (startLine !== undefined && endLine !== undefined && endLine < startLine) {
        fail("source_read_line_range_invalid");
      }
      const maxFileBytes = optionalInteger(
        parsed.max_file_bytes,
        "source_read_max_file_bytes",
        1,
        16 * 1024 * 1024,
      );
      const maxOutputBytes = optionalInteger(
        parsed.max_output_bytes,
        "source_read_max_output_bytes",
        1,
        32 * 1024,
      );
      return {
        path: requiredPath,
        ...(startLine === undefined ? {} : { start_line: startLine }),
        ...(endLine === undefined ? {} : { end_line: endLine }),
        ...(maxFileBytes === undefined ? {} : { max_file_bytes: maxFileBytes }),
        ...(maxOutputBytes === undefined ? {} : { max_output_bytes: maxOutputBytes }),
      };
    }
    case "source.search": {
      exactKeys(
        parsed,
        "source_search_arguments",
        ["query"],
        ["path", "case_sensitive", "max_files", "max_matches", "max_file_bytes"],
      );
      const query = text(parsed.query, "source_search_query", 4_096);
      const caseSensitive = optionalBoolean(parsed.case_sensitive, "source_search_case_sensitive");
      const maxFiles = optionalInteger(parsed.max_files, "source_search_max_files", 1, 10_000);
      const maxMatches = optionalInteger(parsed.max_matches, "source_search_max_matches", 1, 10_000);
      const maxFileBytes = optionalInteger(
        parsed.max_file_bytes,
        "source_search_max_file_bytes",
        1,
        16 * 1024 * 1024,
      );
      return {
        query,
        ...(path === undefined ? {} : { path }),
        ...(caseSensitive === undefined ? {} : { case_sensitive: caseSensitive }),
        ...(maxFiles === undefined ? {} : { max_files: maxFiles }),
        ...(maxMatches === undefined ? {} : { max_matches: maxMatches }),
        ...(maxFileBytes === undefined ? {} : { max_file_bytes: maxFileBytes }),
      };
    }
    case "source.manifest":
      exactKeys(parsed, "source_manifest_arguments", []);
      return {};
    case "artifacts.inspect": {
      exactKeys(
        parsed,
        "artifact_inspect_arguments",
        ["path"],
        ["max_file_bytes", "max_header_bytes", "max_strings", "max_string_bytes"],
      );
      const requiredPath = text(parsed.path, "artifact_inspect_path", 4_096);
      const maxFileBytes = optionalInteger(
        parsed.max_file_bytes,
        "artifact_inspect_max_file_bytes",
        1,
        64 * 1024 * 1024,
      );
      const maxHeaderBytes = optionalInteger(
        parsed.max_header_bytes,
        "artifact_inspect_max_header_bytes",
        1,
        4_096,
      );
      const maxStrings = optionalInteger(parsed.max_strings, "artifact_inspect_max_strings", 1, 512);
      const maxStringBytes = optionalInteger(
        parsed.max_string_bytes,
        "artifact_inspect_max_string_bytes",
        4,
        4_096,
      );
      return {
        path: requiredPath,
        ...(maxFileBytes === undefined ? {} : { max_file_bytes: maxFileBytes }),
        ...(maxHeaderBytes === undefined ? {} : { max_header_bytes: maxHeaderBytes }),
        ...(maxStrings === undefined ? {} : { max_strings: maxStrings }),
        ...(maxStringBytes === undefined ? {} : { max_string_bytes: maxStringBytes }),
      };
    }
    case "transform.apply": {
      exactKeys(parsed, "transform_apply_arguments", ["transform", "input_text"], ["max_output_bytes"]);
      const transform = oneOf(
        parsed.transform,
        [
          "base64.decode_utf8",
          "base64.encode_utf8",
          "hex.decode_utf8",
          "hex.encode_utf8",
          "url.decode",
          "url.encode",
          "rot13",
        ] as const,
        "transform_apply_name",
      );
      const inputText = text(parsed.input_text, "transform_apply_input_text", 32 * 1024);
      const maxOutputBytes = optionalInteger(
        parsed.max_output_bytes,
        "transform_apply_max_output_bytes",
        1,
        64 * 1024,
      );
      return {
        transform,
        input_text: inputText,
        ...(maxOutputBytes === undefined ? {} : { max_output_bytes: maxOutputBytes }),
      };
    }
    case "http.request": {
      exactKeys(
        parsed,
        "http_request_arguments",
        ["target_alias"],
        ["method", "path", "query", "headers", "json_body", "content", "timeout_seconds", "max_response_bytes"],
      );
      const method = parsed.method === undefined
        ? "GET"
        : oneOf(
          parsed.method,
          ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const,
          "http_request_method",
        );
      const query = parsed.query === undefined
        ? {}
        : stringRecord(parsed.query, "http_request_query", 32, 128, 4_096);
      const jsonBody = parsed.json_body === undefined ? undefined : httpJsonBody(parsed.json_body);
      const content = optionalText(parsed.content, "http_request_content", 64 * 1024);
      if (jsonBody !== undefined && jsonBody !== null && content !== undefined) {
        fail("http_request_body_is_ambiguous");
      }
      const timeoutSeconds = parsed.timeout_seconds === undefined
        ? undefined
        : finiteNumber(parsed.timeout_seconds, "http_request_timeout_seconds", 1, 15);
      const maxResponseBytes = optionalInteger(
        parsed.max_response_bytes,
        "http_request_max_response_bytes",
        1,
        256 * 1024,
      );
      return {
        target_alias: identifier(parsed.target_alias, "http_request_target_alias"),
        method,
        path: httpPath(parsed.path),
        query,
        headers: httpHeaders(parsed.headers),
        ...(jsonBody === undefined ? {} : { json_body: jsonBody }),
        ...(content === undefined ? {} : { content }),
        ...(timeoutSeconds === undefined ? {} : { timeout_seconds: timeoutSeconds }),
        ...(maxResponseBytes === undefined ? {} : { max_response_bytes: maxResponseBytes }),
      };
    }
  }
}

function parseToolObservationArtifact(value: unknown): ToolObservationArtifact {
  const parsed = record(value, "tool_observation_artifact");
  exactKeys(parsed, "tool_observation_artifact", ["artifact_id", "digest", "size_bytes", "summary"]);
  return {
    artifact_id: identifier(parsed.artifact_id, "tool_observation_artifact_id"),
    digest: digest(parsed.digest, "tool_observation_digest"),
    size_bytes: integer(parsed.size_bytes, "tool_observation_size_bytes", 0, 16 * 1024 * 1024),
    summary: text(parsed.summary, "tool_observation_summary", 2_000),
  };
}

function parseToolGatewayResponse(value: unknown, expected: GatewayToolRequest): ToolGatewayResponse {
  const parsed = record(value, "tool_gateway_response");
  if (parsed.accepted === true) {
    exactKeys(
      parsed,
      "tool_gateway_accepted_response",
      [
        "schema_version", "accepted", "invocation_id", "tool_call_id", "tool_name", "tool_version",
        "cached", "artifact", "result",
      ],
    );
    if (integer(parsed.schema_version, "tool_gateway_schema_version", 1, 1) !== 1) {
      fail("tool_gateway_schema_version_invalid");
    }
    const toolName = oneOf(parsed.tool_name, GATEWAY_TOOL_NAMES, "tool_gateway_tool_name");
    if (
      parsed.tool_call_id !== expected.call.tool_call_id
      || toolName !== expected.call.tool_name
      || parsed.tool_version !== "1.0.0"
    ) {
      fail("tool_gateway_response_call_mismatch");
    }
    const result = boundedJson(parsed.result, "tool_gateway_result");
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
      fail("tool_gateway_result_must_be_object");
    }
    return {
      schema_version: 1,
      accepted: true,
      invocation_id: identifier(parsed.invocation_id, "tool_gateway_invocation_id"),
      tool_call_id: expected.call.tool_call_id,
      tool_name: toolName,
      tool_version: "1.0.0",
      cached: boolean(parsed.cached, "tool_gateway_cached"),
      artifact: parseToolObservationArtifact(parsed.artifact),
      result: result as Readonly<Record<string, unknown>>,
    };
  }
  if (parsed.accepted === false) {
    exactKeys(
      parsed,
      "tool_gateway_rejected_response",
      ["schema_version", "accepted", "tool_call_id", "tool_name", "code", "invocation_id", "cached"],
    );
    if (integer(parsed.schema_version, "tool_gateway_schema_version", 1, 1) !== 1) {
      fail("tool_gateway_schema_version_invalid");
    }
    const toolName = oneOf(parsed.tool_name, GATEWAY_TOOL_NAMES, "tool_gateway_tool_name");
    if (parsed.tool_call_id !== expected.call.tool_call_id || toolName !== expected.call.tool_name) {
      fail("tool_gateway_response_call_mismatch");
    }
    return {
      schema_version: 1,
      accepted: false,
      tool_call_id: expected.call.tool_call_id,
      tool_name: toolName,
      code: identifier(parsed.code, "tool_gateway_rejection_code"),
      invocation_id: nullableIdentifier(parsed.invocation_id, "tool_gateway_invocation_id"),
      cached: boolean(parsed.cached, "tool_gateway_cached"),
    };
  }
  fail("tool_gateway_response_accepted_invalid");
}

function parseAgentJob(value: unknown): AgentJob {
  const parsed = record(value, "agent_job");
  exactKeys(
    parsed,
    "agent_job",
    [
      "id", "run_id", "kind", "payload_ref", "payload_digest", "state", "lease_owner",
      "lease_version", "lease_expires_at", "attempts", "deadline_at", "created_at", "updated_at",
    ],
  );
  const payloadDigest = parsed.payload_digest === null ? null : digest(parsed.payload_digest, "agent_job_payload_digest");
  return {
    id: identifier(parsed.id, "agent_job_id"),
    run_id: identifier(parsed.run_id, "agent_job_run_id"),
    kind: oneOf(parsed.kind, AGENT_JOB_KINDS, "agent_job_kind"),
    payload_ref: nullableText(parsed.payload_ref, "agent_job_payload_ref", 500),
    payload_digest: payloadDigest,
    state: oneOf(parsed.state, ["queued", "leased", "completed", "failed"] as const, "agent_job_state"),
    lease_owner: nullableIdentifier(parsed.lease_owner, "agent_job_lease_owner"),
    lease_version: integer(parsed.lease_version, "agent_job_lease_version", 0, 1_000_000),
    lease_expires_at: nullableTimestamp(parsed.lease_expires_at, "agent_job_lease_expires_at"),
    attempts: integer(parsed.attempts, "agent_job_attempts", 0, 1_000_000),
    deadline_at: nullableTimestamp(parsed.deadline_at, "agent_job_deadline_at"),
    created_at: timestamp(parsed.created_at, "agent_job_created_at"),
    updated_at: timestamp(parsed.updated_at, "agent_job_updated_at"),
  };
}

function parseEvidenceRef(value: unknown): ContextEvidenceRef {
  const parsed = record(value, "context_evidence_ref");
  exactKeys(parsed, "context_evidence_ref", ["observation_id", "artifact_id", "digest"]);
  return {
    observation_id: identifier(parsed.observation_id, "context_evidence_observation_id"),
    artifact_id: identifier(parsed.artifact_id, "context_evidence_artifact_id"),
    digest: digest(parsed.digest, "context_evidence_digest"),
  };
}

function parseContextManifest(value: unknown): ContextManifest {
  const parsed = record(value, "context_manifest");
  exactKeys(
    parsed,
    "context_manifest",
    [
      "schema", "schema_version", "id", "run_id", "task_id", "challenge_digest", "role", "objective",
      "allowed_tool_ids", "evidence_refs", "hypothesis_refs", "active_hint_refs", "attempt_fingerprints",
      "budget_slice", "created_at", "expires_at", "digest",
    ],
  );
  if (parsed.schema !== "ctfmesh.context-manifest" || parsed.schema_version !== 1) {
    fail("context_manifest_schema_version_invalid");
  }
  if (!Array.isArray(parsed.evidence_refs) || parsed.evidence_refs.length > 128) {
    fail("context_manifest_evidence_refs_invalid");
  }
  const budget = record(parsed.budget_slice, "context_manifest_budget_slice");
  exactKeys(budget, "context_manifest_budget_slice", ["tool_calls", "input_tokens", "output_tokens"]);
  return {
    schema: "ctfmesh.context-manifest",
    schema_version: 1,
    id: identifier(parsed.id, "context_manifest_id"),
    run_id: identifier(parsed.run_id, "context_manifest_run_id"),
    task_id: identifier(parsed.task_id, "context_manifest_task_id"),
    challenge_digest: digest(parsed.challenge_digest, "context_manifest_challenge_digest"),
    role: oneOf(parsed.role, AGENT_ROLES, "context_manifest_role"),
    objective: text(parsed.objective, "context_manifest_objective", 4_000),
    allowed_tool_ids: identifierArray(parsed.allowed_tool_ids, "context_manifest_allowed_tool_ids", 32),
    evidence_refs: parsed.evidence_refs.map(parseEvidenceRef),
    hypothesis_refs: identifierArray(parsed.hypothesis_refs, "context_manifest_hypothesis_refs", 64),
    active_hint_refs: identifierArray(parsed.active_hint_refs, "context_manifest_active_hint_refs", 32),
    attempt_fingerprints: (() => {
      const values = identifierArray(parsed.attempt_fingerprints, "context_manifest_attempt_fingerprints", 64);
      for (const entry of values) {
        if (!SHA256.test(entry)) {
          fail("context_manifest_attempt_fingerprint_invalid");
        }
      }
      return values;
    })(),
    budget_slice: {
      tool_calls: integer(budget.tool_calls, "context_manifest_budget_tool_calls"),
      input_tokens: integer(budget.input_tokens, "context_manifest_budget_input_tokens"),
      output_tokens: integer(budget.output_tokens, "context_manifest_budget_output_tokens"),
    },
    created_at: timestamp(parsed.created_at, "context_manifest_created_at"),
    expires_at: timestamp(parsed.expires_at, "context_manifest_expires_at"),
    digest: digest(parsed.digest, "context_manifest_digest"),
  };
}

function parseWorkerTask(value: unknown): WorkerTask {
  const parsed = record(value, "worker_task");
  exactKeys(
    parsed,
    "worker_task",
    [
      "id", "run_id", "branch_id", "role", "objective", "required_evidence", "context_manifest_id",
      "state", "lease_owner", "lease_version", "lease_expires_at", "attempts", "deadline_at",
      "created_at", "updated_at",
    ],
  );
  return {
    id: identifier(parsed.id, "worker_task_id"),
    run_id: identifier(parsed.run_id, "worker_task_run_id"),
    branch_id: identifier(parsed.branch_id, "worker_task_branch_id"),
    role: oneOf(parsed.role, AGENT_ROLES, "worker_task_role"),
    objective: text(parsed.objective, "worker_task_objective", 4_000),
    required_evidence: identifierArray(parsed.required_evidence, "worker_task_required_evidence", 32),
    context_manifest_id: identifier(parsed.context_manifest_id, "worker_task_context_manifest_id"),
    state: oneOf(parsed.state, ["queued", "leased", "completed", "failed", "cancelled"] as const, "worker_task_state"),
    lease_owner: nullableIdentifier(parsed.lease_owner, "worker_task_lease_owner"),
    lease_version: integer(parsed.lease_version, "worker_task_lease_version", 0, 1_000_000),
    lease_expires_at: nullableTimestamp(parsed.lease_expires_at, "worker_task_lease_expires_at"),
    attempts: integer(parsed.attempts, "worker_task_attempts", 0, 1_000_000),
    deadline_at: timestamp(parsed.deadline_at, "worker_task_deadline_at"),
    created_at: timestamp(parsed.created_at, "worker_task_created_at"),
    updated_at: timestamp(parsed.updated_at, "worker_task_updated_at"),
  };
}

function parseAgentSession(value: unknown): AgentSession {
  const parsed = record(value, "agent_session");
  exactKeys(
    parsed,
    "agent_session",
    [
      "id", "run_id", "start_job_id", "task_id", "context_manifest_id", "role", "state",
      "session_store_key", "runner_id", "created_at", "updated_at",
    ],
  );
  return {
    id: identifier(parsed.id, "agent_session_id"),
    run_id: identifier(parsed.run_id, "agent_session_run_id"),
    start_job_id: identifier(parsed.start_job_id, "agent_session_start_job_id"),
    task_id: identifier(parsed.task_id, "agent_session_task_id"),
    context_manifest_id: identifier(parsed.context_manifest_id, "agent_session_context_manifest_id"),
    role: oneOf(parsed.role, AGENT_ROLES, "agent_session_role"),
    state: oneOf(parsed.state, AGENT_SESSION_STATES, "agent_session_state"),
    session_store_key: identifier(parsed.session_store_key, "agent_session_store_key"),
    runner_id: nullableIdentifier(parsed.runner_id, "agent_session_runner_id"),
    created_at: timestamp(parsed.created_at, "agent_session_created_at"),
    updated_at: timestamp(parsed.updated_at, "agent_session_updated_at"),
  };
}

function parseAgentSteer(value: unknown): AgentSteer {
  const parsed = record(value, "agent_steer");
  exactKeys(
    parsed,
    "agent_steer",
    ["id", "run_id", "session_id", "message", "message_digest", "state", "created_at", "applied_at"],
  );
  return {
    id: identifier(parsed.id, "agent_steer_id"),
    run_id: identifier(parsed.run_id, "agent_steer_run_id"),
    session_id: identifier(parsed.session_id, "agent_steer_session_id"),
    message: text(parsed.message, "agent_steer_message", 2_000),
    message_digest: digest(parsed.message_digest, "agent_steer_message_digest"),
    state: oneOf(parsed.state, ["queued", "applied"] as const, "agent_steer_state"),
    created_at: timestamp(parsed.created_at, "agent_steer_created_at"),
    applied_at: nullableTimestamp(parsed.applied_at, "agent_steer_applied_at"),
  };
}

function parsePowerPiSession(value: unknown): PowerPiSession {
  const parsed = record(value, "power_pi_session");
  exactKeys(
    parsed,
    "power_pi_session",
    [
      "id", "run_id", "start_job_id", "label", "role", "provider", "model", "temperature",
      "archive_digest", "brief", "target_host", "target_port", "workspace_id", "state", "runner_id",
      "session_store_key", "created_at", "updated_at",
    ],
  );
  const targetHost = nullableText(parsed.target_host, "power_pi_session_target_host", 253);
  const targetPort = parsed.target_port === null
    ? null
    : integer(parsed.target_port, "power_pi_session_target_port", 1, 65_535);
  if ((targetHost === null) !== (targetPort === null)) {
    fail("power_pi_session_target_shape_invalid");
  }
  const session = {
    id: identifier(parsed.id, "power_pi_session_id"),
    run_id: identifier(parsed.run_id, "power_pi_session_run_id"),
    start_job_id: identifier(parsed.start_job_id, "power_pi_session_start_job_id"),
    label: oneOf(parsed.label, ["auto", "A", "B", "C"] as const, "power_pi_session_label"),
    role: oneOf(parsed.role, ["autoprompter", "racer"] as const, "power_pi_session_role"),
    provider: oneOf(parsed.provider, ["openai", "google", "deepseek"] as const, "power_pi_session_provider"),
    model: modelIdentifier(parsed.model, "power_pi_session_model"),
    temperature: finiteNumber(parsed.temperature, "power_pi_session_temperature", 0, 2),
    archive_digest: digest(parsed.archive_digest, "power_pi_session_archive_digest"),
    brief: text(parsed.brief, "power_pi_session_brief", 4_000),
    target_host: targetHost,
    target_port: targetPort,
    workspace_id: identifier(parsed.workspace_id, "power_pi_session_workspace_id"),
    state: oneOf(
      parsed.state,
      ["starting", "ready", "running", "aborting", "aborted", "failed"] as const,
      "power_pi_session_state",
    ),
    runner_id: nullableIdentifier(parsed.runner_id, "power_pi_session_runner_id"),
    session_store_key: identifier(parsed.session_store_key, "power_pi_session_store_key"),
    created_at: timestamp(parsed.created_at, "power_pi_session_created_at"),
    updated_at: timestamp(parsed.updated_at, "power_pi_session_updated_at"),
  } satisfies PowerPiSession;
  if (!/^ws_[0-9a-f]{32}$/.test(session.workspace_id)) {
    fail("power_pi_session_workspace_id_invalid");
  }
  return session;
}

function parsePowerPiSteer(value: unknown): PowerPiSteer {
  const parsed = record(value, "power_pi_steer");
  exactKeys(
    parsed,
    "power_pi_steer",
    ["id", "run_id", "session_id", "job_id", "message", "message_digest", "state", "created_at", "applied_at"],
  );
  return {
    id: identifier(parsed.id, "power_pi_steer_id"),
    run_id: identifier(parsed.run_id, "power_pi_steer_run_id"),
    session_id: identifier(parsed.session_id, "power_pi_steer_session_id"),
    job_id: identifier(parsed.job_id, "power_pi_steer_job_id"),
    message: text(parsed.message, "power_pi_steer_message", 2_000),
    message_digest: digest(parsed.message_digest, "power_pi_steer_message_digest"),
    state: oneOf(parsed.state, ["queued", "applied"] as const, "power_pi_steer_state"),
    created_at: timestamp(parsed.created_at, "power_pi_steer_created_at"),
    applied_at: nullableTimestamp(parsed.applied_at, "power_pi_steer_applied_at"),
  };
}

function parsePowerSessionWork(value: unknown): PowerSessionWork {
  const parsed = record(value, "power_session_work");
  exactKeys(parsed, "power_session_work", ["job", "session"], ["steer"]);
  const job = parseAgentJob(parsed.job);
  if (
    job.kind !== "power_session_start"
    && job.kind !== "power_steer"
    && job.kind !== "power_abort"
  ) {
    fail("power_session_work_kind_invalid");
  }
  const session = parsePowerPiSession(parsed.session);
  if (session.run_id !== job.run_id) {
    fail("power_session_work_run_mismatch");
  }
  if (job.kind === "power_steer") {
    if (parsed.steer === undefined) {
      fail("power_session_work_steer_missing");
    }
    const steer = parsePowerPiSteer(parsed.steer);
    if (steer.run_id !== job.run_id || steer.session_id !== session.id || steer.job_id !== job.id) {
      fail("power_session_work_steer_mismatch");
    }
    return { job, session, steer };
  }
  if (parsed.steer !== undefined) {
    fail("power_session_work_steer_unexpected");
  }
  return { job, session };
}

function parseOperatorHint(value: unknown): OperatorHint {
  const parsed = record(value, "operator_hint");
  exactKeys(
    parsed,
    "operator_hint",
    ["id", "technique_id", "directive", "scope", "status", "note_data"],
  );
  return {
    id: identifier(parsed.id, "operator_hint_id"),
    technique_id: identifier(parsed.technique_id, "operator_hint_technique_id"),
    directive: oneOf(
      parsed.directive,
      ["explore", "prioritize", "require_probe", "avoid"] as const,
      "operator_hint_directive",
    ),
    scope: identifier(parsed.scope, "operator_hint_scope"),
    status: oneOf(parsed.status, ["active"] as const, "operator_hint_status"),
    note_data: text(parsed.note_data, "operator_hint_note_data", 500),
  };
}

function parseBranchPortfolioEntry(value: unknown): BranchPortfolioEntry {
  const parsed = record(value, "branch_portfolio_entry");
  exactKeys(parsed, "branch_portfolio_entry", ["id", "technique_id", "scope", "state", "score"]);
  return {
    id: identifier(parsed.id, "branch_portfolio_entry_id"),
    technique_id: identifier(parsed.technique_id, "branch_portfolio_entry_technique_id"),
    scope: identifier(parsed.scope, "branch_portfolio_entry_scope"),
    state: oneOf(
      parsed.state,
      ["active", "stalled", "suspended", "completed", "failed"] as const,
      "branch_portfolio_entry_state",
    ),
    score: finiteNumber(parsed.score, "branch_portfolio_entry_score", -2, 2),
  };
}

/** Parse the only response shapes the runner accepts from the internal API. */
export const controlContract = {
  claimedJob(value: unknown): AgentJob | null {
    const parsed = record(value, "claim_response");
    exactKeys(parsed, "claim_response", ["job"]);
    return parsed.job === null ? null : parseAgentJob(parsed.job);
  },

  startSessionWork(value: unknown): StartSessionWork {
    const parsed = record(value, "start_session_work");
    exactKeys(parsed, "start_session_work", ["job", "task", "context_manifest"]);
    const job = parseAgentJob(parsed.job);
    if (job.kind !== "start_session") {
      fail("start_session_work_kind_invalid");
    }
    const task = parseWorkerTask(parsed.task);
    const contextManifest = parseContextManifest(parsed.context_manifest);
    if (task.id !== contextManifest.task_id || task.context_manifest_id !== contextManifest.id) {
      fail("start_session_work_context_task_mismatch");
    }
    return { job, task, context_manifest: contextManifest };
  },

  sessionReservation(value: unknown): { readonly session: AgentSession; readonly task: WorkerTask; readonly context_manifest: ContextManifest } {
    const parsed = record(value, "session_reservation");
    exactKeys(parsed, "session_reservation", ["session", "task", "context_manifest"]);
    const session = parseAgentSession(parsed.session);
    const task = parseWorkerTask(parsed.task);
    const contextManifest = parseContextManifest(parsed.context_manifest);
    if (
      session.task_id !== task.id
      || session.context_manifest_id !== contextManifest.id
      || task.context_manifest_id !== contextManifest.id
      || session.role !== contextManifest.role
    ) {
      fail("session_reservation_context_mismatch");
    }
    return { session, task, context_manifest: contextManifest };
  },

  powerSessionWork(value: unknown): PowerSessionWork {
    return parsePowerSessionWork(value);
  },

  agentSession: parseAgentSession,
  agentJob: parseAgentJob,
  agentSteer: parseAgentSteer,

  eventBatchAck(value: unknown): void {
    const parsed = record(value, "agent_event_batch_ack");
    exactKeys(parsed, "agent_event_batch_ack", ["items"]);
    if (!Array.isArray(parsed.items) || parsed.items.length > 128) {
      fail("agent_event_batch_ack_invalid");
    }
    // Event rows are immutable control-plane output and do not grant the
    // runner any capability. Still require objects so a proxy cannot smuggle
    // a surprising primitive into diagnostics or future code.
    for (const item of parsed.items) {
      record(item, "agent_event_batch_ack_item");
    }
  },

  turnWork(value: unknown): TurnWork {
    const parsed = record(value, "turn_work");
    exactKeys(parsed, "turn_work", ["job", "session", "task", "context_manifest"]);
    const job = parseAgentJob(parsed.job);
    const session = parseAgentSession(parsed.session);
    const task = parseWorkerTask(parsed.task);
    const contextManifest = parseContextManifest(parsed.context_manifest);
    if (
      job.kind !== "run_turn"
      || session.task_id !== task.id
      || session.context_manifest_id !== contextManifest.id
      || task.context_manifest_id !== contextManifest.id
      || session.role !== contextManifest.role
    ) {
      fail("turn_work_context_mismatch");
    }
    return { job, session, task, context_manifest: contextManifest };
  },

  steerWork(value: unknown): SteerWork {
    const parsed = record(value, "steer_work");
    exactKeys(parsed, "steer_work", ["job", "session", "steer", "context_manifest"]);
    const job = parseAgentJob(parsed.job);
    const session = parseAgentSession(parsed.session);
    const steer = parseAgentSteer(parsed.steer);
    const contextManifest = parseContextManifest(parsed.context_manifest);
    if (
      job.kind !== "steer"
      || steer.session_id !== session.id
      || session.context_manifest_id !== contextManifest.id
      || session.role !== contextManifest.role
    ) {
      fail("steer_work_session_mismatch");
    }
    return { job, session, steer, context_manifest: contextManifest };
  },

  sessionWork(value: unknown, expectedKind: "abort" | "dispose"): SessionWork {
    const parsed = record(value, "session_work");
    exactKeys(parsed, "session_work", ["job", "session"]);
    const job = parseAgentJob(parsed.job);
    const session = parseAgentSession(parsed.session);
    if (job.kind !== expectedKind) {
      fail("session_work_kind_invalid");
    }
    return { job, session };
  },

  findingSubmission(value: unknown): { readonly finding_id: string } {
    const parsed = record(value, "finding_submission_response");
    exactKeys(parsed, "finding_submission_response", ["finding_id", "event"]);
    // The event is intentionally opaque to the runner. Its event-chain
    // integrity is verified by the control plane, not duplicated here.
    record(parsed.event, "finding_submission_event");
    return { finding_id: identifier(parsed.finding_id, "finding_submission_id") };
  },

  candidateSubmission(value: unknown): { readonly candidateId: string } {
    const parsed = record(value, "candidate_submission_response");
    exactKeys(parsed, "candidate_submission_response", ["candidate", "verification_job"]);
    const candidate = record(parsed.candidate, "candidate_submission_candidate");
    return { candidateId: identifier(candidate.id, "candidate_submission_candidate_id") };
  },

  taskDelegation(value: unknown): { readonly task: WorkerTask; readonly session_job: AgentJob } {
    const parsed = record(value, "task_delegation_response");
    exactKeys(parsed, "task_delegation_response", ["task", "session_job"]);
    const task = parseWorkerTask(parsed.task);
    const sessionJob = parseAgentJob(parsed.session_job);
    if (task.role === "master" || sessionJob.kind !== "start_session" || sessionJob.run_id !== task.run_id) {
      fail("task_delegation_response_invalid");
    }
    return { task, session_job: sessionJob };
  },

  piRunState(value: unknown): PiRunState {
    const parsed = record(value, "pi_run_state");
    exactKeys(
      parsed,
      "pi_run_state",
      [
        "run_id", "run_status", "session_id", "session_state", "task_id", "task_state",
        "context_manifest_digest", "budget", "operator_hints", "branch_portfolio",
      ],
    );
    const budget = record(parsed.budget, "pi_run_state_budget");
    exactKeys(budget, "pi_run_state_budget", ["max_tool_calls", "max_cost_usd"]);
    const maxToolCalls = budget.max_tool_calls === null
      ? null
      : integer(budget.max_tool_calls, "pi_run_state_max_tool_calls");
    const maxCost = budget.max_cost_usd === null
      ? null
      : finiteNumber(budget.max_cost_usd, "pi_run_state_max_cost_usd");
    if (!Array.isArray(parsed.operator_hints) || parsed.operator_hints.length > 32) {
      fail("pi_run_state_operator_hints_invalid");
    }
    if (!Array.isArray(parsed.branch_portfolio) || parsed.branch_portfolio.length > 16) {
      fail("pi_run_state_branch_portfolio_invalid");
    }
    return {
      run_id: identifier(parsed.run_id, "pi_run_state_run_id"),
      run_status: identifier(parsed.run_status, "pi_run_state_run_status"),
      session_id: identifier(parsed.session_id, "pi_run_state_session_id"),
      session_state: oneOf(parsed.session_state, AGENT_SESSION_STATES, "pi_run_state_session_state"),
      task_id: identifier(parsed.task_id, "pi_run_state_task_id"),
      task_state: identifier(parsed.task_state, "pi_run_state_task_state"),
      context_manifest_digest: digest(parsed.context_manifest_digest, "pi_run_state_context_digest"),
      budget: { max_tool_calls: maxToolCalls, max_cost_usd: maxCost },
      operator_hints: parsed.operator_hints.map(parseOperatorHint),
      branch_portfolio: parsed.branch_portfolio.map(parseBranchPortfolioEntry),
    };
  },

  flagCapturePatterns(value: unknown): FlagCapturePatterns {
    const parsed = record(value, "flag_capture_patterns");
    exactKeys(parsed, "flag_capture_patterns", ["flag_capture_patterns"]);
    if (!Array.isArray(parsed.flag_capture_patterns) || parsed.flag_capture_patterns.length < 1 || parsed.flag_capture_patterns.length > 8) {
      fail("flag_capture_patterns_invalid");
    }
    return {
      flag_capture_patterns: parsed.flag_capture_patterns.map((pattern) => (
        text(pattern, "flag_capture_pattern", 512)
      )),
    };
  },

  toolGatewayResponse(value: unknown, expected: GatewayToolRequest): ToolGatewayResponse {
    return parseToolGatewayResponse(value, expected);
  },
};

/** Validate outbound data before the server performs its independent Pydantic validation. */
export function validateBridgeEvent(value: AgentBridgeEvent): AgentBridgeEvent {
  const base = record(value, "agent_bridge_event");
  const optional = [
    "message_digest", "preview", "tool_name", "input_digest", "output_digest", "input_tokens",
    "output_tokens", "cost_usd", "retry_attempt", "error_code",
    "prompt_contract_version", "prompt_contract_digest",
  ];
  exactKeys(base, "agent_bridge_event", ["sequence", "type", "session_id", "occurred_at"], optional);
  const type = oneOf(base.type, AGENT_EVENT_TYPES, "agent_bridge_event_type");
  const toolName = base.tool_name === undefined ? undefined : identifier(base.tool_name, "agent_bridge_event_tool_name");
  const errorCode = base.error_code === undefined ? undefined : identifier(base.error_code, "agent_bridge_event_error_code");
  const retryAttempt = base.retry_attempt === undefined ? undefined : integer(base.retry_attempt, "agent_bridge_event_retry_attempt", 1, 100);
  const promptContractVersion = base.prompt_contract_version === undefined
    ? undefined
    : integer(base.prompt_contract_version, "agent_bridge_event_prompt_contract_version", 1, 1_000);
  const promptContractDigest = base.prompt_contract_digest === undefined
    ? undefined
    : digest(base.prompt_contract_digest, "agent_bridge_event_prompt_contract_digest");
  if ((type === "agent.tool.started" || type === "agent.tool.completed") !== (toolName !== undefined)) {
    fail("agent_bridge_event_tool_shape_invalid");
  }
  if ((type === "agent.error") !== (errorCode !== undefined)) {
    fail("agent_bridge_event_error_shape_invalid");
  }
  if ((type === "agent.session.retry") !== (retryAttempt !== undefined)) {
    fail("agent_bridge_event_retry_shape_invalid");
  }
  if ((promptContractVersion === undefined) !== (promptContractDigest === undefined)) {
    fail("agent_bridge_event_prompt_contract_shape_invalid");
  }
  if (promptContractDigest !== undefined && type !== "agent.session.started") {
    fail("agent_bridge_event_prompt_contract_type_invalid");
  }
  const event: AgentBridgeEvent = {
    sequence: integer(base.sequence, "agent_bridge_event_sequence", 1, 10_000),
    type,
    session_id: identifier(base.session_id, "agent_bridge_event_session_id"),
    occurred_at: timestamp(base.occurred_at, "agent_bridge_event_occurred_at"),
    ...(base.message_digest === undefined ? {} : { message_digest: digest(base.message_digest, "agent_bridge_event_message_digest") }),
    ...(base.preview === undefined ? {} : { preview: text(base.preview, "agent_bridge_event_preview", 480) }),
    ...(toolName === undefined ? {} : { tool_name: toolName }),
    ...(base.input_digest === undefined ? {} : { input_digest: digest(base.input_digest, "agent_bridge_event_input_digest") }),
    ...(base.output_digest === undefined ? {} : { output_digest: digest(base.output_digest, "agent_bridge_event_output_digest") }),
    ...(base.input_tokens === undefined ? {} : { input_tokens: integer(base.input_tokens, "agent_bridge_event_input_tokens") }),
    ...(base.output_tokens === undefined ? {} : { output_tokens: integer(base.output_tokens, "agent_bridge_event_output_tokens") }),
    ...(base.cost_usd === undefined ? {} : { cost_usd: finiteNumber(base.cost_usd, "agent_bridge_event_cost_usd") }),
    ...(retryAttempt === undefined ? {} : { retry_attempt: retryAttempt }),
    ...(errorCode === undefined ? {} : { error_code: errorCode }),
    ...(promptContractVersion === undefined ? {} : { prompt_contract_version: promptContractVersion }),
    ...(promptContractDigest === undefined ? {} : { prompt_contract_digest: promptContractDigest }),
  };
  return event;
}

export function validateFindingSubmission(value: FindingSubmission): FindingSubmission {
  const parsed = record(value, "finding_submission");
  exactKeys(
    parsed,
    "finding_submission",
    ["session_id", "tool_call_id", "statement", "evidence_ids", "confidence", "disposition"],
  );
  const evidenceIds = identifierArray(parsed.evidence_ids, "finding_submission_evidence_ids", 32);
  if (evidenceIds.length === 0) {
    fail("finding_submission_evidence_required");
  }
  return {
    session_id: identifier(parsed.session_id, "finding_submission_session_id"),
    tool_call_id: identifier(parsed.tool_call_id, "finding_submission_tool_call_id"),
    statement: text(parsed.statement, "finding_submission_statement", 2_000),
    evidence_ids: evidenceIds,
    confidence: finiteNumber(parsed.confidence, "finding_submission_confidence", 0, 1),
    disposition: oneOf(
      parsed.disposition,
      ["supports", "contradicts", "inconclusive"] as const,
      "finding_submission_disposition",
    ),
  };
}

export function validateTaskDelegation(value: TaskDelegationRequest): TaskDelegationRequest {
  const parsed = record(value, "task_delegation");
  exactKeys(
    parsed,
    "task_delegation",
    ["tool_call_id", "role", "technique_id", "objective", "evidence_ids"],
  );
  const role = oneOf(parsed.role, AGENT_ROLES, "task_delegation_role");
  if (role === "master") {
    fail("task_delegation_master_role_denied");
  }
  const evidenceIds = identifierArray(parsed.evidence_ids, "task_delegation_evidence_ids", 32);
  if (evidenceIds.length === 0) {
    fail("task_delegation_evidence_required");
  }
  return {
    tool_call_id: identifier(parsed.tool_call_id, "task_delegation_tool_call_id"),
    role,
    technique_id: oneOf(
      parsed.technique_id,
      ["general.review", "web.path_traversal", "web.authz_boundary", "web.sqli_basic"] as const,
      "task_delegation_technique_id",
    ),
    objective: text(parsed.objective, "task_delegation_objective", 2_000),
    evidence_ids: evidenceIds,
  };
}

const PLAN_VARIABLE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const PLAN_PLACEHOLDER = /^\$\{([A-Za-z][A-Za-z0-9_]{0,63})\}$/;
const PLAN_FLAG_LIKE = /\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}/i;

function exploitPlanValue(value: unknown, name: string): string {
  const parsed = text(value, name, 4_096);
  if (/[\r\n\0]/.test(parsed) || PLAN_FLAG_LIKE.test(parsed)) {
    fail(`${name}_invalid`);
  }
  if (parsed.includes("${") && !PLAN_PLACEHOLDER.test(parsed)) {
    fail(`${name}_placeholder_invalid`);
  }
  return parsed;
}

function exploitPlanPath(value: unknown): string {
  const path = text(value, "exploit_plan_path", 2_048);
  if (
    !path.startsWith("/")
    || path.startsWith("//")
    || path.includes("\\")
    || path.split("/").includes("..")
    || /[\r\n\0?#]/.test(path)
    || path.includes("://")
  ) {
    fail("exploit_plan_path_invalid");
  }
  return path;
}

function exploitPlanStringMap(
  value: unknown,
  name: string,
  maximum: number,
  allowedKeys?: ReadonlySet<string>,
): Readonly<Record<string, string>> {
  const parsed = record(value, name);
  const entries = Object.entries(parsed);
  if (entries.length > maximum) {
    fail(`${name}_too_large`);
  }
  const result: Record<string, string> = {};
  for (const [key, entry] of entries) {
    if (!PLAN_VARIABLE.test(key) || (allowedKeys !== undefined && !allowedKeys.has(key))) {
      fail(`${name}_key_invalid`);
    }
    result[key] = exploitPlanValue(entry, `${name}_${key}`);
  }
  return result;
}

function parseExploitPlanDraft(value: unknown): ExploitPlanDraftV1 {
  const parsed = record(value, "exploit_plan");
  exactKeys(
    parsed,
    "exploit_plan",
    ["schema_version", "challenge_digest", "technique_id", "steps", "assertions", "evidence_refs"],
    ["variables"],
  );
  if (parsed.schema_version !== "ctfmesh.exploit-plan.v1") {
    fail("exploit_plan_schema_version_invalid");
  }
  const challengeDigest = digest(parsed.challenge_digest, "exploit_plan_challenge_digest");
  const techniqueId = oneOf(
    parsed.technique_id,
    ["web.path_traversal", "web.authz_boundary", "web.sqli_basic"] as const,
    "exploit_plan_technique_id",
  );
  const variables = parsed.variables === undefined
    ? {}
    : exploitPlanStringMap(parsed.variables, "exploit_plan_variables", 16);
  for (const value of Object.values(variables)) {
    if (PLAN_PLACEHOLDER.test(value)) {
      fail("exploit_plan_variable_reference_forbidden");
    }
  }
  if (!Array.isArray(parsed.steps) || parsed.steps.length < 1 || parsed.steps.length > 8) {
    fail("exploit_plan_steps_invalid");
  }
  let captures = 0;
  const steps = parsed.steps.map((entry, index) => {
    const step = record(entry, `exploit_plan_step_${index}`);
    exactKeys(step, `exploit_plan_step_${index}`, ["op", "path"], ["method", "query", "headers", "capture"]);
    if (step.op !== "http.request" || (step.method !== undefined && step.method !== "GET")) {
      fail("exploit_plan_operation_not_allowed");
    }
    const query = step.query === undefined
      ? {}
      : exploitPlanStringMap(step.query, `exploit_plan_step_${index}_query`, 32);
    const headers = step.headers === undefined
      ? {}
      : exploitPlanStringMap(
        step.headers,
        `exploit_plan_step_${index}_headers`,
        8,
        new Set(["accept", "content-type", "x-ctfmesh-user"]),
      );
    let capture: Readonly<{ flag: string }> | undefined;
    if (step.capture !== undefined) {
      const parsedCapture = record(step.capture, `exploit_plan_step_${index}_capture`);
      exactKeys(parsedCapture, `exploit_plan_step_${index}_capture`, ["flag"]);
      const flag = text(parsedCapture.flag, `exploit_plan_step_${index}_capture_flag`, 1_024);
      if (!flag.startsWith("regex:")) {
        fail("exploit_plan_capture_invalid");
      }
      captures += 1;
      capture = { flag };
    }
    return {
      op: "http.request" as const,
      ...(step.method === undefined ? {} : { method: "GET" as const }),
      path: exploitPlanPath(step.path),
      ...(Object.keys(query).length === 0 ? {} : { query }),
      ...(Object.keys(headers).length === 0 ? {} : { headers: headers as ExploitPlanHeaders }),
      ...(capture === undefined ? {} : { capture }),
    };
  });
  const references = steps.flatMap((step) => [...Object.values(step.query ?? {}), ...Object.values(step.headers ?? {})])
    .map((entry) => PLAN_PLACEHOLDER.exec(entry)?.[1])
    .filter((entry): entry is string => entry !== undefined);
  if (references.some((entry) => !(entry in variables))) {
    fail("exploit_plan_unknown_variable");
  }
  if (captures !== 1 || steps.at(-1)?.capture === undefined) {
    fail("exploit_plan_capture_invalid");
  }
  if (!Array.isArray(parsed.assertions) || parsed.assertions.length !== 1 || parsed.assertions[0] !== "capture.flag exists") {
    fail("exploit_plan_assertions_invalid");
  }
  const evidenceRefs = identifierArray(parsed.evidence_refs, "exploit_plan_evidence_refs", 32);
  if (evidenceRefs.length === 0) {
    fail("exploit_plan_evidence_refs_required");
  }
  return {
    schema_version: "ctfmesh.exploit-plan.v1",
    challenge_digest: challengeDigest,
    technique_id: techniqueId,
    ...(Object.keys(variables).length === 0 ? {} : { variables }),
    steps,
    assertions: ["capture.flag exists"],
    evidence_refs: evidenceRefs,
  };
}

export function validateCandidateSubmission(value: ExploitCandidateSubmission): ExploitCandidateSubmission {
  const parsed = record(value, "candidate_submission");
  exactKeys(parsed, "candidate_submission", ["session_id", "tool_call_id", "idempotency_key", "plan"]);
  const toolCallId = identifier(parsed.tool_call_id, "candidate_submission_tool_call_id");
  const idempotencyKey = identifier(parsed.idempotency_key, "candidate_submission_idempotency_key");
  if (toolCallId !== idempotencyKey) {
    fail("candidate_submission_idempotency_key_mismatch");
  }
  return {
    session_id: identifier(parsed.session_id, "candidate_submission_session_id"),
    tool_call_id: toolCallId,
    idempotency_key: idempotencyKey,
    plan: parseExploitPlanDraft(parsed.plan),
  };
}

/**
 * Revalidate the outbound gateway envelope even though TypeBox already checks
 * the SDK tool parameters. This prevents a future custom-tool refactor from
 * smuggling a slot name, URL, or unreviewed source operation into fetch.
 */
export function validateGatewayToolRequest(value: GatewayToolRequest): GatewayToolRequest {
  const parsed = record(value, "tool_gateway_request");
  exactKeys(parsed, "tool_gateway_request", ["session_id", "call"]);
  const call = record(parsed.call, "tool_gateway_call");
  exactKeys(
    call,
    "tool_gateway_call",
    ["schema_version", "tool_call_id", "idempotency_key", "tool_name", "tool_version", "arguments"],
  );
  if (integer(call.schema_version, "tool_gateway_call_schema_version", 1, 1) !== 1) {
    fail("tool_gateway_call_schema_version_invalid");
  }
  const toolCallId = identifier(call.tool_call_id, "tool_gateway_call_id");
  const idempotencyKey = identifier(call.idempotency_key, "tool_gateway_idempotency_key");
  if (toolCallId !== idempotencyKey) {
    fail("tool_gateway_idempotency_key_mismatch");
  }
  const toolName = oneOf(call.tool_name, GATEWAY_TOOL_NAMES, "tool_gateway_call_tool_name");
  if (call.tool_version !== "1.0.0") {
    fail("tool_gateway_call_version_invalid");
  }
  return {
    session_id: identifier(parsed.session_id, "tool_gateway_session_id"),
    call: {
      schema_version: 1,
      tool_call_id: toolCallId,
      idempotency_key: idempotencyKey,
      tool_name: toolName,
      tool_version: "1.0.0",
      arguments: parseGatewayArguments(toolName, call.arguments),
    },
  };
}
