import type {
  ConsoleSnapshot,
  HintCard,
  HintDirective,
  HintTemplate,
  SchedulerBranch,
} from "./types";

// These are an explicit client-side mirror of the server allowlist.  The UI
// never accepts a provider URL or arbitrary provider identifier, so a key
// entered here can only be sent back to CTFMesh's fixed server-side adapter.
export type ArchiveProviderId = "openai-responses" | "gemini-openai-compat" | "deepseek-chat";
export type ExactInstanceProviderId = "openai" | "gemini" | "deepseek";
// Presets are only conveniences. The API owns and validates the bounded
// numeric interval; keeping this a number lets Settings submit a smaller
// operator-tuned value without pretending the browser is the policy layer.
export type ArchiveTriageOutputTokenBudget = number;
export type ArchiveTriageTimeoutSeconds = number;

export interface ExactInstanceBudget {
  wallTimeSeconds: number;
  maxToolCalls: number;
  maxHttpRequests: number;
  maxCostUsd: number;
}

export interface RuntimeCapabilities {
  schemaVersion: "ctfmesh.runtime-capabilities/v1";
  archiveIntakeReady: boolean;
  providerTriageReady: boolean;
  exactInstance: {
    ready: boolean;
    missing: Array<"source_slots" | "tool_gateway" | "credential_lease" | "independent_verifier">;
  };
  power: {
    ready: boolean;
    missing: Array<"power_profile" | "sandboxd" | "flag_router">;
  };
}

export interface PowerRacerLaunch {
  label: "A" | "B" | "C";
  provider: ArchiveProviderId;
  model: string;
  temperature: number;
}

export interface PowerRunLaunch {
  target?: { host: string; port: number };
  authorizedTarget: boolean;
  contestOffline: boolean;
  /** Literal capture template such as `DH{*}` or `picoCTF{*}`, never a regular expression. */
  flagFormat?: string;
  /** Optional operator context for the first racer brief. */
  challengeDescription?: string;
  racers: PowerRacerLaunch[];
  providerKeys: Partial<Record<ArchiveProviderId, string>>;
  budget: { wallTimeSeconds: number; maxCostUsd: number; maxTurnCostUsd: number };
}

export interface PowerRun {
  runId: string;
  challengeId: string;
  status: string;
  progress: { consoleUrl: string; activityStreamUrl: string };
}

export interface CandidateReviewResolution {
  accepted: boolean;
  status: "paused" | "running" | "solved";
  resumedRacerCount?: number;
}

/** Credential-free identity needed to direct one operator suggestion to a racer. */
export interface PowerSession {
  id: string;
  label: "auto" | "A" | "B" | "C";
  role: "autoprompter" | "racer";
  state: "starting" | "ready" | "running" | "awaiting_review" | "aborting" | "aborted" | "failed";
}

export interface ArchiveProviderOption {
  id: ArchiveProviderId;
  label: string;
  keyLabel: string;
  outputContract: "strict_schema" | "json_validated";
}

export const ARCHIVE_PROVIDER_OPTIONS: readonly ArchiveProviderOption[] = [
  {
    id: "openai-responses",
    label: "OpenAI Responses",
    keyLabel: "OpenAI API key",
    outputContract: "strict_schema",
  },
  {
    id: "gemini-openai-compat",
    label: "Google Gemini",
    keyLabel: "Gemini API key",
    outputContract: "json_validated",
  },
  {
    id: "deepseek-chat",
    label: "DeepSeek Chat",
    keyLabel: "DeepSeek API key",
    outputContract: "json_validated",
  },
] as const;

export interface ChallengeManifest {
  apiVersion: "ctfmesh.io/v1alpha1";
  kind: "Challenge";
  metadata: {
    name: string;
    category: string;
    tags: string[];
  };
  spec: {
    mode: "assisted" | "contest";
    limits: {
      wall_time_seconds: number;
      max_tool_calls: number;
      max_http_requests: number;
      max_cost_usd: number;
    };
  };
}

export interface ChallengeRecord {
  id: string;
  name: string;
  digest: string;
  created_at: string;
  manifest: ChallengeManifest;
}

export interface ManifestValidation {
  valid: boolean;
  manifest?: ChallengeManifest;
  scope?: unknown[];
  errors?: Array<{ path: string; reason_code?: string; message: string }>;
}

export interface ArchiveInventoryFile {
  id: string;
  path: string;
  size_bytes: number;
  sha256: string;
  media_hint: string;
}

export interface ArchiveIntake {
  schema_version: "ctfmesh.archive-intake/v1";
  intake_id: string;
  created_at: string;
  boundary: {
    offline_only: boolean;
    network: string;
    target_network?: string;
    provider_egress?: string;
    code_execution: string;
    model_actions: string;
    verification: string;
  };
  archive: {
    name: string;
    format: string;
    size_bytes: number;
    sha256: string;
  };
  inventory: {
    file_count: number;
    expanded_size_bytes: number;
    media_type_counts: Record<string, number>;
    files: ArchiveInventoryFile[];
  };
  analysis: {
    static: {
      status: string;
      category_hints: Array<{ category: string; score: number }>;
      candidate_flags: {
        classification: string;
        count: number;
        initial_scan_bytes: number;
        initial_scan_complete: boolean;
        reveal_available: boolean;
      };
      nested_archive_count: number;
    };
    ai: ArchiveAiAnalysis;
  };
}

export interface ArchiveIntakeSummary {
  intake_id: string;
  created_at: string;
  name: string;
  format: string;
  file_count: number;
  expanded_size_bytes: number;
  category: string;
  ai_status: "not_requested" | "completed";
}

export interface TrackedRunSummary {
  id: string;
  challengeId: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface ArchiveAiAnalysis {
  status: "not_requested" | "completed" | string;
  provider?: string;
  model?: string;
  output_contract?: "strict_schema" | "json_validated" | string;
  category?: string;
  summary?: string;
  facts?: Array<{ statement: string; confidence: number; evidence_ids: string[] }>;
  hypotheses?: Array<{ statement: string; confidence: number; evidence_ids: string[] }>;
  next_actions?: Array<{ statement: string; evidence_ids: string[] }>;
  execution: string;
  verification: string;
}

export type ArchiveTriageProgressStage =
  | "request_accepted"
  | "receipt_loaded"
  | "evidence_prepared"
  | "provider_request_started"
  | "provider_response_received"
  | "result_validated"
  | "result_saved";

export interface ArchiveTriageProgressEvent {
  schemaVersion: "ctfmesh.archive-triage-stream/v1";
  sequence: number;
  stage: ArchiveTriageProgressStage;
  summary: string;
}

export interface CandidateFlagReveal {
  intake_id: string;
  classification: "unverified_input_candidate";
  candidate_flags: string[];
  candidate_count: number;
  scan_complete: boolean;
  message: string;
}

/** Raw values returned only after an explicit local Power-runtime reveal. */
export interface RuntimeCandidateReveal {
  runId: string;
  classification: "unverified_runtime_candidate";
  candidates: Array<{
    value: string;
    racerLabels: Array<"auto" | "A" | "B" | "C">;
    /** Opaque current-review sources. It is absent for historical scans. */
    racerSessionIds?: string[];
  }>;
  candidateCount: number;
  scannedArtifactCount: number;
  unavailableArtifactCount: number;
  scanComplete: boolean;
  message: string;
}

export interface VerifiedFlagReveal {
  flag: string;
  oneTime: true;
}

export interface HintCardDraft {
  template_id: string;
  directive: HintDirective;
  target_ref: string;
  priority: number;
  note: string;
}

interface RunResponse {
  id: string;
}

export interface ExactInstanceRun {
  runId: string;
  challengeId: string;
  status: string;
  scope: {
    entryOrigin: string;
    sourceSlot: "source-slot-1" | "source-slot-2";
  };
  progress: {
    consoleUrl: string;
    activityStreamUrl: string;
  };
}

/** The control plane accepted an asynchronous or already-complete cancellation. */
export interface RunCancellation {
  accepted: true;
  status: "cancellation_requested" | "cancelled";
  agentJobIds: string[];
}

interface ExactInstanceRunWire {
  run_id: string;
  challenge_id: string;
  status: string;
  scope: {
    entry_origin: string;
    source_slot: "source-slot-1" | "source-slot-2";
  };
  progress: {
    console_url: string;
    activity_stream_url: string;
  };
}

interface RunCancellationWire {
  accepted: true;
  status: "cancellation_requested" | "cancelled";
  agent_job_ids: string[];
}

// The API deliberately classifies provider failures without returning the
// provider's response body.  Keep the browser-side mirror equally closed: a
// malformed or future server response must not cause an arbitrary diagnostic
// (which could contain sensitive upstream content) to reach the operator UI.
const PUBLIC_PROVIDER_ERROR_CODES = new Set([
  "missing_api_key",
  "timeout",
  "transport_error",
  "http_error",
  "response_too_large",
  "triage_cites_unknown_evidence",
  "malformed_response",
  "missing_choice",
  "incomplete_response",
  "incomplete_max_output_tokens",
  "incomplete_content_filter",
  "missing_output_text",
  "provider_tool_call_forbidden",
  "malformed_structured_output",
  "triage_schema_violation",
  "model_refusal",
]);
const ARCHIVE_TRIAGE_PROGRESS_STAGES = new Set<ArchiveTriageProgressStage>([
  "request_accepted",
  "receipt_loaded",
  "evidence_prepared",
  "provider_request_started",
  "provider_response_received",
  "result_validated",
  "result_saved",
]);
const ARCHIVE_TRIAGE_PROGRESS_SUMMARIES: Readonly<Record<ArchiveTriageProgressStage, string>> = {
  request_accepted: "Request accepted.",
  receipt_loaded: "Local receipt loaded.",
  evidence_prepared: "Metadata evidence prepared.",
  provider_request_started: "Request sent to the AI provider.",
  provider_response_received: "Provider response received.",
  result_validated: "Structured response validated.",
  result_saved: "Triage receipt updated.",
};
const ARCHIVE_TRIAGE_STREAM_SCHEMA = "ctfmesh.archive-triage-stream/v1";
const MAX_ARCHIVE_TRIAGE_STREAM_EVENTS = 16;
const MAX_ARCHIVE_TRIAGE_STREAM_BUFFER_CHARS = 4 * 1024 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isChallengeManifest(value: unknown): value is ChallengeManifest {
  if (!isRecord(value) || value.apiVersion !== "ctfmesh.io/v1alpha1" || value.kind !== "Challenge") {
    return false;
  }
  const metadata = value.metadata;
  const spec = value.spec;
  if (!isRecord(metadata) || !isRecord(spec) || !isRecord(spec.limits)) {
    return false;
  }
  const limits = spec.limits;
  return (
    typeof metadata.name === "string" &&
    typeof metadata.category === "string" &&
    Array.isArray(metadata.tags) &&
    metadata.tags.every((tag) => typeof tag === "string") &&
    (spec.mode === "assisted" || spec.mode === "contest") &&
    isNumber(limits.wall_time_seconds) &&
    isNumber(limits.max_tool_calls) &&
    isNumber(limits.max_http_requests) &&
    isNumber(limits.max_cost_usd)
  );
}

function isChallengeRecord(value: unknown): value is ChallengeRecord {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.name === "string" &&
    typeof value.digest === "string" &&
    typeof value.created_at === "string" &&
    isChallengeManifest(value.manifest)
  );
}

function isRunResponse(value: unknown): value is RunResponse {
  return isRecord(value) && typeof value.id === "string" && value.id.length > 0;
}

function isExactInstanceRun(value: unknown): value is ExactInstanceRunWire {
  if (!isRecord(value) || typeof value.run_id !== "string" || typeof value.challenge_id !== "string") {
    return false;
  }
  const scope = value.scope;
  const progress = value.progress;
  return (
    typeof value.status === "string"
    && isRecord(scope)
    && typeof scope.entry_origin === "string"
    && (scope.source_slot === "source-slot-1" || scope.source_slot === "source-slot-2")
    && isRecord(progress)
    && typeof progress.console_url === "string"
    && typeof progress.activity_stream_url === "string"
  );
}

function isRunCancellation(value: unknown): value is RunCancellationWire {
  return isRecord(value)
    && value.accepted === true
    && (value.status === "cancellation_requested" || value.status === "cancelled")
    && Array.isArray(value.agent_job_ids)
    && value.agent_job_ids.every((jobId) => typeof jobId === "string");
}

const RUNTIME_MISSING_CODES = new Set([
  "source_slots",
  "tool_gateway",
  "credential_lease",
  "independent_verifier",
]);
const POWER_RUNTIME_MISSING_CODES = new Set(["power_profile", "sandboxd", "flag_router"]);

function isRuntimeCapabilities(value: unknown): value is {
  schema_version: "ctfmesh.runtime-capabilities/v1";
  archive_intake: { status: "ready" | "unavailable" };
  provider_triage: { status: "ready" | "unavailable" };
  exact_instance: { status: "ready" | "unavailable"; missing: string[] };
  power: { status: "ready" | "unavailable"; missing: string[] };
} {
  if (!isRecord(value) || value.schema_version !== "ctfmesh.runtime-capabilities/v1") return false;
  const archive = value.archive_intake;
  const provider = value.provider_triage;
  const exact = value.exact_instance;
  const power = value.power;
  return isRecord(archive)
    && (archive.status === "ready" || archive.status === "unavailable")
    && isRecord(provider)
    && (provider.status === "ready" || provider.status === "unavailable")
    && isRecord(exact)
    && (exact.status === "ready" || exact.status === "unavailable")
    && Array.isArray(exact.missing)
    && exact.missing.every((item) => typeof item === "string" && RUNTIME_MISSING_CODES.has(item))
    && isRecord(power)
    && (power.status === "ready" || power.status === "unavailable")
    && Array.isArray(power.missing)
    && power.missing.every(
      (item) => typeof item === "string" && POWER_RUNTIME_MISSING_CODES.has(item),
    );
}

function isStringRecord(value: unknown): value is Record<string, number> {
  return isRecord(value) && Object.values(value).every(isNumber);
}

function isArchiveInventoryFile(value: unknown): value is ArchiveInventoryFile {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.path === "string" &&
    isNumber(value.size_bytes) &&
    typeof value.sha256 === "string" &&
    typeof value.media_hint === "string"
  );
}

function isArchiveAiAnalysis(value: unknown): value is ArchiveAiAnalysis {
  if (!isRecord(value) || typeof value.status !== "string" || typeof value.execution !== "string" || typeof value.verification !== "string") {
    return false;
  }
  return (
    (value.provider === undefined || typeof value.provider === "string") &&
    (value.model === undefined || typeof value.model === "string") &&
    (value.output_contract === undefined || typeof value.output_contract === "string") &&
    (value.category === undefined || typeof value.category === "string") &&
    (value.summary === undefined || typeof value.summary === "string")
  );
}

// Every API payload is untrusted at this boundary. The server contract guarantees normal receipts
// are redacted; this guard verifies the shape before the UI renders that public representation.
function isArchiveIntake(value: unknown): value is ArchiveIntake {
  if (!isRecord(value) || value.schema_version !== "ctfmesh.archive-intake/v1" || typeof value.intake_id !== "string" || typeof value.created_at !== "string") {
    return false;
  }
  const { boundary, archive, inventory, analysis } = value;
  if (!isRecord(boundary) || !isRecord(archive) || !isRecord(inventory) || !isRecord(analysis)) {
    return false;
  }
  const staticAnalysis = analysis.static;
  return (
    typeof boundary.offline_only === "boolean" &&
    typeof boundary.network === "string" &&
    typeof boundary.code_execution === "string" &&
    typeof boundary.model_actions === "string" &&
    typeof boundary.verification === "string" &&
    typeof archive.name === "string" &&
    typeof archive.format === "string" &&
    isNumber(archive.size_bytes) &&
    typeof archive.sha256 === "string" &&
    isNumber(inventory.file_count) &&
    isNumber(inventory.expanded_size_bytes) &&
    isStringRecord(inventory.media_type_counts) &&
    Array.isArray(inventory.files) &&
    inventory.files.every(isArchiveInventoryFile) &&
    isRecord(staticAnalysis) &&
    typeof staticAnalysis.status === "string" &&
    Array.isArray(staticAnalysis.category_hints) &&
    staticAnalysis.category_hints.every(
      (item) => isRecord(item) && typeof item.category === "string" && isNumber(item.score),
    ) &&
    isRecord(staticAnalysis.candidate_flags) &&
    typeof staticAnalysis.candidate_flags.classification === "string" &&
    isNumber(staticAnalysis.candidate_flags.count) &&
    isNumber(staticAnalysis.candidate_flags.initial_scan_bytes) &&
    typeof staticAnalysis.candidate_flags.initial_scan_complete === "boolean" &&
    typeof staticAnalysis.candidate_flags.reveal_available === "boolean" &&
    isNumber(staticAnalysis.nested_archive_count) &&
    isArchiveAiAnalysis(analysis.ai)
  );
}

function isArchiveIntakeSummary(value: unknown): value is ArchiveIntakeSummary {
  return (
    isRecord(value) &&
    typeof value.intake_id === "string" &&
    typeof value.created_at === "string" &&
    typeof value.name === "string" &&
    typeof value.format === "string" &&
    isNumber(value.file_count) &&
    isNumber(value.expanded_size_bytes) &&
    typeof value.category === "string" &&
    (value.ai_status === "not_requested" || value.ai_status === "completed")
  );
}

function isTrackedRunRecord(value: unknown): value is {
  id: string;
  challenge_id: string;
  status: string;
  created_at: string;
  updated_at: string;
} {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.challenge_id === "string" &&
    typeof value.status === "string" &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function isArchiveTriageProgressEvent(value: unknown): value is {
  schema_version: string;
  kind: "progress";
  sequence: number;
  stage: ArchiveTriageProgressStage;
  summary: string;
} {
  return (
    isRecord(value) &&
    value.schema_version === ARCHIVE_TRIAGE_STREAM_SCHEMA &&
    value.kind === "progress" &&
    Number.isInteger(value.sequence) &&
    (value.sequence as number) > 0 &&
    typeof value.stage === "string" &&
    ARCHIVE_TRIAGE_PROGRESS_STAGES.has(value.stage as ArchiveTriageProgressStage) &&
    typeof value.summary === "string" &&
    value.summary === ARCHIVE_TRIAGE_PROGRESS_SUMMARIES[
      value.stage as ArchiveTriageProgressStage
    ]
  );
}

function safeProviderErrorSuffix(value: unknown): string {
  if (typeof value !== "string" || !PUBLIC_PROVIDER_ERROR_CODES.has(value)) {
    return "";
  }
  // These labels are derived from a small server-owned enum. They make the
  // common retry case actionable without reflecting arbitrary upstream text.
  if (value === "incomplete_max_output_tokens") {
    return " · provider: output budget reached; retry";
  }
  if (value === "incomplete_content_filter") {
    return " · provider: response filtered";
  }
  if (value === "timeout") {
    return " · provider deadline reached; choose Unlimited in Settings, then retry";
  }
  return ` · provider: ${value}`;
}

function isCandidateFlagReveal(value: unknown): value is CandidateFlagReveal {
  return (
    isRecord(value) &&
    typeof value.intake_id === "string" &&
    value.classification === "unverified_input_candidate" &&
    Array.isArray(value.candidate_flags) &&
    value.candidate_flags.every((item) => typeof item === "string") &&
    isNumber(value.candidate_count) &&
    typeof value.scan_complete === "boolean" &&
    typeof value.message === "string"
  );
}

function isRuntimeCandidateReveal(value: unknown): value is {
  run_id: string;
  classification: "unverified_runtime_candidate";
  candidates: Array<{
    value: string;
    racer_labels: Array<"auto" | "A" | "B" | "C">;
    racer_session_ids?: string[];
  }>;
  candidate_count: number;
  scanned_artifact_count: number;
  unavailable_artifact_count: number;
  scan_complete: boolean;
  message: string;
} {
  return (
    isRecord(value) &&
    typeof value.run_id === "string" &&
    value.classification === "unverified_runtime_candidate" &&
    Array.isArray(value.candidates) &&
    value.candidates.every(
      (item) =>
        isRecord(item) &&
        typeof item.value === "string" &&
        Array.isArray(item.racer_labels) &&
        item.racer_labels.every(
          (label) => label === "auto" || label === "A" || label === "B" || label === "C",
        )
        && (item.racer_session_ids === undefined
          || (Array.isArray(item.racer_session_ids)
            && item.racer_session_ids.every((sessionId) => typeof sessionId === "string"))),
    ) &&
    isNumber(value.candidate_count) &&
    isNumber(value.scanned_artifact_count) &&
    isNumber(value.unavailable_artifact_count) &&
    typeof value.scan_complete === "boolean" &&
    typeof value.message === "string"
  );
}

function isVerifiedFlagReveal(value: unknown): value is { flag: string; one_time: true } {
  return isRecord(value) && typeof value.flag === "string" && value.one_time === true;
}

function isHintDirective(value: unknown): value is HintDirective {
  return value === "explore" || value === "prioritize" || value === "require_probe" || value === "avoid";
}

function isHintStatus(value: unknown): boolean {
  return value === "active"
    || value === "fulfilled"
    || value === "contradicted"
    || value === "dismissed"
    || value === "expired";
}

function isHintTemplate(value: unknown): value is HintTemplate {
  return (
    isRecord(value)
    && typeof value.id === "string"
    && isNumber(value.version)
    && typeof value.label === "string"
    && typeof value.technique_id === "string"
    && typeof value.category === "string"
    && isHintDirective(value.default_directive)
    && Array.isArray(value.recommended_roles)
    && value.recommended_roles.every((role) => typeof role === "string")
    && Array.isArray(value.recommended_tools)
    && value.recommended_tools.every((tool) => typeof tool === "string")
    && typeof value.branch_seed === "string"
    && Array.isArray(value.falsifiers)
    && value.falsifiers.every((falsifier) => typeof falsifier === "string")
  );
}

function isHintCard(value: unknown): value is HintCard {
  return (
    isRecord(value)
    && typeof value.id === "string"
    && typeof value.run_id === "string"
    && typeof value.template_id === "string"
    && isNumber(value.template_version)
    && typeof value.technique_id === "string"
    && typeof value.category === "string"
    && isHintDirective(value.directive)
    && typeof value.target_ref === "string"
    && isNumber(value.priority)
    && typeof value.note === "string"
    && value.epistemic_status === "human_hypothesis"
    && isHintStatus(value.status)
    && Array.isArray(value.evidence_refs)
    && value.evidence_refs.every((reference) => typeof reference === "string")
    && typeof value.actor_id === "string"
    && typeof value.created_at === "string"
    && typeof value.updated_at === "string"
  );
}

function isSchedulerBranch(value: unknown): value is SchedulerBranch {
  return (
    isRecord(value)
    && typeof value.id === "string"
    && typeof value.run_id === "string"
    && typeof value.family === "string"
    && (value.state === "active"
      || value.state === "stalled"
      || value.state === "suspended"
      || value.state === "completed"
      || value.state === "failed")
    && typeof value.technique_id === "string"
    && typeof value.branch_scope === "string"
    && isNumber(value.priority)
    && isNumber(value.novelty)
    && isNumber(value.evidence_strength)
    && isNumber(value.expected_value)
    && isNumber(value.normalized_cost)
    && isNumber(value.repetition_penalty)
    && isNumber(value.consecutive_no_observation)
    && isNumber(value.score)
    && typeof value.created_at === "string"
    && typeof value.updated_at === "string"
  );
}

function isConsoleSnapshot(value: unknown): value is ConsoleSnapshot {
  if (!isRecord(value) || value.schema_version !== "1" || !isRecord(value.run)) {
    return false;
  }

  const { run } = value;
  const triage = isRecord(run.triage) ? run.triage : null;

  return (
    typeof run.id === "string" &&
    typeof run.category === "string" &&
    typeof run.status === "string" &&
    typeof run.current_stage === "string" &&
    typeof run.target_scope === "string" &&
    typeof run.scope_kind === "string" &&
    typeof run.execution_mode === "string" &&
    typeof run.provider_label === "string" &&
    triage !== null &&
    typeof triage.read_only === "boolean" &&
    typeof triage.actions_executed === "number" &&
    typeof triage.verification_attempted === "boolean" &&
    Array.isArray(triage.selected_skill_ids) &&
    triage.selected_skill_ids.every((skill) => typeof skill === "string") &&
    Array.isArray(value.budgets) &&
    Array.isArray(value.facts) &&
    Array.isArray(value.hypotheses) &&
    Array.isArray(value.experiments) &&
    Array.isArray(value.events) &&
    Array.isArray(value.artifacts) &&
    isRecord(value.verification) &&
    Array.isArray(value.custody) &&
    Array.isArray(value.hints) &&
    value.hints.every(isHintCard) &&
    Array.isArray(value.branches) &&
    value.branches.every(isSchedulerBranch)
  );
}

function providerErrorSuffix(detail: Record<string, unknown>): string {
  // This endpoint's only safe diagnostic is the server-owned provider code.
  // Never surface an upstream response, an arbitrary `details` value, or a
  // value not present in the reviewed allowlist above.
  if (detail.code !== "archive_triage_provider_failed" || !isRecord(detail.details)) {
    return "";
  }
  const providerCode = detail.details.provider_code;
  return safeProviderErrorSuffix(providerCode);
}

async function decodeJson(response: Response): Promise<unknown> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    if (!response.ok) {
      throw new Error(`Request failed with status ${response.status}.`);
    }
    throw new Error("The API returned an unreadable response.");
  }
  if (!response.ok) {
    // Only the documented public error pair is surfaced; malformed responses get a generic status.
    const detail = isRecord(body) && isRecord(body.detail) ? body.detail : null;
    if (detail && typeof detail.code === "string") {
      const message = typeof detail.message === "string" ? detail.message : "Request failed";
      throw new Error(`${message} (${detail.code}${providerErrorSuffix(detail)})`);
    }
    throw new Error(`Request failed with status ${response.status}.`);
  }
  return body;
}

export async function validateManifest(manifest: unknown, signal?: AbortSignal): Promise<ManifestValidation> {
  const response = await fetch("/v1/challenges/validate", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ manifest }),
    signal,
  });
  const body = await decodeJson(response);
  if (!isRecord(body) || typeof body.valid !== "boolean") {
    throw new Error("The API did not return a valid manifest result.");
  }
  const errors = Array.isArray(body.errors)
    ? body.errors.filter(
      (item): item is { path: string; reason_code?: string; message: string } =>
        isRecord(item) && typeof item.path === "string" && typeof item.message === "string",
    )
    : undefined;
  return {
    valid: body.valid,
    manifest: isChallengeManifest(body.manifest) ? body.manifest : undefined,
    scope: Array.isArray(body.scope) ? body.scope : undefined,
    errors,
  };
}

export async function importChallenge(manifest: ChallengeManifest): Promise<ChallengeRecord> {
  const response = await fetch("/v1/challenges", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ manifest }),
  });
  const body = await decodeJson(response);
  if (!isChallengeRecord(body)) {
    throw new Error("The API did not return an imported challenge record.");
  }
  return body;
}

export async function listChallenges(signal?: AbortSignal): Promise<ChallengeRecord[]> {
  const response = await fetch("/v1/challenges", {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isRecord(body) || !Array.isArray(body.items) || !body.items.every(isChallengeRecord)) {
    throw new Error("The API did not return a valid challenge list.");
  }
  return body.items;
}

export async function uploadArchive(file: File, signal?: AbortSignal): Promise<ArchiveIntake> {
  // Send raw bytes so the API can stream and enforce archive limits; browser checks are convenience only.
  const response = await fetch("/v1/archive-intakes", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": file.type || "application/octet-stream",
      "X-Archive-Name": file.name,
    },
    body: file,
    signal,
  });
  const body = await decodeJson(response);
  if (!isArchiveIntake(body)) {
    throw new Error("The API did not return a valid archive intake record.");
  }
  return body;
}

export async function listArchiveIntakes(signal?: AbortSignal): Promise<ArchiveIntakeSummary[]> {
  const response = await fetch("/v1/archive-intakes?limit=50", {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isRecord(body) || !Array.isArray(body.items) || !body.items.every(isArchiveIntakeSummary)) {
    throw new Error("The API did not return a valid archive session history.");
  }
  return body.items;
}

export async function removeArchiveIntake(
  intakeId: string,
  signal?: AbortSignal,
): Promise<void> {
  // The exact server-issued ID is repeated as an explicit destructive
  // confirmation. Hide never calls this endpoint.
  const response = await fetch(`/v1/archive-intakes/${encodeURIComponent(intakeId)}`, {
    method: "DELETE",
    headers: {
      Accept: "application/json",
      "X-Confirm-Remove": intakeId,
    },
    signal,
  });
  const body = await decodeJson(response);
  if (
    !isRecord(body) ||
    body.removed !== true ||
    body.intake_id !== intakeId
  ) {
    throw new Error("The API did not confirm permanent archive removal.");
  }
}

export async function listTrackedRuns(signal?: AbortSignal): Promise<TrackedRunSummary[]> {
  const response = await fetch("/v1/runs?limit=50", {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isRecord(body) || !Array.isArray(body.items) || !body.items.every(isTrackedRunRecord)) {
    throw new Error("The API did not return a valid run session history.");
  }
  return body.items.map((item) => ({
    id: item.id,
    challengeId: item.challenge_id,
    status: item.status,
    createdAt: item.created_at,
    updatedAt: item.updated_at,
  }));
}

/** Read configuration presence only; the response contains no service URL or credential. */
export async function getRuntimeCapabilities(signal?: AbortSignal): Promise<RuntimeCapabilities> {
  const response = await fetch("/v1/runtime/capabilities", {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isRuntimeCapabilities(body)) {
    throw new Error("The API did not return valid runtime capabilities.");
  }
  return {
    schemaVersion: body.schema_version,
    archiveIntakeReady: body.archive_intake.status === "ready",
    providerTriageReady: body.provider_triage.status === "ready",
    exactInstance: {
      ready: body.exact_instance.status === "ready",
      missing: body.exact_instance.missing as RuntimeCapabilities["exactInstance"]["missing"],
    },
    power: {
      ready: body.power.status === "ready",
      missing: body.power.missing as RuntimeCapabilities["power"]["missing"],
    },
  };
}

export async function getArchiveIntake(
  intakeId: string,
  signal?: AbortSignal,
): Promise<ArchiveIntake> {
  const response = await fetch(`/v1/archive-intakes/${encodeURIComponent(intakeId)}`, {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isArchiveIntake(body)) {
    throw new Error("The API did not return a valid archive intake record.");
  }
  return body;
}

export async function runArchiveTriage(
  intakeId: string,
  request: {
    provider: ArchiveProviderId;
    model: string;
    apiKey: string;
    providerEgressAcknowledged: true;
    maxOutputTokens: ArchiveTriageOutputTokenBudget;
    timeoutSeconds: ArchiveTriageTimeoutSeconds;
  },
  onProgress?: (event: ArchiveTriageProgressEvent) => void,
  signal?: AbortSignal,
): Promise<ArchiveIntake> {
  // The same one-shot request carries both the temporary key and a bounded
  // progress response. No key or provider body appears in the NDJSON frames.
  const response = await fetch(
    `/v1/archive-intakes/${encodeURIComponent(intakeId)}/triage/stream`,
    {
      method: "POST",
      headers: { Accept: "application/x-ndjson", "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: request.provider,
        model: request.model,
        api_key: request.apiKey,
        provider_egress_acknowledged: request.providerEgressAcknowledged,
        max_output_tokens: request.maxOutputTokens,
        timeout_seconds: request.timeoutSeconds,
      }),
      signal,
    },
  );
  if (!response.ok) {
    await decodeJson(response);
    throw new Error(`Request failed with status ${response.status}.`);
  }
  if (!response.headers.get("content-type")?.includes("application/x-ndjson") || !response.body) {
    throw new Error("The API did not return a readable AI progress stream.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let expectedSequence = 1;
  let eventCount = 0;
  let terminal = false;
  let result: ArchiveIntake | null = null;

  function consumeLine(line: string): void {
    if (!line || terminal) {
      if (line) {
        throw new Error("The API returned an invalid AI progress sequence.");
      }
      return;
    }
    eventCount += 1;
    if (eventCount > MAX_ARCHIVE_TRIAGE_STREAM_EVENTS) {
      throw new Error("The API returned too many AI progress events.");
    }
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new Error("The API returned malformed AI progress data.");
    }
    if (!isRecord(value) || value.sequence !== expectedSequence) {
      throw new Error("The API returned an invalid AI progress sequence.");
    }
    expectedSequence += 1;
    if (isArchiveTriageProgressEvent(value)) {
      onProgress?.({
        schemaVersion: ARCHIVE_TRIAGE_STREAM_SCHEMA,
        sequence: value.sequence,
        stage: value.stage,
        // Render the reviewed browser-owned mirror, never arbitrary stream text.
        summary: ARCHIVE_TRIAGE_PROGRESS_SUMMARIES[value.stage],
      });
      return;
    }
    if (value.schema_version !== ARCHIVE_TRIAGE_STREAM_SCHEMA) {
      throw new Error("The API returned an unsupported AI progress contract.");
    }
    if (value.kind === "result" && isArchiveIntake(value.intake)) {
      terminal = true;
      result = value.intake;
      return;
    }
    if (
      value.kind === "error" &&
      typeof value.code === "string" &&
      typeof value.message === "string"
    ) {
      terminal = true;
      throw new Error(
        `${value.message} (${value.code}${safeProviderErrorSuffix(value.provider_code)})`,
      );
    }
    throw new Error("The API returned an invalid AI progress event.");
  }

  try {
    while (true) {
      const { done, value } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      if (buffer.length > MAX_ARCHIVE_TRIAGE_STREAM_BUFFER_CHARS) {
        throw new Error("The API returned an oversized AI progress event.");
      }
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      lines.forEach((line) => consumeLine(line.endsWith("\r") ? line.slice(0, -1) : line));
      if (done) {
        if (buffer) {
          consumeLine(buffer.endsWith("\r") ? buffer.slice(0, -1) : buffer);
        }
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  if (!terminal || !result) {
    throw new Error("The AI progress stream ended before a result was available.");
  }
  return result;
}

export async function revealArchiveCandidateFlags(intakeId: string): Promise<CandidateFlagReveal> {
  // Candidate values are deliberately absent from the normal receipt; confirmation makes disclosure explicit.
  const response = await fetch(
    `/v1/archive-intakes/${encodeURIComponent(intakeId)}/candidate-flags/reveal`,
    {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    },
  );
  const body = await decodeJson(response);
  if (!isCandidateFlagReveal(body)) {
    throw new Error("The API did not return a valid candidate reveal.");
  }
  return body;
}

export async function revealRuntimeCandidateFlags(runId: string): Promise<RuntimeCandidateReveal> {
  // This remains available for historical local review. Active Power runs use
  // loadRuntimeCandidateReviewQueue() after the durable candidate gate pauses.
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/candidate-flags/reveal`,
    {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
      cache: "no-store",
    },
  );
  const body = await decodeJson(response);
  if (!isRuntimeCandidateReveal(body)) {
    throw new Error("The API did not return a valid runtime candidate reveal.");
  }
  return {
    runId: body.run_id,
    classification: body.classification,
    candidates: body.candidates.map((candidate) => ({
      value: candidate.value,
      racerLabels: candidate.racer_labels,
      ...(candidate.racer_session_ids === undefined
        ? {}
        : { racerSessionIds: candidate.racer_session_ids }),
    })),
    candidateCount: body.candidate_count,
    scannedArtifactCount: body.scanned_artifact_count,
    unavailableArtifactCount: body.unavailable_artifact_count,
    scanComplete: body.scan_complete,
    message: body.message,
  };
}

export async function loadRuntimeCandidateReviewQueue(
  runId: string,
): Promise<RuntimeCandidateReveal> {
  // The queue is scoped to the immutable output that opened the current
  // candidate gate. It is response-only and must never be browser cached.
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/candidate-review/queue`,
    {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    },
  );
  const body = await decodeJson(response);
  if (!isRuntimeCandidateReveal(body)) {
    throw new Error("The API did not return a valid runtime candidate queue.");
  }
  return {
    runId: body.run_id,
    classification: body.classification,
    candidates: body.candidates.map((candidate) => ({
      value: candidate.value,
      racerLabels: candidate.racer_labels,
      ...(candidate.racer_session_ids === undefined
        ? {}
        : { racerSessionIds: candidate.racer_session_ids }),
    })),
    candidateCount: body.candidate_count,
    scannedArtifactCount: body.scanned_artifact_count,
    unavailableArtifactCount: body.unavailable_artifact_count,
    scanComplete: body.scan_complete,
    message: body.message,
  };
}

function candidateReviewIdempotencyKey(action: "confirm" | "reject"): string {
  const suffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `power-candidate-${action}-${suffix}`.slice(0, 199);
}

function candidateReviewResolution(value: unknown): CandidateReviewResolution {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The API did not return a valid candidate-review result.");
  }
  const payload = value as Record<string, unknown>;
  if (
    typeof payload.accepted !== "boolean"
    || (payload.status !== "paused" && payload.status !== "running" && payload.status !== "solved")
    || (payload.resumed_racer_count !== undefined
      && (typeof payload.resumed_racer_count !== "number"
        || !Number.isSafeInteger(payload.resumed_racer_count)
        || payload.resumed_racer_count < 0))
  ) {
    throw new Error("The API did not return a valid candidate-review result.");
  }
  return {
    accepted: payload.accepted,
    status: payload.status,
    ...(payload.resumed_racer_count === undefined
      ? {}
      : { resumedRacerCount: payload.resumed_racer_count as number }),
  };
}

/** Send one browser-selected runtime value to the independent flag router. */
export async function confirmRuntimeCandidateReview(
  runId: string,
  candidate: string,
  sessionId?: string,
): Promise<CandidateReviewResolution> {
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/candidate-review/confirm`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": candidateReviewIdempotencyKey("confirm"),
      },
      body: JSON.stringify({ confirm: true, candidate, ...(sessionId ? { session_id: sessionId } : {}) }),
      cache: "no-store",
    },
  );
  return candidateReviewResolution(await decodeJson(response));
}

/** Reject the current candidate gate and enqueue a fresh racer continuation. */
export async function rejectRuntimeCandidateReview(
  runId: string,
  sessionId?: string,
): Promise<CandidateReviewResolution> {
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/candidate-review/reject`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": candidateReviewIdempotencyKey("reject"),
      },
      body: JSON.stringify({ confirm: true, ...(sessionId ? { session_id: sessionId } : {}) }),
      cache: "no-store",
    },
  );
  return candidateReviewResolution(await decodeJson(response));
}

export async function revealVerifiedFlag(runId: string): Promise<VerifiedFlagReveal> {
  // The raw value exists only in an API process-memory lease and is consumed
  // by this request. Keep this response out of browser caches and history.
  const response = await fetch(`/v1/runs/${encodeURIComponent(runId)}/flag-reveal`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true }),
    cache: "no-store",
  });
  const body = await decodeJson(response);
  if (!isVerifiedFlagReveal(body)) {
    throw new Error("The API did not return a valid verified flag reveal.");
  }
  return { flag: body.flag, oneTime: body.one_time };
}

function exactInstanceProvider(provider: ArchiveProviderId): ExactInstanceProviderId {
  switch (provider) {
    case "openai-responses":
      return "openai";
    case "gemini-openai-compat":
      return "gemini";
    case "deepseek-chat":
      return "deepseek";
  }
}

function exactRunIdempotencyKey(): string {
  // This retry key identifies only one browser action. It deliberately omits
  // archive content, target URL, model ID and the one-time provider key.
  const suffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `ui-exact-run-${suffix}`;
}

export async function launchExactInstanceRun(
  intakeId: string,
  request: {
    entryUrl: string;
    flagFormat?: string;
    provider: ArchiveProviderId;
    model: string;
    apiKey: string;
    providerEgressAcknowledged: true;
    targetAccessAcknowledged: true;
    budget: ExactInstanceBudget;
  },
): Promise<ExactInstanceRun> {
  // The browser never receives a provider base URL or a source-slot path.
  // The API translates the reviewed provider name, constructs the manifest,
  // then drops the request-local key after depositing a Pi memory lease.
  const response = await fetch(`/v1/archive-intakes/${encodeURIComponent(intakeId)}/runs`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": exactRunIdempotencyKey(),
    },
    body: JSON.stringify({
      target: {
        entry_url: request.entryUrl,
        ...(request.flagFormat?.trim() ? { flag_format: request.flagFormat.trim() } : {}),
      },
      execution: {
        provider: exactInstanceProvider(request.provider),
        model: request.model,
        api_key: request.apiKey,
        provider_egress_acknowledged: request.providerEgressAcknowledged,
        target_access_acknowledged: request.targetAccessAcknowledged,
      },
      budget: {
        wall_time_seconds: request.budget.wallTimeSeconds,
        max_tool_calls: request.budget.maxToolCalls,
        max_http_requests: request.budget.maxHttpRequests,
        max_cost_usd: request.budget.maxCostUsd,
      },
    }),
  });
  const body = await decodeJson(response);
  if (!isExactInstanceRun(body)) {
    throw new Error("The API did not return a valid scoped run.");
  }
  return {
    runId: body.run_id,
    challengeId: body.challenge_id,
    status: body.status,
    scope: {
      entryOrigin: body.scope.entry_origin,
      sourceSlot: body.scope.source_slot,
    },
    progress: {
      consoleUrl: body.progress.console_url,
      activityStreamUrl: body.progress.activity_stream_url,
    },
  };
}

function powerRunIdempotencyKey(): string {
  const suffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `ui-power-run-${suffix}`;
}

function isPowerRun(value: unknown): value is {
  run_id: string;
  challenge_id: string;
  status: string;
  progress: { console_url: string; activity_stream_url: string };
} {
  return isRecord(value)
    && typeof value.run_id === "string"
    && typeof value.challenge_id === "string"
    && typeof value.status === "string"
    && isRecord(value.progress)
    && typeof value.progress.console_url === "string"
    && typeof value.progress.activity_stream_url === "string";
}

function isPowerSession(value: unknown): value is {
  id: string;
  label: "auto" | "A" | "B" | "C";
  role: "autoprompter" | "racer";
  state: "starting" | "ready" | "running" | "aborting" | "aborted" | "failed";
} {
  return isRecord(value)
    && typeof value.id === "string"
    && (value.label === "auto" || value.label === "A" || value.label === "B" || value.label === "C")
    && (value.role === "autoprompter" || value.role === "racer")
    && (value.state === "starting" || value.state === "ready" || value.state === "running"
      || value.state === "awaiting_review" || value.state === "aborting" || value.state === "aborted" || value.state === "failed");
}

function powerSteerIdempotencyKey(): string {
  const suffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `ui-power-steer-${suffix}`;
}

/** Load session IDs without exposing a credential, workspace ID, or transcript. */
export async function listPowerSessions(runId: string, signal?: AbortSignal): Promise<PowerSession[]> {
  const response = await fetch(`/v1/runs/${encodeURIComponent(runId)}/power-sessions`, {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isRecord(body) || !Array.isArray(body.items) || !body.items.every(isPowerSession)) {
    throw new Error("The API did not return valid Power sessions.");
  }
  return body.items.map((item) => ({
    id: item.id,
    label: item.label,
    role: item.role,
    state: item.state,
  }));
}

/**
 * Renew broker-only credentials for an active Power run.
 *
 * The provider key originates from the browser's local vault on every call;
 * neither this API helper nor its response retains it. The backend derives
 * the allowed session/provider/model tuple from durable, key-free metadata.
 */
export async function refreshPowerCredentials(
  runId: string,
  providerKeys: Partial<Record<ArchiveProviderId, string>>,
): Promise<number> {
  const response = await fetch(`/v1/runs/${encodeURIComponent(runId)}/power-credentials`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ provider_keys: providerKeys }),
    cache: "no-store",
  });
  const body = await decodeJson(response);
  if (
    !isRecord(body)
    || body.accepted !== true
    || !isNumber(body.refreshed_sessions)
    || !Number.isInteger(body.refreshed_sessions)
    || body.refreshed_sessions < 0
  ) {
    throw new Error("The API did not renew the local Power credential.");
  }
  return body.refreshed_sessions;
}

/** Queue an operator suggestion; Pi delivers it before its next model request. */
export async function steerPowerSession(
  runId: string,
  sessionId: string,
  message: string,
): Promise<void> {
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/power-sessions/${encodeURIComponent(sessionId)}/steer`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": powerSteerIdempotencyKey(),
      },
      body: JSON.stringify({ message }),
    },
  );
  const body = await decodeJson(response);
  if (!isRecord(body) || body.accepted !== true || typeof body.steer_id !== "string") {
    throw new Error("The API did not accept the racer suggestion.");
  }
}

/** Start exactly three isolated Power racers using Settings-owned vault keys. */
export async function launchPowerRun(intakeId: string, request: PowerRunLaunch): Promise<PowerRun> {
  const response = await fetch(`/v1/archive-intakes/${encodeURIComponent(intakeId)}/power-runs`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": powerRunIdempotencyKey(),
    },
    body: JSON.stringify({
      ...(request.target ? { target: request.target } : {}),
      authorized_target: request.authorizedTarget,
      open_egress: false,
      racer_count: 3,
      contest_offline: request.contestOffline,
      ...(request.flagFormat?.trim() ? { flag_format: request.flagFormat.trim() } : {}),
      ...(request.challengeDescription?.trim()
        ? { challenge_description: request.challengeDescription.trim() }
        : {}),
      racers: request.racers.map((racer) => ({
        label: racer.label,
        provider: racer.provider,
        model: racer.model,
        temperature: racer.temperature,
      })),
      provider_keys: request.providerKeys,
      budget: {
        wall_time_seconds: request.budget.wallTimeSeconds,
        max_cost_usd: request.budget.maxCostUsd,
        max_turn_cost_usd: request.budget.maxTurnCostUsd,
      },
    }),
  });
  const body = await decodeJson(response);
  if (!isPowerRun(body)) {
    throw new Error("The API did not return a valid Power run.");
  }
  return {
    runId: body.run_id,
    challengeId: body.challenge_id,
    status: body.status,
    progress: {
      consoleUrl: body.progress.console_url,
      activityStreamUrl: body.progress.activity_stream_url,
    },
  };
}

/**
 * Ask the durable control plane to stop a run. The browser never aborts Pi
 * directly; a live session receives a separately leased abort job instead.
 */
export async function cancelTrackedRun(runId: string): Promise<RunCancellation> {
  const response = await fetch(`/v1/runs/${encodeURIComponent(runId)}/cancel`, {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  const body = await decodeJson(response);
  if (!isRunCancellation(body)) {
    throw new Error("The API did not accept run cancellation.");
  }
  return {
    accepted: true,
    status: body.status,
    agentJobIds: body.agent_job_ids,
  };
}

export async function createTrackedRun(challenge: ChallengeRecord): Promise<string> {
  const { limits } = challenge.manifest.spec;
  const response = await fetch("/v1/runs", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: challenge.id,
      mode: challenge.manifest.spec.mode,
      provider: "operator-pending",
      budget: {
        wall_time_seconds: limits.wall_time_seconds,
        max_tool_calls: limits.max_tool_calls,
        max_http_requests: limits.max_http_requests,
        max_cost_usd: limits.max_cost_usd,
      },
    }),
  });
  const body = await decodeJson(response);
  if (!isRunResponse(body)) {
    throw new Error("The API did not return a valid run ID.");
  }
  return body.id;
}

export async function getConsoleSnapshot(
  runId: string,
  signal?: AbortSignal,
): Promise<ConsoleSnapshot> {
  const response = await fetch(`/v1/runs/${encodeURIComponent(runId)}/console`, {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isConsoleSnapshot(body)) {
    throw new Error("The run console response does not match schema version 1.");
  }
  return body;
}

/** Fetch the checked-in Hint Template catalog; no challenge data can add a template. */
export async function getHintTemplates(signal?: AbortSignal): Promise<HintTemplate[]> {
  const response = await fetch("/v1/hint-templates", {
    headers: { Accept: "application/json" },
    signal,
  });
  const body = await decodeJson(response);
  if (!isRecord(body) || !Array.isArray(body.items) || !body.items.every(isHintTemplate)) {
    throw new Error("The API did not return a valid Hint Template catalog.");
  }
  return body.items;
}

function hintIdempotencyKey(action: "create" | "update" | "dismiss"): string {
  // Idempotency protects a local retry, not authentication.  The key is
  // intentionally generated client-side and contains no note, target, key,
  // or other sensitive run content.
  const suffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `ui-hint-${action}-${suffix}`;
}

export async function createHintCard(runId: string, draft: HintCardDraft): Promise<HintCard> {
  const response = await fetch(`/v1/runs/${encodeURIComponent(runId)}/hints`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": hintIdempotencyKey("create"),
    },
    body: JSON.stringify(draft),
  });
  const body = await decodeJson(response);
  if (!isHintCard(body)) {
    throw new Error("The API did not return a valid Hint Card.");
  }
  return body;
}

export async function updateHintCard(
  runId: string,
  hintId: string,
  draft: Omit<HintCardDraft, "template_id">,
): Promise<HintCard> {
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/hints/${encodeURIComponent(hintId)}`,
    {
      method: "PATCH",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": hintIdempotencyKey("update"),
      },
      body: JSON.stringify(draft),
    },
  );
  const body = await decodeJson(response);
  if (!isHintCard(body)) {
    throw new Error("The API did not return a valid Hint Card.");
  }
  return body;
}

export async function dismissHintCard(runId: string, hintId: string): Promise<HintCard> {
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/hints/${encodeURIComponent(hintId)}`,
    {
      method: "DELETE",
      headers: {
        Accept: "application/json",
        "Idempotency-Key": hintIdempotencyKey("dismiss"),
      },
    },
  );
  const body = await decodeJson(response);
  if (!isHintCard(body)) {
    throw new Error("The API did not return a valid Hint Card.");
  }
  return body;
}

/**
 * Download one immutable observation's bytes.
 *
 * A tool receipt shows redacted output capped at 6 KiB, so it summarises the
 * evidence and is never the evidence. Everything a racer produced - the
 * exploit scripts it wrote, the dumps it took - was sealed in the artifact
 * store and reachable by this route, but nothing an operator could see named
 * the artifact, so recovering a script meant reading the store on the host.
 * The confirmation is what the API records as a deliberate disclosure.
 */
export async function downloadRunArtifact(runId: string, artifactId: string): Promise<Blob> {
  const response = await fetch(
    `/v1/runs/${encodeURIComponent(runId)}/artifacts/${encodeURIComponent(artifactId)}/content`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    },
  );
  if (!response.ok) {
    throw new Error(
      response.status === 404
        ? "These bytes are no longer in the artifact store."
        : "The API refused to release these bytes.",
    );
  }
  return response.blob();
}
