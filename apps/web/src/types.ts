export type ConsoleView = "overview" | "blackboard" | "trace" | "verification";

export type RunStatus =
  | "queued"
  | "ready"
  | "running"
  | "paused"
  | "verifying"
  | "completed"
  | "solved"
  | "failed"
  | "cancelled"
  | "budget_exhausted";

export type RunStage = "triage" | "hypothesis" | "exploit" | "replay";
export type ScopeKind = "artifact_bundle" | "docker_compose" | "remote" | "unknown";
export type RunExecutionMode = "standard" | "read_only_triage";

export interface TriageMetadata {
  read_only: boolean;
  actions_executed: number;
  verification_attempted: boolean;
  selected_skill_ids: string[];
}

export interface RunSummary {
  id: string;
  challenge_name: string;
  category: string;
  status: RunStatus;
  started_at: string;
  elapsed_seconds: number;
  current_stage: RunStage;
  event_sequence: number;
  target_scope: string;
  scope_kind: ScopeKind;
  execution_mode: RunExecutionMode;
  provider_label: string;
  triage: TriageMetadata;
}

export interface BudgetMeter {
  id: string;
  label: string;
  used: number;
  limit: number;
  unit: "USD" | "requests" | "seconds" | "tokens";
}

export interface Fact {
  id: string;
  statement: string;
  state: "proposed" | "accepted" | "disputed" | "retracted";
  observed_at: string;
  confidence: number;
  evidence_refs: string[];
}

export interface Hypothesis {
  id: string;
  statement: string;
  status: "open" | "testing" | "supported" | "rejected" | "merged" | "suspended";
  confidence: number;
  rationale: string;
  evidence_refs: string[];
}

export interface Experiment {
  id: string;
  objective: string;
  status: "queued" | "running" | "passed" | "failed";
  risk: "read_only" | "target_interaction";
  outcome: string | null;
  evidence_refs: string[];
}

export interface SensitiveValue {
  value: string;
  classification: "public" | "sensitive" | "secret";
  masked_label?: string;
}

export interface TraceDetail {
  label: string;
  content: SensitiveValue;
}

export interface TraceEvent {
  sequence: number;
  id: string;
  occurred_at: string;
  kind: "worker" | "tool" | "policy" | "artifact" | "verifier";
  title: string;
  summary: string;
  tool_name?: string;
  duration_ms?: number;
  policy_decision?: "allow" | "deny" | "not_applicable";
  details: TraceDetail[];
  artifact_refs: string[];
  /** Safe identifiers extracted from event metadata for cross-panel links. */
  related_refs: string[];
}

export type HintDirective = "explore" | "prioritize" | "require_probe" | "avoid";
export type HintStatus = "active" | "fulfilled" | "contradicted" | "dismissed" | "expired";

/** Maintainer-reviewed catalog metadata. It cannot carry operator instructions. */
export interface HintTemplate {
  id: string;
  version: number;
  label: string;
  technique_id: string;
  category: string;
  default_directive: HintDirective;
  recommended_roles: string[];
  recommended_tools: string[];
  branch_seed: string;
  falsifiers: string[];
}

/** One local human hypothesis. Its note stays visibly unverified in the UI. */
export interface HintCard {
  id: string;
  run_id: string;
  template_id: string;
  template_version: number;
  technique_id: string;
  category: string;
  directive: HintDirective;
  target_ref: string;
  priority: number;
  note: string;
  epistemic_status: "human_hypothesis";
  status: HintStatus;
  evidence_refs: string[];
  actor_id: string;
  created_at: string;
  updated_at: string;
}

/** Explainable scheduler projection; scores are never claims of truth. */
export interface SchedulerBranch {
  id: string;
  run_id: string;
  family: string;
  state: "active" | "stalled" | "suspended" | "completed" | "failed";
  technique_id: string;
  branch_scope: string;
  priority: number;
  novelty: number;
  evidence_strength: number;
  expected_value: number;
  normalized_cost: number;
  repetition_penalty: number;
  consecutive_no_observation: number;
  score: number;
  created_at: string;
  updated_at: string;
}

export interface Artifact {
  id: string;
  name: string;
  media_type: string;
  digest: string;
  size_bytes: number;
  classification: "public" | "sensitive" | "secret";
}

export interface ReplayResult {
  attempt: number;
  status: "pending" | "running" | "passed" | "failed";
  started_from_clean_reset: boolean;
  artifact_digest_match: boolean;
  duration_ms: number | null;
  evidence_ref: string | null;
}

export interface VerificationResult {
  status: "pending" | "running" | "verified" | "failed";
  summary: string;
  exploit_digest: string | null;
  environment_digest: string | null;
  flag: SensitiveValue | null;
  replay_required: number;
  replay_passed: number;
  flaky: boolean;
  replays: ReplayResult[];
}

export interface CustodyNode {
  id: string;
  kind: "source" | "fact" | "hypothesis" | "action" | "artifact" | "verification";
  label: string;
  ref_id: string;
  digest: string | null;
  event_sequence: number;
  state: "observed" | "derived" | "verified" | "missing";
  related_refs: string[];
  target_view: ConsoleView;
}

export interface ConsoleSnapshot {
  schema_version: "1";
  run: RunSummary;
  budgets: BudgetMeter[];
  facts: Fact[];
  hypotheses: Hypothesis[];
  experiments: Experiment[];
  events: TraceEvent[];
  artifacts: Artifact[];
  verification: VerificationResult;
  custody: CustodyNode[];
  hints: HintCard[];
  branches: SchedulerBranch[];
}
