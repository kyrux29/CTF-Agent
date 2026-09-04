import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";

import type { HintCardDraft, PowerSession } from "../api";
import { HintDeck } from "./HintDeck";
import {
  RacerColumn,
  type RacerActivityMessage,
  type RacerToolTranscript,
  type RacerViewState,
} from "./RacerColumn";
import type {
  BudgetMeter,
  ConsoleSnapshot,
  ConsoleView,
  CustodyNode,
  Fact,
  HintTemplate,
  Hypothesis,
  SensitiveValue,
  TraceEvent,
} from "../types";

type BlackboardFilter = "all" | "facts" | "hypotheses" | "experiments" | "conflicts";

interface RunConsoleProps {
  snapshot: ConsoleSnapshot;
  embedded?: boolean;
  isRefreshing?: boolean;
  isCancelling?: boolean;
  notice?: string | null;
  onOpenSessions?: () => void;
  onRefresh?: () => void;
  onCancel?: () => void;
  revealedFlag?: string | null;
  isRevealing?: boolean;
  onRevealFlag?: () => void | Promise<void>;
  hintTemplates?: readonly HintTemplate[];
  onCreateHint?: (draft: HintCardDraft) => Promise<void>;
  onUpdateHint?: (
    hintId: string,
    draft: Omit<HintCardDraft, "template_id">,
  ) => Promise<void>;
  onDismissHint?: (hintId: string) => Promise<void>;
  powerSessions?: readonly PowerSession[];
  onSteerRacer?: (label: "A" | "B" | "C", message: string) => Promise<void>;
  candidateSuggestions?: readonly PowerCandidateSuggestion[];
  canRevealInputCandidates?: boolean;
  isRevealingInputCandidates?: boolean;
  onRevealInputCandidates?: () => void | Promise<void>;
  isLoadingRuntimeCandidates?: boolean;
  isFindingMoreCandidates?: boolean;
  onFindMoreCandidates?: () => void | Promise<void>;
  onMarkCandidate?: (id: string, status: PowerCandidateStatus) => void | Promise<void>;
}

export type PowerCandidateStatus =
  | "unreviewed"
  | "manual_valid"
  | "manual_rejected"
  | "verified";

export interface PowerCandidateSuggestion {
  id: string;
  value: string;
  source: "archive" | "runtime" | "verified";
  status: PowerCandidateStatus;
  createdAt: string;
  racerLabels?: readonly ("auto" | "A" | "B" | "C")[];
  /**
   * True only for values returned by the immutable evidence set which opened
   * the current durable candidate-review pause. Historical scans and archive
   * hits are useful clues, but must never look actionable for this run.
   */
  reviewEligible?: boolean;
}

const TABS: Array<{ id: ConsoleView; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "blackboard", label: "Blackboard" },
  { id: "trace", label: "Trace" },
  { id: "verification", label: "Verification" },
];

const STAGES: Array<{ id: ConsoleSnapshot["run"]["current_stage"]; label: string }> = [
  { id: "triage", label: "Triage" },
  { id: "hypothesis", label: "Hypothesis" },
  { id: "exploit", label: "Exploit" },
  { id: "replay", label: "Replay" },
];

const CUSTODY_DRAWER_QUERY = "(max-width: 1199px)";

function useMediaQuery(query: string): boolean {
  const getMatch = () =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia(query).matches
      : false;
  const [matches, setMatches] = useState(getMatch);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const mediaQuery = window.matchMedia(query);
    const updateMatch = () => setMatches(mediaQuery.matches);
    updateMatch();
    mediaQuery.addEventListener("change", updateMatch);
    return () => mediaQuery.removeEventListener("change", updateMatch);
  }, [query]);

  return matches;
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

function formatCategory(value: string): string {
  return value.replaceAll("_", " ").replaceAll("-", " ").toUpperCase();
}

function formatElapsed(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  return hours > 0
    ? `${hours}:${minutes.toString().padStart(2, "0")}:${remainder.toString().padStart(2, "0")}`
    : `${minutes}:${remainder.toString().padStart(2, "0")}`;
}

function isSolveActive(status: ConsoleSnapshot["run"]["status"]): boolean {
  // A completed archive triage is deliberately not considered solve work.
  // Only the durable run lifecycle drives this indicator, so it never
  // pretends that private model reasoning is being streamed to the browser.
  return status === "queued" || status === "ready" || status === "running" || status === "paused" || status === "verifying";
}

function useDisplayedElapsed(snapshot: ConsoleSnapshot): number {
  const active = isSolveActive(snapshot.run.status);
  const [elapsed, setElapsed] = useState(snapshot.run.elapsed_seconds);

  useEffect(() => {
    setElapsed(snapshot.run.elapsed_seconds);
  }, [snapshot.run.elapsed_seconds, snapshot.run.id]);

  useEffect(() => {
    if (!active) {
      return;
    }
    const startedAt = Date.parse(snapshot.run.started_at);
    const update = () => {
      const wallClockElapsed = Number.isNaN(startedAt)
        ? snapshot.run.elapsed_seconds
        : Math.max(0, Math.floor((Date.now() - startedAt) / 1_000));
      // A stale snapshot must never make the live clock move backwards.
      setElapsed((current) => Math.max(snapshot.run.elapsed_seconds, wallClockElapsed, current));
    };
    update();
    const interval = window.setInterval(update, 1_000);
    return () => window.clearInterval(interval);
  }, [active, snapshot.run.elapsed_seconds, snapshot.run.started_at]);

  return elapsed;
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "Unknown time";
  }
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(date);
}

function compactDigest(digest: string | null): string {
  if (!digest) {
    return "No digest";
  }
  const [algorithm, value = ""] = digest.split(":", 2);
  return `${algorithm}:${value.slice(0, 12)}${value.length > 12 ? "…" : ""}`;
}

function budgetText(budget: BudgetMeter): string {
  if (budget.unit === "USD") {
    return `$${budget.used.toFixed(2)} / $${budget.limit.toFixed(2)}`;
  }
  if (budget.unit === "seconds") {
    return `${Math.ceil(budget.used / 60)}m / ${Math.ceil(budget.limit / 60)}m`;
  }
  return `${budget.used.toLocaleString()} / ${budget.limit.toLocaleString()} ${budget.unit}`;
}

function percentage(used: number, limit: number): number {
  if (limit <= 0) {
    return 0;
  }
  return Math.min(100, Math.max(0, (used / limit) * 100));
}

function MaskedValue({ field }: { field: SensitiveValue }) {
  if (field.classification === "public") {
    return <span className="literal-value">{field.value}</span>;
  }

  const label = field.masked_label ?? `${humanize(field.classification)} value`;
  return (
    <span className="masked-value" aria-label={`${label} masked`}>
      <span aria-hidden="true">••••••••</span>
      <span className="mask-label" aria-hidden="true">
        masked
      </span>
    </span>
  );
}

function VerifiedFlagRevealBanner({
  revealedFlag,
  flagCopied,
  isRevealing,
  revealRequested,
  onReveal,
  onCopy,
}: {
  revealedFlag: string | null;
  flagCopied: boolean;
  isRevealing: boolean;
  revealRequested: boolean;
  onReveal: () => void;
  onCopy: () => void;
}) {
  return (
    <section className="power-solved-banner" aria-label="Verified flag" aria-live="polite">
      <div className="power-solved-banner-status">
        <StatusGlyph state="solved" />
        <span>Verified</span>
      </div>
      {revealedFlag ? (
        <div className="power-solved-banner-value">
          <label htmlFor="power-verified-flag">Raw flag</label>
          <input id="power-verified-flag" value={revealedFlag} readOnly />
          <button type="button" className="power-secondary" onClick={onCopy}>
            {flagCopied ? "Copied" : "Copy"}
          </button>
        </div>
      ) : (
        <button
          type="button"
          className="power-primary"
          onClick={onReveal}
          disabled={isRevealing || revealRequested}
        >
          {isRevealing || revealRequested ? "Revealing…" : "Reveal flag"}
        </button>
      )}
    </section>
  );
}

/**
 * Titles that mean a racer moved. Anything newer than the idle receipt ends
 * the idle state; the run's own status stays "running" throughout, because the
 * sessions are alive and still holding their leases.
 */
const POWER_MOVE_TITLES = new Set([
  "Power pi tool transcript",
  "Power command observed",
  "Power pi activity",
  "Power pi steer queued",
  "Power pi steer applied",
]);

/**
 * Report whether every Power session is parked.
 *
 * A run that has stopped moving keeps spending wall time, so the header must
 * not go on saying "Racing" while nothing races. Events arrive in sequence
 * order, so the newest of the two kinds settles it.
 */
function powerSessionsIdle(events: readonly TraceEvent[]): boolean {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const title = events[index]?.title ?? "";
    if (title === "Power sessions idle") return true;
    if (POWER_MOVE_TITLES.has(title)) return false;
  }
  return false;
}

function StatusGlyph({ state }: { state: string }) {
  return <span className="status-glyph" data-state={state} aria-hidden="true" />;
}

function RunRibbon({ snapshot }: { snapshot: ConsoleSnapshot }) {
  const currentIndex = STAGES.findIndex((stage) => stage.id === snapshot.run.current_stage);
  const isVerifiedTerminalRun = snapshot.run.status === "solved";
  const isCompletedTriage = snapshot.run.status === "completed" && snapshot.run.current_stage === "triage";
  return (
    <ol className="run-ribbon" aria-label="Run stages">
      {STAGES.map((stage, index) => {
        const state =
          (isVerifiedTerminalRun || isCompletedTriage) && index <= currentIndex
            ? "complete"
            : index < currentIndex
              ? "complete"
              : index === currentIndex
                ? "current"
                : "pending";
        return (
          <li key={stage.id} className="ribbon-stage" data-state={state}>
            <span className="ribbon-marker" aria-hidden="true">
              {state === "complete" ? "✓" : index + 1}
            </span>
            <span>
              <span className="ribbon-label">{stage.label}</span>
              <span className="ribbon-state">{humanize(state)}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function TriageStatusCard({ snapshot }: { snapshot: ConsoleSnapshot }) {
  const observedCount = snapshot.facts.filter((fact) => fact.state === "accepted").length;
  const proposedFactCount = snapshot.facts.filter((fact) => fact.state === "proposed").length;
  const disputedCount = snapshot.facts.filter((fact) => fact.state === "disputed").length;
  const openHypothesisCount = snapshot.hypotheses.filter(
    (hypothesis) => hypothesis.status === "open" || hypothesis.status === "testing",
  ).length;
  const proposalCount = proposedFactCount + openHypothesisCount;
  const isReadOnlyTriage =
    snapshot.run.execution_mode === "read_only_triage" || snapshot.run.triage.read_only;

  return (
    <section className="triage-status-card" aria-labelledby="triage-status-heading">
      <div className="triage-status-heading">
        <p className="section-kicker">Triage boundary</p>
        <h2 id="triage-status-heading">
          {isReadOnlyTriage ? "Read-only triage remains a proposal" : "Evidence before a path forward"}
        </h2>
        <p>
          {isReadOnlyTriage
            ? "This CLI-only review records declared evidence and suggested leads. It does not execute a proposed action or establish a flag."
            : "Observations can inform a lead. A lead remains a proposal until a scoped experiment and verifier establish it."}
        </p>
      </div>
      <dl className="triage-status-grid" aria-label="Triage claim status">
        <div data-state="accepted">
          <dt>Observed</dt>
          <dd>{observedCount}</dd>
          <span>accepted facts</span>
        </div>
        <div data-state="proposed">
          <dt>Proposed</dt>
          <dd>{proposalCount}</dd>
          <span>{proposalCount === 1 ? "claim needs evidence" : "claims need evidence"}</span>
        </div>
        <div data-state={disputedCount > 0 ? "disputed" : "clear"}>
          <dt>Disputed</dt>
          <dd>{disputedCount}</dd>
          <span>{disputedCount === 0 ? "no open contradiction" : "needs review"}</span>
        </div>
      </dl>
      <dl className="triage-context-grid" aria-label="Triage run context">
        <div>
          <dt>Category</dt>
          <dd>{formatCategory(snapshot.run.category)}</dd>
        </div>
        <div>
          <dt>Stage</dt>
          <dd>{humanize(snapshot.run.current_stage)}</dd>
        </div>
        <div className="triage-context-scope">
          <dt>Declared scope</dt>
          <dd><code>{snapshot.run.target_scope}</code></dd>
        </div>
        <div>
          <dt>Provider</dt>
          <dd>{snapshot.run.provider_label}</dd>
        </div>
        {isReadOnlyTriage ? (
          <div>
            <dt>Actions executed</dt>
            <dd>{snapshot.run.triage.actions_executed}</dd>
          </div>
        ) : null}
        {isReadOnlyTriage ? (
          <div>
            <dt>Verification</dt>
            <dd>{snapshot.run.triage.verification_attempted ? "Attempted" : "Not attempted"}</dd>
          </div>
        ) : null}
      </dl>
      {isReadOnlyTriage && snapshot.run.triage.selected_skill_ids.length > 0 ? (
        <p className="triage-skill-context">
          <span>Selected skills</span>
          <code>{snapshot.run.triage.selected_skill_ids.join(" · ")}</code>
        </p>
      ) : null}
      <div className="triage-status-rule">
        <span className="verification-seal" aria-hidden="true">!</span>
        <p>
          <strong>A proposal cannot solve a run.</strong>
          <span>Only an independent verifier can record a solved state after clean replay.</span>
        </p>
      </div>
    </section>
  );
}

function isPowerRun(snapshot: ConsoleSnapshot): boolean {
  return snapshot.run.provider_label === "power-swarm";
}

const POWER_RACER_LABELS = ["A", "B", "C"] as const;
const POWER_RACER_LANES: Readonly<Record<PowerRacerLabel, string>> = {
  A: "static analysis",
  B: "dynamic behavior",
  C: "exploit validation",
};

// This mirrors the runner's closed, reviewed action vocabulary. Unknown text
// is never copied into the racer strip or activity rail.
const POWER_ACTION_SUMMARIES = new Set([
  "Mapping workspace files.",
  "Reading one challenge file.",
  "Saving a derived work file.",
  "Running a bounded analysis command.",
  "Opening an interactive analysis tool.",
  "Sending bounded input to an analysis tool.",
  "Reading an interactive analysis result.",
  "Closing an interactive analysis tool.",
  "Starting a debugger for the challenge binary.",
  "Inspecting the binary in the debugger.",
  "Closing the debugger session.",
  "Connecting to the declared target.",
  "Sending scoped input to the declared target.",
  "Reading a scoped target response.",
  "Closing the target connection.",
  "Submitting an observed candidate for independent verification.",
]);

// New Pi receipts expose only a closed action discriminant. Converting that
// discriminant locally keeps older runs useful without rendering a command,
// path, target, model response, or other untrusted text.
const POWER_ACTION_TYPE_SUMMARIES: Readonly<Record<string, string>> = {
  exec: "Running a bounded analysis command.",
  pty_start: "Opening an interactive analysis tool.",
  pty_send: "Sending bounded input to an analysis tool.",
  pty_read: "Reading an interactive analysis result.",
  pty_close: "Closing an interactive analysis tool.",
  tube_connect: "Connecting to the declared target.",
  tube_send: "Sending scoped input to the declared target.",
  tube_receive: "Reading a scoped target response.",
  tube_close: "Closing the target connection.",
  flag_submit: "Submitting an observed candidate for independent verification.",
};

const POWER_FAILURE_SUMMARIES = new Set([
  "Provider rejected the saved API key.",
  "Provider rate limit reached.",
  "Provider account quota is unavailable.",
  "Selected model is unavailable.",
  "Provider rejected the model tool schema.",
  "Provider connection failed.",
  "Provider is temporarily unavailable.",
  "Provider ended the turn before work began.",
  "Provider model turn was aborted.",
  "Provider did not complete a usable model turn.",
]);

const POWER_LIFECYCLE_SUMMARIES: Record<string, string> = {
  "Power scope declared": "Target scope locked.",
  "Power pi sessions started": "Racer sessions queued.",
  "Power pi session queued": "A racer session was queued.",
  "Power pi session ready": "A racer reached a safe boundary.",
  "Power pi steer queued": "Coordinator steer queued.",
  "Power pi steer applied": "Coordinator steer applied.",
  "Power pi abort requested": "Sibling stop requested.",
  "Power pi session aborted": "A racer session stopped.",
  "Power pi session failed": "A racer session failed.",
  "Power pi provision failed": "Workspace preparation failed.",
  "Power autoprompter progress": "Preparing the shared brief.",
  "Power budget progress": "Budget reservation updated.",
  "Power swarm started": "Power race started.",
  "Power swarm progress": "Race state updated.",
  "Power pi usage": "Usage telemetry recorded.",
  "Power swarm completed": "Power race completed.",
  "Power swarm cancelled": "Power race cancelled.",
  "Power swarm failed": "Power race stopped after a runtime failure.",
};
const POWER_TERMINAL_RAW_FLAG = /\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}/i;
const POWER_TERMINAL_BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i;
const POWER_TERMINAL_API_KEY = /\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{16,})\b/;
const POWER_TERMINAL_SECRET_ASSIGNMENT = /\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+/i;

type PowerRacerLabel = (typeof POWER_RACER_LABELS)[number];

interface PowerActivityItem {
  eventId: string;
  occurredAt: string;
  actor: string;
  summary: string;
}

function publicEventDetail(event: TraceEvent | undefined, label: string): string | undefined {
  const detail = event?.details.find((item) => item.label === label);
  return detail?.content.classification === "public" ? detail.content.value : undefined;
}

function powerRacerLabel(event: TraceEvent): PowerRacerLabel | null {
  const detailLabel = publicEventDetail(event, "Racer");
  if (detailLabel === "A" || detailLabel === "B" || detailLabel === "C") {
    return detailLabel;
  }
  const match = /^Racer ([ABC]):/.exec(event.summary);
  return match?.[1] === "A" || match?.[1] === "B" || match?.[1] === "C"
    ? match[1]
    : null;
}

function safeCounter(value: string | undefined): number {
  if (!value || !/^\d{1,7}$/.test(value)) return 0;
  return Number(value);
}

function reviewedPowerActionSummary(event: TraceEvent | undefined): string | undefined {
  const summary = publicEventDetail(event, "Activity");
  if (summary && POWER_ACTION_SUMMARIES.has(summary)) return summary;
  const action = publicEventDetail(event, "Action");
  return action ? POWER_ACTION_TYPE_SUMMARIES[action] : undefined;
}

function powerRacerState(
  event: TraceEvent | undefined,
  runStatus: ConsoleSnapshot["run"]["status"],
  session: PowerSession | undefined,
): RacerViewState {
  if (runStatus === "solved") return "solved";
  if (runStatus === "cancelled") return "cancelled";
  if (runStatus === "failed") return "failed";
  if (runStatus === "budget_exhausted" || runStatus === "completed") return "stopped";
  if (runStatus === "verifying") return "verifying";

  // The durable session state is newer than the last metadata-only tool
  // receipt, so use it when the API has supplied it. A `bumped` receipt is
  // still retained below as the fallback for historical runs without the
  // session list.
  if (session?.state === "starting") return "briefing";
  if (session?.state === "ready") return "queued";
  if (session?.state === "running") return "running";
  if (session?.state === "aborting" || session?.state === "aborted") return "stopped";
  if (session?.state === "failed") return "failed";

  const detailState = publicEventDetail(event, "State")?.toLowerCase();
  const summaryState = event?.summary.match(/\((queued|briefing|running|bumped|stopped|failed|cancelled)\)\.?$/)?.[1];
  const state = detailState ?? summaryState;
  if (
    state === "queued"
    || state === "briefing"
    || state === "running"
    || state === "bumped"
    || state === "stopped"
    || state === "failed"
    || state === "cancelled"
  ) {
    return state;
  }
  return "queued";
}

function reviewedPowerActivity(event: TraceEvent): PowerActivityItem | null {
  if (event.title === "Power command observed") {
    const summary = reviewedPowerActionSummary(event);
    if (!summary) return null;
    const label = powerRacerLabel(event);
    return {
      eventId: event.id,
      occurredAt: event.occurred_at,
      actor: label ? `racer-${label}` : "racer",
      summary,
    };
  }
  const projectedFailure = event.title === "Power pi session failed"
    ? publicEventDetail(event, "Failure")
    : undefined;
  const summary = projectedFailure && POWER_FAILURE_SUMMARIES.has(projectedFailure)
    ? projectedFailure
    : POWER_LIFECYCLE_SUMMARIES[event.title];
  return summary
    ? { eventId: event.id, occurredAt: event.occurred_at, actor: "runtime", summary }
    : null;
}

/** Return only the API-validated, redacted Pi message projection. */
function reviewedPowerMessage(event: TraceEvent): RacerActivityMessage | null {
  if (event.title !== "Power pi activity") return null;
  const kind = publicEventDetail(event, "Message kind");
  const content = publicEventDetail(event, "Message");
  if ((kind !== "prompt" && kind !== "response") || !content) return null;
  return { id: event.id, kind, content, occurredAt: event.occurred_at };
}

/** Return only a complete server-reviewed tool terminal record. */
function reviewedPowerToolTranscript(event: TraceEvent): RacerToolTranscript | null {
  if (event.title !== "Power pi tool transcript") return null;
  const tool = publicEventDetail(event, "Tool");
  const command = publicEventDetail(event, "Command");
  const output = publicEventDetail(event, "Output");
  const exitCode = publicEventDetail(event, "Exit code");
  const timedOut = publicEventDetail(event, "Timed out");
  const outputCapped = publicEventDetail(event, "Output capped");
  if (
    !tool || !/^ctf_[a-z0-9_]{2,59}$/.test(tool)
    || !command || command.length > 2_000
    || !output || output.length > 6_000
    || POWER_TERMINAL_RAW_FLAG.test(command)
    || POWER_TERMINAL_RAW_FLAG.test(output)
    || POWER_TERMINAL_BEARER.test(command)
    || POWER_TERMINAL_BEARER.test(output)
    || POWER_TERMINAL_API_KEY.test(command)
    || POWER_TERMINAL_API_KEY.test(output)
    || POWER_TERMINAL_SECRET_ASSIGNMENT.test(command)
    || POWER_TERMINAL_SECRET_ASSIGNMENT.test(output)
    || (exitCode !== "n/a" && !/^-?\d{1,3}$/.test(exitCode ?? ""))
    || (timedOut !== "yes" && timedOut !== "no")
    || (outputCapped !== "yes" && outputCapped !== "no")
  ) {
    return null;
  }
  return {
    id: event.id,
    tool,
    command,
    output,
    exitCode: exitCode === "n/a" ? null : Number(exitCode),
    timedOut: timedOut === "yes",
    outputTruncated: outputCapped === "yes",
    occurredAt: event.occurred_at,
  };
}

function PowerActivityRail({ events }: { events: TraceEvent[] }) {
  const items = events.map(reviewedPowerActivity).filter((item): item is PowerActivityItem => item !== null).slice(-12);
  return (
    <section className="power-activity-rail" aria-labelledby="power-activity-heading">
      <header>
        <h3 id="power-activity-heading">Activity</h3>
        <span>{items.length}</span>
      </header>
      {items.length > 0 ? (
        <ol aria-label="Reviewed Power activity">
          {items.map((item) => (
            <li key={item.eventId}>
              <time dateTime={item.occurredAt}>{formatTime(item.occurredAt)}</time>
              <strong>{item.actor}</strong>
              <span>{item.summary}</span>
            </li>
          ))}
        </ol>
      ) : <p className="power-activity-empty">Waiting for the first durable receipt.</p>}
    </section>
  );
}

function candidateStatusLabel(
  status: PowerCandidateStatus,
  reviewEligible: boolean,
): string {
  if (status === "manual_valid") return "Marked likely";
  if (status === "manual_rejected") return "Dismissed";
  if (status === "verified") return "Verified";
  if (reviewEligible) return "Awaiting review";
  return "Unchecked";
}

/**
 * One candidate row.
 *
 * `actionable` is the whole point of this component: only a value from the
 * evidence set that opened the current pause can change the run. Everything
 * else is a clue, and must not offer a control that looks like it decides
 * anything. Confirm and Reject are always shown together for an actionable
 * row — an operator who submits the value and is told it is wrong needs a way
 * back into the race that is not "Stop all".
 */
function CandidateRow({
  candidate,
  actionable,
  copiedId,
  onCopy,
  onMark,
  run,
}: {
  candidate: PowerCandidateSuggestion;
  actionable: boolean;
  copiedId: string | null;
  onCopy: (candidate: PowerCandidateSuggestion) => void | Promise<void>;
  onMark?: (id: string, status: PowerCandidateStatus) => void | Promise<void>;
  run: (action: () => void | Promise<void>) => Promise<void>;
}) {
  const decided = candidate.status !== "unreviewed";
  return (
    <li data-status={candidate.status} data-actionable={actionable ? "true" : "false"}>
      <code>{candidate.value}</code>
      <span>
        {candidate.racerLabels?.length ? candidate.racerLabels.join(", ") : candidate.source}
      </span>
      <strong>{candidateStatusLabel(candidate.status, Boolean(candidate.reviewEligible))}</strong>
      <div>
        <button
          type="button"
          className="power-text-button"
          onClick={() => void run(() => onCopy(candidate))}
          title="Copy this value so you can submit it on the scoreboard."
        >
          {copiedId === candidate.id ? "Copied" : "Copy"}
        </button>
        {actionable ? (
          <>
            <button
              type="button"
              className="power-primary"
              disabled={onMark === undefined || decided}
              onClick={() => void run(() => onMark?.(candidate.id, "manual_valid"))}
              title="The scoreboard accepted this exact value."
            >
              Accepted
            </button>
            <button
              type="button"
              className="power-secondary"
              disabled={onMark === undefined || decided}
              onClick={() => void run(() => onMark?.(candidate.id, "manual_rejected"))}
              title="The scoreboard rejected it. This resumes the same racers; it is the
                     header's Continue search, said next to the value it is about."
            >
              Rejected
            </button>
          </>
        ) : (
          <button
            type="button"
            className="power-text-button"
            disabled={onMark === undefined}
            onClick={() => void run(() => onMark?.(candidate.id, "manual_rejected"))}
            title="Hide this clue. This does not change the run."
          >
            Dismiss
          </button>
        )}
      </div>
    </li>
  );
}

function PowerCandidateDesk({
  candidates,
  canRevealInputCandidates,
  isRevealingInputCandidates,
  onRevealInputCandidates,
  isLoadingRuntimeCandidates,
  isFindingMoreCandidates,
  onFindMoreCandidates,
  onMarkCandidate,
  candidateReviewPending,
  onStopAll,
  isStoppingAll,
}: {
  candidates: readonly PowerCandidateSuggestion[];
  canRevealInputCandidates: boolean;
  isRevealingInputCandidates: boolean;
  onRevealInputCandidates?: () => void | Promise<void>;
  isLoadingRuntimeCandidates: boolean;
  isFindingMoreCandidates: boolean;
  onFindMoreCandidates?: () => void | Promise<void>;
  onMarkCandidate?: (id: string, status: PowerCandidateStatus) => void | Promise<void>;
  candidateReviewPending: boolean;
  onStopAll?: () => void;
  isStoppingAll: boolean;
}) {
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  async function run(action: () => void | Promise<void>): Promise<void> {
    setError(null);
    try {
      await action();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Candidate action failed.");
    }
  }

  async function copy(candidate: PowerCandidateSuggestion): Promise<void> {
    // The operator scores this value on whatever platform the challenge uses,
    // so getting it out of the browser is the desk's primary action.
    if (!navigator.clipboard) {
      throw new Error("This browser will not allow copying.");
    }
    await navigator.clipboard.writeText(candidate.value);
    setCopiedId(candidate.id);
  }

  // Only a value from the evidence set that opened the current pause can
  // change the run. Splitting the two apart is what keeps a historical scan
  // from ever looking like a decision.
  const awaiting = candidates.filter(
    (candidate) => candidateReviewPending && candidate.reviewEligible,
  );
  const clues = candidates.filter(
    (candidate) => !(candidateReviewPending && candidate.reviewEligible),
  );

  return (
    <section className="power-candidate-desk" aria-labelledby="power-candidate-heading">
      <header>
        <div>
          <h3 id="power-candidate-heading">Candidates</h3>
          <span>{candidates.length}</span>
          {candidateReviewPending ? <em>{isLoadingRuntimeCandidates ? "Loading…" : "Review needed"}</em> : null}
        </div>
        <div className="power-candidate-actions">
          {canRevealInputCandidates && onRevealInputCandidates ? (
            <button
              type="button"
              className="power-secondary"
              onClick={() => void run(onRevealInputCandidates)}
              disabled={isRevealingInputCandidates}
            >
              {isRevealingInputCandidates ? "Loading…" : "Load from archive"}
            </button>
          ) : null}
          {onFindMoreCandidates ? (
            <button
              type="button"
              className="power-primary"
              onClick={() => void run(onFindMoreCandidates)}
              disabled={isFindingMoreCandidates}
            >
              {isFindingMoreCandidates ? "Continuing…" : candidateReviewPending ? "Continue search" : "Reload search"}
            </button>
          ) : null}
          {candidateReviewPending && onStopAll ? (
            <button
              type="button"
              className="power-secondary run-cancel-button"
              onClick={onStopAll}
              disabled={isStoppingAll}
            >
              {isStoppingAll ? "Stopping…" : "Stop all"}
            </button>
          ) : null}
        </div>
      </header>
      {candidates.length > 0 ? (
        <>
          {awaiting.length > 0 ? (
            <div className="power-candidate-group" data-group="awaiting">
              <h4>Waiting on you</h4>
              <p>
                Copy the value, submit it wherever this challenge is scored, then say what
                happened. The race stays paused until you do.
              </p>
              <ol aria-label="Candidates awaiting your decision">
                {awaiting.map((candidate) => (
                  <CandidateRow
                    key={candidate.id}
                    candidate={candidate}
                    actionable
                    copiedId={copiedId}
                    onCopy={copy}
                    onMark={onMarkCandidate}
                    run={run}
                  />
                ))}
              </ol>
            </div>
          ) : null}
          {clues.length > 0 ? (
            <div className="power-candidate-group" data-group="clues">
              <h4>Clues</h4>
              <p>Seen elsewhere in this run or in the archive. Marking one changes nothing.</p>
              <ol aria-label="Candidate clues">
                {clues.map((candidate) => (
                  <CandidateRow
                    key={candidate.id}
                    candidate={candidate}
                    actionable={false}
                    copiedId={copiedId}
                    onCopy={copy}
                    onMark={onMarkCandidate}
                    run={run}
                  />
                ))}
              </ol>
            </div>
          ) : null}
        </>
      ) : (
        <p>No candidate loaded.</p>
      )}
      {error ? <small role="alert">{error}</small> : null}
    </section>
  );
}

/** Render the Power snapshot as an operator race strip, never a transcript. */
function PowerOverviewPanel({
  snapshot,
  navigate,
  powerSessions = [],
  onSteerRacer,
  candidateSuggestions = [],
  canRevealInputCandidates = false,
  isRevealingInputCandidates = false,
  onRevealInputCandidates,
  isLoadingRuntimeCandidates = false,
  isFindingMoreCandidates = false,
  onFindMoreCandidates,
  onMarkCandidate,
  onCancel,
  isCancelling = false,
}: {
  snapshot: ConsoleSnapshot;
  navigate: (reference: string, view: ConsoleView) => void;
  powerSessions?: readonly PowerSession[];
  onSteerRacer?: (label: "A" | "B" | "C", message: string) => Promise<void>;
  candidateSuggestions?: readonly PowerCandidateSuggestion[];
  canRevealInputCandidates?: boolean;
  isRevealingInputCandidates?: boolean;
  onRevealInputCandidates?: () => void | Promise<void>;
  isLoadingRuntimeCandidates?: boolean;
  isFindingMoreCandidates?: boolean;
  onFindMoreCandidates?: () => void | Promise<void>;
  onMarkCandidate?: (id: string, status: PowerCandidateStatus) => void | Promise<void>;
  onCancel?: () => void;
  isCancelling?: boolean;
}) {
  const latestEventForRacer = (label: PowerRacerLabel) => snapshot.events
    .slice()
    .reverse()
    .find((event) => event.title === "Power command observed" && powerRacerLabel(event) === label);
  const latestEvent = snapshot.events.at(-1);
  const latestFailure = snapshot.events
    .slice()
    .reverse()
    .map((event) => publicEventDetail(event, "Failure"))
    .find((detail) => detail !== undefined && POWER_FAILURE_SUMMARIES.has(detail));
  const terminal = !isSolveActive(snapshot.run.status);

  return (
    <div className="power-run-overview">
      <div className="power-console-heading">
        <h2>Race strip</h2>
        <span className="mono">event #{snapshot.run.event_sequence}</span>
      </div>
      <ol className="power-racer-grid" aria-label="Power racer columns">
        {POWER_RACER_LABELS.map((label) => {
          const racerEvents = snapshot.events.filter(
            (item) => item.title === "Power command observed" && powerRacerLabel(item) === label,
          );
          const event = racerEvents.at(-1) ?? latestEventForRacer(label);
          const explicitActionCount = racerEvents.reduce(
            (maximum, item) => Math.max(maximum, safeCounter(publicEventDetail(item, "Turn"))),
            0,
          );
          const explicitObservationCount = racerEvents.reduce(
            (maximum, item) => Math.max(maximum, safeCounter(publicEventDetail(item, "Evidence count"))),
            0,
          );
          const observedEvidenceCount = racerEvents.filter(
            (item) => publicEventDetail(item, "Evidence") === "Captured immutable observation.",
          ).length;
          const activity = reviewedPowerActionSummary(event);
          const fingerprint = publicEventDetail(event, "Fingerprint");
          const messages = snapshot.events
            .filter((item) => powerRacerLabel(item) === label)
            .map(reviewedPowerMessage)
            .filter((item): item is RacerActivityMessage => item !== null);
          const transcripts = snapshot.events
            .filter((item) => powerRacerLabel(item) === label)
            .map(reviewedPowerToolTranscript)
            .filter((item): item is RacerToolTranscript => item !== null);
          const racerSession = powerSessions.find(
            (session) => session.label === label && session.role === "racer",
          );
          return (
            <RacerColumn
              key={label}
              label={label}
              lane={POWER_RACER_LANES[label]}
              state={powerRacerState(event, snapshot.run.status, racerSession)}
              actionCount={Math.max(explicitActionCount, racerEvents.length)}
              observationCount={Math.max(explicitObservationCount, observedEvidenceCount)}
              lastAction={activity ?? "No reviewed action yet."}
              fingerprint={fingerprint && /^[a-f0-9]{8,64}$/i.test(fingerprint) ? fingerprint : undefined}
              activity={messages}
              transcripts={transcripts}
              onSteer={
                racerSession && racerSession.state !== "aborting" && racerSession.state !== "aborted" && racerSession.state !== "failed"
                  ? onSteerRacer ? (message) => onSteerRacer(label, message) : undefined
                  : undefined
              }
            />
          );
        })}
      </ol>
      <PowerCandidateDesk
        candidates={candidateSuggestions}
        canRevealInputCandidates={canRevealInputCandidates}
        isRevealingInputCandidates={isRevealingInputCandidates}
        onRevealInputCandidates={onRevealInputCandidates}
        isLoadingRuntimeCandidates={isLoadingRuntimeCandidates}
        isFindingMoreCandidates={isFindingMoreCandidates}
        onFindMoreCandidates={onFindMoreCandidates}
        onMarkCandidate={onMarkCandidate}
        candidateReviewPending={snapshot.run.status === "paused"}
        onStopAll={onCancel}
        isStoppingAll={isCancelling}
      />
      <PowerActivityRail events={snapshot.events} />
      {terminal ? (
        <section className="power-recovery" role="alert" aria-label="Power run recovery">
          <div>
            <strong>{snapshot.run.status === "budget_exhausted" ? "Race cap reached" : humanize(snapshot.run.status)}</strong>
            <span>
              {snapshot.run.status === "budget_exhausted"
                ? "Adjust limits in Settings before retrying."
                : latestFailure ?? "Inspect the durable trace before retrying."}
            </span>
          </div>
          <button type="button" className="secondary-button" onClick={() => navigate(latestEvent?.id ?? "", "trace")}>
            Open trace
          </button>
        </section>
      ) : null}
    </div>
  );
}

function EvidenceButton({
  id,
  eyebrow,
  title,
  meta,
  state,
  selected,
  onSelect,
}: {
  id: string;
  eyebrow: string;
  title: string;
  meta: string;
  state: string;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      className="evidence-row"
      data-state={state}
      data-selected={selected}
      onClick={onSelect}
      aria-pressed={selected}
    >
      <span className="evidence-row-mark">
        <StatusGlyph state={state} />
      </span>
      <span className="evidence-row-copy">
        <span className="evidence-eyebrow">
          <span className="mono">{id}</span> · {eyebrow}
        </span>
        <span className="evidence-title">{title}</span>
        <span className="evidence-meta">{meta}</span>
      </span>
      <span className="row-arrow" aria-hidden="true">
        →
      </span>
    </button>
  );
}

function OverviewPanel({
  snapshot,
  selectedRef,
  navigate,
  hintTemplates,
  onCreateHint,
  onUpdateHint,
  onDismissHint,
  powerSessions,
  onSteerRacer,
  candidateSuggestions,
  canRevealInputCandidates,
  isRevealingInputCandidates,
  onRevealInputCandidates,
  isLoadingRuntimeCandidates,
  isFindingMoreCandidates,
  onFindMoreCandidates,
  onMarkCandidate,
  onCancel,
  isCancelling,
}: {
  snapshot: ConsoleSnapshot;
  selectedRef: string | null;
  navigate: (reference: string, view: ConsoleView) => void;
  hintTemplates: readonly HintTemplate[];
  onCreateHint?: (draft: HintCardDraft) => Promise<void>;
  onUpdateHint?: (
    hintId: string,
    draft: Omit<HintCardDraft, "template_id">,
  ) => Promise<void>;
  onDismissHint?: (hintId: string) => Promise<void>;
  powerSessions?: readonly PowerSession[];
  onSteerRacer?: (label: "A" | "B" | "C", message: string) => Promise<void>;
  candidateSuggestions?: readonly PowerCandidateSuggestion[];
  canRevealInputCandidates?: boolean;
  isRevealingInputCandidates?: boolean;
  onRevealInputCandidates?: () => void | Promise<void>;
  isLoadingRuntimeCandidates?: boolean;
  isFindingMoreCandidates?: boolean;
  onFindMoreCandidates?: () => void | Promise<void>;
  onMarkCandidate?: (id: string, status: PowerCandidateStatus) => void | Promise<void>;
  onCancel?: () => void;
  isCancelling?: boolean;
}) {
  if (isPowerRun(snapshot)) {
    return (
      <PowerOverviewPanel
        snapshot={snapshot}
        navigate={navigate}
        powerSessions={powerSessions}
        onSteerRacer={onSteerRacer}
        candidateSuggestions={candidateSuggestions}
        canRevealInputCandidates={canRevealInputCandidates}
        isRevealingInputCandidates={isRevealingInputCandidates}
        onRevealInputCandidates={onRevealInputCandidates}
        isLoadingRuntimeCandidates={isLoadingRuntimeCandidates}
        isFindingMoreCandidates={isFindingMoreCandidates}
        onFindMoreCandidates={onFindMoreCandidates}
        onMarkCandidate={onMarkCandidate}
        onCancel={onCancel}
        isCancelling={isCancelling}
      />
    );
  }
  const leadHypothesis = snapshot.hypotheses.find((hypothesis) => hypothesis.status === "supported") ??
    snapshot.hypotheses[0];
  const latestFact = snapshot.facts[0];
  const latestEvents = snapshot.events.slice(-3).reverse();

  return (
    <div className="panel-stack">
      <section className="workspace-section run-progress" aria-labelledby="progress-heading">
        <div className="section-heading-row">
          <div>
            <p className="section-kicker">Run protocol</p>
            <h2 id="progress-heading">From observation to replay</h2>
          </div>
          <span className="sequence-chip mono">event #{snapshot.run.event_sequence}</span>
        </div>
        <RunRibbon snapshot={snapshot} />
      </section>

      <TriageStatusCard snapshot={snapshot} />

      <HintDeck
        hints={snapshot.hints}
        branches={snapshot.branches}
        events={snapshot.events}
        templates={hintTemplates}
        runStatus={snapshot.run.status}
        onCreate={onCreateHint}
        onUpdate={onUpdateHint}
        onDismiss={onDismissHint}
        onNavigateEvent={(eventId) => navigate(eventId, "trace")}
        onNavigateEvidence={(reference) => navigate(reference, "trace")}
      />

      <section className="workspace-section" aria-labelledby="focus-heading">
        <div className="section-heading-row">
          <div>
            <p className="section-kicker">Current case</p>
            <h2 id="focus-heading">Evidence in focus</h2>
          </div>
          <p className="section-note">Select an item to inspect its custody path.</p>
        </div>
        <div className="evidence-list">
          {latestFact ? (
            <EvidenceButton
              id={latestFact.id}
              eyebrow={
                latestFact.state === "proposed"
                  ? "Proposed observation · not verified"
                  : latestFact.state === "disputed"
                    ? "Contradiction"
                    : latestFact.state === "retracted"
                      ? "Retracted observation"
                      : "Observed fact"
              }
              title={latestFact.statement}
              meta={`${latestFact.evidence_refs.length} evidence refs · ${Math.round(latestFact.confidence * 100)}% confidence`}
              state={latestFact.state}
              selected={selectedRef === latestFact.id}
              onSelect={() => navigate(latestFact.id, "blackboard")}
            />
          ) : (
            <p className="empty-state">No observed fact has been committed yet.</p>
          )}
          {leadHypothesis ? (
            <EvidenceButton
              id={leadHypothesis.id}
              eyebrow="Lead hypothesis"
              title={leadHypothesis.statement}
              meta={`${leadHypothesis.evidence_refs.length} linked refs · ${Math.round(leadHypothesis.confidence * 100)}% confidence`}
              state={leadHypothesis.status}
              selected={selectedRef === leadHypothesis.id}
              onSelect={() => navigate(leadHypothesis.id, "blackboard")}
            />
          ) : null}
        </div>
      </section>

      <section className="workspace-section activity-section" aria-labelledby="activity-heading">
        <div className="section-heading-row">
          <div>
            <p className="section-kicker">Recent trace</p>
            <h2 id="activity-heading">Last recorded actions</h2>
          </div>
          <button type="button" className="text-button" onClick={() => navigate(latestEvents[0]?.id ?? "", "trace")}>
            Open full trace
          </button>
        </div>
        <ol className="activity-list">
          {latestEvents.map((event) => (
            <li key={event.id}>
              <button type="button" onClick={() => navigate(event.id, "trace")}>
                <span className="mono">#{event.sequence}</span>
                <span className="activity-copy">
                  <strong>{event.title}</strong>
                  <span>{event.summary}</span>
                </span>
                <time dateTime={event.occurred_at}>{formatTime(event.occurred_at)} UTC</time>
              </button>
            </li>
          ))}
        </ol>
      </section>

      <section className="verification-gate" data-state={snapshot.verification.status} aria-label="Verification gate">
        <div className="verification-seal" aria-hidden="true">
          {snapshot.verification.status === "verified" ? "✓" : "·"}
        </div>
        <div>
          <p className="section-kicker">Independent gate</p>
          <h2>{humanize(snapshot.verification.status)}</h2>
          <p>{snapshot.verification.summary}</p>
        </div>
        <div className="replay-count">
          <strong>
            {snapshot.verification.replay_passed}/{snapshot.verification.replay_required}
          </strong>
          <span>clean replays</span>
        </div>
        <button type="button" className="secondary-button" onClick={() => navigate("V-002", "verification")}>
          Inspect verification
        </button>
      </section>
    </div>
  );
}

function FactRow({
  fact,
  selected,
  onSelect,
}: {
  fact: Fact;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <EvidenceButton
      id={fact.id}
      eyebrow={
        fact.state === "proposed"
          ? "Proposed observation · not verified"
          : fact.state === "disputed"
            ? "Contradiction"
            : fact.state === "retracted"
              ? "Retracted observation"
              : "Observed fact"
      }
      title={fact.statement}
      meta={`${Math.round(fact.confidence * 100)}% confidence · ${fact.evidence_refs.join(", ")}`}
      state={fact.state}
      selected={selected}
      onSelect={onSelect}
    />
  );
}

function HypothesisRow({
  hypothesis,
  selected,
  onSelect,
}: {
  hypothesis: Hypothesis;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <EvidenceButton
      id={hypothesis.id}
      eyebrow={
        hypothesis.status === "open"
          ? "Open proposal · not verified"
          : `${humanize(hypothesis.status)} hypothesis`
      }
      title={hypothesis.statement}
      meta={`${Math.round(hypothesis.confidence * 100)}% confidence · ${hypothesis.rationale}`}
      state={hypothesis.status}
      selected={selected}
      onSelect={onSelect}
    />
  );
}

function BlackboardPanel({
  snapshot,
  selectedRef,
  filter,
  setFilter,
  onSelect,
}: {
  snapshot: ConsoleSnapshot;
  selectedRef: string | null;
  filter: BlackboardFilter;
  setFilter: (filter: BlackboardFilter) => void;
  onSelect: (reference: string) => void;
}) {
  const showFacts = filter === "all" || filter === "facts";
  const showHypotheses = filter === "all" || filter === "hypotheses";
  const showExperiments = filter === "all" || filter === "experiments";
  const showConflicts = filter === "conflicts";
  const disputedFacts = snapshot.facts.filter((fact) => fact.state === "disputed");
  const rejectedHypotheses = snapshot.hypotheses.filter((hypothesis) => hypothesis.status === "rejected");

  return (
    <div className="panel-stack">
      <section className="workspace-intro" aria-labelledby="blackboard-heading">
        <div>
          <p className="section-kicker">Shared run state</p>
          <h2 id="blackboard-heading">Blackboard</h2>
          <p>Claims remain separate from observations until evidence closes the gap. A proposed lead never changes run status on its own.</p>
        </div>
        <div className="mobile-filter-row" aria-label="Filter blackboard">
          {(["all", "facts", "hypotheses", "experiments", "conflicts"] as const).map((item) => (
            <button
              key={item}
              type="button"
              data-active={filter === item}
              aria-pressed={filter === item}
              onClick={() => setFilter(item)}
            >
              {humanize(item)}
            </button>
          ))}
        </div>
      </section>

      {showFacts ? (
        <section className="workspace-section" aria-labelledby="facts-heading">
          <div className="section-heading-row">
            <div>
              <p className="section-kicker">Recorded</p>
              <h3 id="facts-heading">Facts</h3>
            </div>
            <span className="count-label">{snapshot.facts.length}</span>
          </div>
          <div className="evidence-list">
            {snapshot.facts.map((fact) => (
              <FactRow
                key={fact.id}
                fact={fact}
                selected={selectedRef === fact.id}
                onSelect={() => onSelect(fact.id)}
              />
            ))}
          </div>
        </section>
      ) : null}

      {showHypotheses ? (
        <section className="workspace-section" aria-labelledby="hypotheses-heading">
          <div className="section-heading-row">
            <div>
              <p className="section-kicker">Reasoned</p>
              <h3 id="hypotheses-heading">Hypotheses</h3>
            </div>
            <span className="count-label">{snapshot.hypotheses.length}</span>
          </div>
          <div className="evidence-list">
            {snapshot.hypotheses.map((hypothesis) => (
              <HypothesisRow
                key={hypothesis.id}
                hypothesis={hypothesis}
                selected={selectedRef === hypothesis.id}
                onSelect={() => onSelect(hypothesis.id)}
              />
            ))}
          </div>
        </section>
      ) : null}

      {showExperiments ? (
        <section className="workspace-section" aria-labelledby="experiments-heading">
          <div className="section-heading-row">
            <div>
              <p className="section-kicker">Tested</p>
              <h3 id="experiments-heading">Experiments</h3>
            </div>
            <span className="count-label">{snapshot.experiments.length}</span>
          </div>
          <div className="evidence-list">
            {snapshot.experiments.map((experiment) => (
              <EvidenceButton
                key={experiment.id}
                id={experiment.id}
                eyebrow={`${humanize(experiment.status)} · ${humanize(experiment.risk)}`}
                title={experiment.objective}
                meta={experiment.outcome ?? "No outcome recorded yet."}
                state={experiment.status}
                selected={selectedRef === experiment.id}
                onSelect={() => onSelect(experiment.id)}
              />
            ))}
          </div>
        </section>
      ) : null}

      {showConflicts ? (
        <section className="workspace-section conflict-section" aria-labelledby="conflicts-heading">
          <div className="section-heading-row">
            <div>
              <p className="section-kicker">Needs attention</p>
              <h3 id="conflicts-heading">Contradictions and rejected paths</h3>
            </div>
            <span className="count-label">{disputedFacts.length + rejectedHypotheses.length}</span>
          </div>
          <div className="evidence-list">
            {disputedFacts.map((fact) => (
              <FactRow
                key={fact.id}
                fact={fact}
                selected={selectedRef === fact.id}
                onSelect={() => onSelect(fact.id)}
              />
            ))}
            {rejectedHypotheses.map((hypothesis) => (
              <HypothesisRow
                key={hypothesis.id}
                hypothesis={hypothesis}
                selected={selectedRef === hypothesis.id}
                onSelect={() => onSelect(hypothesis.id)}
              />
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

function TraceRow({
  event,
  expanded,
  selected,
  onToggle,
}: {
  event: TraceEvent;
  expanded: boolean;
  selected: boolean;
  onToggle: () => void;
}) {
  const detailsId = `event-details-${event.sequence}`;
  return (
    <article className="trace-row" id={`ref-${event.id}`} data-selected={selected}>
      <button
        type="button"
        className="trace-summary"
        aria-expanded={expanded}
        aria-controls={detailsId}
        aria-label={`${expanded ? "Hide" : "Show"} details for event ${event.sequence}`}
        onClick={onToggle}
      >
        <span className="trace-sequence mono">#{event.sequence}</span>
        <span className="trace-kind">
          <StatusGlyph state={event.policy_decision === "deny" ? "denied" : event.kind} />
          {humanize(event.kind)}
        </span>
        <span className="trace-copy">
          <strong>{event.title}</strong>
          <span>{event.summary}</span>
        </span>
        <span className="trace-time">
          <time dateTime={event.occurred_at}>{formatTime(event.occurred_at)} UTC</time>
          <span aria-hidden="true">{expanded ? "−" : "+"}</span>
        </span>
      </button>
      {expanded ? (
        <div className="trace-details" id={detailsId}>
          <dl className="trace-metadata">
            <div>
              <dt>Tool</dt>
              <dd className="mono">{event.tool_name ?? "Not applicable"}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>
                <span className="policy-label" data-state={event.policy_decision}>
                  {humanize(event.policy_decision ?? "not_applicable")}
                </span>
              </dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd>{event.duration_ms === undefined ? "Not reported" : `${event.duration_ms} ms`}</dd>
            </div>
            <div>
              <dt>Artifacts</dt>
              <dd className="mono">{event.artifact_refs.join(", ") || "None"}</dd>
            </div>
          </dl>
          {event.details.length > 0 ? (
            <dl className="event-payload">
              {event.details.map((detail) => (
                <div key={detail.label}>
                  <dt>{detail.label}</dt>
                  <dd>
                    <MaskedValue field={detail.content} />
                  </dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="empty-detail">This event has no inline payload. Evidence remains in digested artifacts.</p>
          )}
        </div>
      ) : null}
    </article>
  );
}

function TracePanel({
  snapshot,
  selectedRef,
  onSelect,
}: {
  snapshot: ConsoleSnapshot;
  selectedRef: string | null;
  onSelect: (reference: string) => void;
}) {
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(
    () => new Set(selectedRef?.startsWith("EV-") ? [selectedRef] : []),
  );

  function toggleEvent(eventId: string) {
    onSelect(eventId);
    setExpandedEvents((current) => {
      const next = new Set(current);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  }

  return (
    <div className="panel-stack">
      <section className="workspace-intro" aria-labelledby="trace-heading">
        <div>
          <p className="section-kicker">Append-only record</p>
          <h2 id="trace-heading">Tool and verifier trace</h2>
          <p>Payloads are sanitized; large output remains behind immutable artifact references.</p>
        </div>
        <span className="trace-caught-up" role="status">
          <span aria-hidden="true">✓</span> Caught up at #{snapshot.run.event_sequence}
        </span>
      </section>
      <section className="trace-list" aria-label="Run events">
        {snapshot.events.map((event) => (
          <TraceRow
            key={event.id}
            event={event}
            expanded={expandedEvents.has(event.id)}
            selected={selectedRef === event.id}
            onToggle={() => toggleEvent(event.id)}
          />
        ))}
      </section>
    </div>
  );
}

function VerificationPanel({ snapshot }: { snapshot: ConsoleSnapshot }) {
  const result = snapshot.verification;
  const hasVerifiedOutput = result.status === "verified";
  const replayAssessment = result.replays.length === 0 ? "Not assessed" : result.flaky ? "Flaky" : "Stable";
  return (
    <div className="panel-stack verification-panel">
      <section className="verification-hero" data-state={result.status} aria-labelledby="verification-heading">
        <div className="verification-seal large" aria-hidden="true">
          {result.status === "verified" ? "✓" : "·"}
        </div>
        <div className="verification-heading-copy">
          <p className="section-kicker">Independent verifier</p>
          <h2 id="verification-heading">{humanize(result.status)}</h2>
          <p>{result.summary}</p>
        </div>
        <div className="verification-score">
          <strong>
            {result.replay_passed}/{result.replay_required}
          </strong>
          <span>clean-reset replays</span>
        </div>
      </section>

      <section className="workspace-section" aria-labelledby="proof-heading">
        <div className="section-heading-row">
          <div>
            <p className="section-kicker">Proof envelope</p>
            <h3 id="proof-heading">{hasVerifiedOutput ? "Verified output" : "Verification record"}</h3>
          </div>
          <span
            className="flaky-label"
            data-state={result.replays.length === 0 ? "pending" : result.flaky ? "flaky" : "stable"}
          >
            {replayAssessment}
          </span>
        </div>
        <dl className="proof-grid">
          <div>
            <dt>Flag</dt>
            <dd>{result.flag ? <MaskedValue field={result.flag} /> : "Not captured"}</dd>
          </div>
          <div>
            <dt>Exploit digest</dt>
            <dd className="mono" title={result.exploit_digest ?? undefined}>
              {compactDigest(result.exploit_digest)}
            </dd>
          </div>
          <div>
            <dt>Environment digest</dt>
            <dd className="mono" title={result.environment_digest ?? undefined}>
              {compactDigest(result.environment_digest)}
            </dd>
          </div>
        </dl>
      </section>

      <section className="workspace-section" aria-labelledby="replays-heading">
        <div className="section-heading-row">
          <div>
            <p className="section-kicker">Reproduction</p>
            <h3 id="replays-heading">Replay ledger</h3>
          </div>
          <span className="count-label">{result.replays.length}</span>
        </div>
        {result.replays.length > 0 ? (
          <ol className="replay-ledger">
            {result.replays.map((replay) => (
              <li key={replay.attempt} data-state={replay.status}>
                <span className="replay-index mono">{replay.attempt.toString().padStart(2, "0")}</span>
                <StatusGlyph state={replay.status} />
                <span className="replay-copy">
                  <strong>{humanize(replay.status)}</strong>
                  <span>
                    {replay.started_from_clean_reset ? "Clean reset" : "State reused"} · {replay.artifact_digest_match ? "Digest matched" : "Digest mismatch"}
                  </span>
                </span>
                <span className="replay-duration">
                  {replay.duration_ms === null ? "Pending" : `${replay.duration_ms} ms`}
                </span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="empty-state">No independent replay has been recorded for this run.</p>
        )}
      </section>

      <section className="workspace-section" aria-labelledby="artifacts-heading">
        <div className="section-heading-row">
          <div>
            <p className="section-kicker">Manifest</p>
            <h3 id="artifacts-heading">Sealed artifacts</h3>
          </div>
          <span className="count-label">{snapshot.artifacts.length}</span>
        </div>
        <div className="artifact-table" role="table" aria-label="Sealed artifacts">
          <div className="artifact-row artifact-header" role="row">
            <span role="columnheader">File</span>
            <span role="columnheader">Digest</span>
            <span role="columnheader">Size</span>
          </div>
          {snapshot.artifacts.map((artifact) => (
            <div className="artifact-row" role="row" key={artifact.id}>
              <span role="cell">
                <strong>{artifact.name}</strong>
                <small>{artifact.media_type}</small>
              </span>
              <span role="cell" className="mono" title={artifact.digest}>
                {compactDigest(artifact.digest)}
              </span>
              <span role="cell">{Math.max(1, Math.round(artifact.size_bytes / 1024))} KB</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function BudgetList({ budgets }: { budgets: BudgetMeter[] }) {
  return (
    <div className="budget-list">
      {budgets.map((budget) => {
        const value = percentage(budget.used, budget.limit);
        return (
          <div className="budget-item" key={budget.id}>
            <div>
              <span>{budget.label}</span>
              <span className="mono">{budgetText(budget)}</span>
            </div>
            <progress value={value} max={100} aria-label={`${budget.label}: ${budgetText(budget)}`} />
          </div>
        );
      })}
    </div>
  );
}

function RunContextStrip({ snapshot }: { snapshot: ConsoleSnapshot }) {
  return (
    <dl className="run-context-strip" aria-label="Run context">
      <div>
        <dt>Category</dt>
        <dd>{formatCategory(snapshot.run.category)}</dd>
      </div>
      <div>
        <dt>Stage</dt>
        <dd>{humanize(snapshot.run.current_stage)}</dd>
      </div>
      <div className="run-context-scope">
        <dt>Declared scope</dt>
        <dd><code>{snapshot.run.target_scope}</code></dd>
      </div>
      <div>
        <dt>Provider</dt>
        <dd>{snapshot.run.provider_label}</dd>
      </div>
    </dl>
  );
}

function RunIndex({
  snapshot,
  filter,
  setFilter,
  setView,
  compact = false,
}: {
  snapshot: ConsoleSnapshot;
  filter: BlackboardFilter;
  setFilter: (filter: BlackboardFilter) => void;
  setView: (view: ConsoleView) => void;
  compact?: boolean;
}) {
  const conflictCount =
    snapshot.facts.filter((fact) => fact.state === "disputed").length +
    snapshot.hypotheses.filter((hypothesis) => hypothesis.status === "rejected").length;
  const filters: Array<{ id: BlackboardFilter; label: string; count: number }> = [
    { id: "facts", label: "Facts", count: snapshot.facts.length },
    { id: "hypotheses", label: "Hypotheses", count: snapshot.hypotheses.length },
    { id: "experiments", label: "Experiments", count: snapshot.experiments.length },
    { id: "conflicts", label: "Conflicts", count: conflictCount },
  ];

  return (
    <aside className="run-index" aria-label="Run index">
      <section>
        <p className="rail-heading">Run state</p>
        <dl className="run-state-list">
          <div>
            <dt>Status</dt>
            <dd>
              <StatusGlyph state={snapshot.run.status} /> {humanize(snapshot.run.status)}
            </dd>
          </div>
          <div>
            <dt>Scope</dt>
            <dd>
              <StatusGlyph state="derived" /> Declared boundary
            </dd>
          </div>
          <div>
            <dt>Stage</dt>
            <dd>{humanize(snapshot.run.current_stage)}</dd>
          </div>
          <div>
            <dt>Provider</dt>
            <dd className="provider-label">{snapshot.run.provider_label}</dd>
          </div>
          <div>
            <dt>Evidence</dt>
            <dd>{snapshot.facts.length + snapshot.events.length} records</dd>
          </div>
        </dl>
      </section>
      <section>
        <p className="rail-heading">Budget</p>
        <BudgetList budgets={snapshot.budgets} />
      </section>
      {!compact ? (
        <section>
        <p className="rail-heading">Blackboard</p>
        <div className="index-filters">
          {filters.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={filter === item.id}
              data-active={filter === item.id}
              onClick={() => {
                setFilter(item.id);
                setView("blackboard");
              }}
            >
              <span>{item.label}</span>
              <span className="mono">{item.count}</span>
            </button>
          ))}
        </div>
        </section>
      ) : null}
      <section className="scope-block">
        <p className="rail-heading">Declared scope</p>
        <code>{snapshot.run.target_scope}</code>
        <p>{humanize(snapshot.run.scope_kind)} boundary · only manifest-declared activity or offline artifacts may contribute evidence.</p>
      </section>
    </aside>
  );
}

function CustodyRail({
  nodes,
  selectedRef,
  open,
  drawer,
  onClose,
  onSelect,
}: {
  nodes: CustodyNode[];
  selectedRef: string | null;
  open: boolean;
  drawer: boolean;
  onClose: () => void;
  onSelect: (node: CustodyNode) => void;
}) {
  const railRef = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const relatedNodes = useMemo(() => {
    if (!selectedRef) {
      return nodes;
    }
    const filtered = nodes.filter(
      (node) => node.ref_id === selectedRef || node.related_refs.includes(selectedRef),
    );
    return filtered.length > 1 ? filtered : nodes;
  }, [nodes, selectedRef]);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!drawer || !open) {
      return;
    }

    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButtonRef.current?.focus();

    const handleKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || railRef.current === null) {
        return;
      }
      const focusable = Array.from(
        railRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.getAttribute("aria-hidden") !== "true");
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) {
        return;
      }
      const active = document.activeElement;
      if (!focusable.includes(active as HTMLElement)) {
        event.preventDefault();
        first.focus();
      } else if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      const previousFocus = previousFocusRef.current;
      previousFocusRef.current = null;
      if (previousFocus?.isConnected) {
        previousFocus.focus();
      }
    };
  }, [drawer, open]);

  const shouldRenderContents = !drawer || open;

  return (
    <>
      {drawer && open ? (
        <button
          type="button"
          className="custody-backdrop"
          aria-label="Dismiss evidence path"
          onClick={onClose}
        />
      ) : null}
      <aside
        ref={railRef}
        className="custody-rail"
        id="custody-panel"
        data-open={open}
        aria-label="Chain of custody"
        aria-hidden={drawer && !open ? true : undefined}
        aria-modal={drawer ? true : undefined}
        role={drawer ? "dialog" : undefined}
        tabIndex={drawer ? -1 : undefined}
      >
        {shouldRenderContents ? (
          <>
            <div className="custody-header">
              <div>
                <p className="rail-heading">Chain of custody</p>
                <p>{selectedRef ? `Path supporting ${selectedRef}` : "Full verification path"}</p>
              </div>
              {drawer ? (
                <button
                  ref={closeButtonRef}
                  type="button"
                  className="drawer-close"
                  onClick={onClose}
                  aria-label="Close evidence path"
                >
                  ×
                </button>
              ) : null}
            </div>
            <ol className="custody-list">
              {relatedNodes.map((node, index) => (
                <li key={node.id} data-state={node.state}>
                  <button
                    type="button"
                    aria-pressed={selectedRef === node.ref_id}
                    data-selected={selectedRef === node.ref_id}
                    onClick={() => onSelect(node)}
                  >
                    <span className="custody-node" aria-hidden="true">
                      {node.state === "verified" ? "✓" : index + 1}
                    </span>
                    <span className="custody-copy">
                      <span className="custody-kind">{humanize(node.kind)}</span>
                      <strong>{node.label}</strong>
                      <span className="mono">{node.ref_id} · event #{node.event_sequence}</span>
                      <span className="mono custody-digest">{compactDigest(node.digest)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ol>
            <div className="custody-legend">
              <span><StatusGlyph state="observed" /> Observed</span>
              <span><StatusGlyph state="derived" /> Derived</span>
              <span><StatusGlyph state="verified" /> Verified</span>
            </div>
          </>
        ) : null}
      </aside>
    </>
  );
}

export function RunConsole({
  snapshot,
  embedded = false,
  isRefreshing = false,
  isCancelling = false,
  notice,
  onOpenSessions,
  onRefresh,
  onCancel,
  revealedFlag = null,
  isRevealing = false,
  onRevealFlag,
  hintTemplates = [],
  onCreateHint,
  onUpdateHint,
  onDismissHint,
  powerSessions,
  onSteerRacer,
  candidateSuggestions = [],
  canRevealInputCandidates = false,
  isRevealingInputCandidates = false,
  onRevealInputCandidates,
  isLoadingRuntimeCandidates = false,
  isFindingMoreCandidates = false,
  onFindMoreCandidates,
  onMarkCandidate,
}: RunConsoleProps) {
  const [view, setView] = useState<ConsoleView>("overview");
  const [selectedRef, setSelectedRef] = useState<string | null>(snapshot.facts[0]?.id ?? null);
  const [blackboardFilter, setBlackboardFilter] = useState<BlackboardFilter>("all");
  const [custodyOpen, setCustodyOpen] = useState(false);
  const [flagCopied, setFlagCopied] = useState(false);
  const [revealRequested, setRevealRequested] = useState(false);
  const revealRequestedRef = useRef(false);
  const isCustodyDrawer = useMediaQuery(CUSTODY_DRAWER_QUERY);
  const powerRun = isPowerRun(snapshot);
  const availableTabs = useMemo(
    () => (powerRun ? TABS.filter((tab) => tab.id !== "blackboard") : TABS),
    [powerRun],
  );
  const solveActive = isSolveActive(snapshot.run.status);
  const displayedElapsed = useDisplayedElapsed(snapshot);

  useEffect(() => {
    if (!isCustodyDrawer) {
      setCustodyOpen(false);
    }
  }, [isCustodyDrawer]);

  useEffect(() => {
    if (!availableTabs.some((tab) => tab.id === view)) {
      setView("overview");
    }
  }, [availableTabs, view]);

  useEffect(() => {
    setFlagCopied(false);
  }, [revealedFlag, snapshot.run.id]);

  useEffect(() => {
    revealRequestedRef.current = false;
    setRevealRequested(false);
  }, [snapshot.run.id]);

  function navigate(reference: string, targetView: ConsoleView) {
    setSelectedRef(reference || null);
    setView(targetView);
  }

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, current: ConsoleView) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") {
      return;
    }
    event.preventDefault();
    const currentIndex = availableTabs.findIndex((tab) => tab.id === current);
    let nextIndex = currentIndex;
    if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % availableTabs.length;
    if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + availableTabs.length) % availableTabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = availableTabs.length - 1;
    const next = availableTabs[nextIndex];
    if (next) {
      setView(next.id);
      document.getElementById(`tab-${next.id}`)?.focus();
    }
  }

  const costBudget = snapshot.budgets.find((budget) => budget.unit === "USD");
  const timeBudget = snapshot.budgets.find((budget) => budget.unit === "seconds");
  const sessionsIdle = powerRun
    && snapshot.run.status === "running"
    && powerSessionsIdle(snapshot.events);
  const statusLabel = powerRun && snapshot.run.status === "running"
    ? sessionsIdle ? "Idle" : "Racing"
    : humanize(snapshot.run.status);
  const statusState = sessionsIdle
    ? "idle"
    : powerRun ? snapshot.run.status : solveActive ? "thinking" : snapshot.run.status;
  const statusHint = sessionsIdle
    ? "Idle. Every racer is waiting; steer one or stop the run."
    : statusLabel;
  const elapsedLabel = powerRun && timeBudget
    ? `${formatElapsed(displayedElapsed)} / ${formatElapsed(timeBudget.limit)}`
    : formatElapsed(displayedElapsed);

  async function copyRevealedFlag(): Promise<void> {
    if (!revealedFlag || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(revealedFlag);
      setFlagCopied(true);
    } catch {
      setFlagCopied(false);
    }
  }

  async function requestVerifiedFlag(): Promise<void> {
    if (
      !onRevealFlag ||
      revealedFlag ||
      isRevealing ||
      revealRequestedRef.current
    ) {
      return;
    }
    revealRequestedRef.current = true;
    setRevealRequested(true);
    try {
      await onRevealFlag();
    } catch {
      // Failed requests may be retried; a successful reveal remains one-shot.
      revealRequestedRef.current = false;
      setRevealRequested(false);
    }
  }

  return (
    <div className={`console-page${embedded ? " console-page--embedded" : ""}${powerRun ? " console-page--power" : ""}`}>
      <a className="skip-link" href="#run-workspace">Skip to run workspace</a>
      <header className="run-header">
        {!embedded ? (
          <div className="brand-lockup compact" aria-label="CTFMesh Evidence Workbench">
            <span className="brand-mark" aria-hidden="true">CM</span>
            <span>
              <strong>CTFMesh</strong>
              <small>Evidence workbench</small>
            </span>
          </div>
        ) : null}
        <div className="run-identity">
          <span className="mono" title={snapshot.run.id}>{powerRun ? `RUN ${snapshot.run.id}` : snapshot.run.id}</span>
          <strong>{snapshot.run.challenge_name}</strong>
          <span>{formatCategory(snapshot.run.category)}</span>
        </div>
        <div className="run-header-metrics" aria-label="Run summary">
          <span
            className="run-status"
            data-state={statusState}
            role="status"
            aria-label={powerRun ? statusHint : solveActive ? `Thinking. ${statusLabel} stage.` : statusLabel}
          >
            <StatusGlyph state={statusState} />
            {!powerRun && solveActive ? (
              <span className="run-thinking-label">
                Thinking <span className="thinking-dots" aria-hidden="true"><i /><i /><i /></span>
              </span>
            ) : statusLabel}
          </span>
          <span>
            <small>Elapsed</small>
            <strong className="mono">{elapsedLabel}</strong>
          </span>
          {costBudget ? (
            <span>
              <small>Cost</small>
              <strong className="mono">{budgetText(costBudget)}</strong>
            </span>
          ) : null}
        </div>
        <div className="header-actions">
          {solveActive && onCancel && !(powerRun && snapshot.run.status === "paused") ? (
            <button
              type="button"
              className="secondary-button run-cancel-button"
              onClick={onCancel}
              disabled={isCancelling}
            >
              {isCancelling ? "Stopping…" : powerRun ? "Stop all" : "Stop"}
            </button>
          ) : null}
          <button
            type="button"
            className="secondary-button run-close-button"
            aria-label={embedded ? "Close run workspace" : "Open sessions"}
            onClick={onOpenSessions}
          >
            {embedded ? "Close" : "Sessions"}
          </button>
          {!powerRun ? (
            <button
              type="button"
              className="icon-button custody-toggle"
              aria-controls={isCustodyDrawer ? "custody-panel" : undefined}
              aria-expanded={isCustodyDrawer ? custodyOpen : undefined}
              onClick={() => setCustodyOpen(true)}
            >
              Evidence path
            </button>
          ) : null}
          <button type="button" className="secondary-button" onClick={onRefresh} disabled={!onRefresh || isRefreshing}>
            <span className="refresh-icon" aria-hidden="true">↻</span>
            <span className="refresh-label">{isRefreshing ? "Refreshing…" : "Refresh evidence"}</span>
          </button>
        </div>
      </header>

      {notice ? (
        <div className="connection-notice" role="alert">
          <strong>Snapshot refresh failed.</strong> {notice} Showing the last complete projection.
        </div>
      ) : null}

      {powerRun && snapshot.run.status === "solved" && onRevealFlag ? (
        <VerifiedFlagRevealBanner
          revealedFlag={revealedFlag}
          flagCopied={flagCopied}
          isRevealing={isRevealing}
          revealRequested={revealRequested}
          onReveal={() => void requestVerifiedFlag()}
          onCopy={() => void copyRevealedFlag()}
        />
      ) : null}

      <div className={`console-grid${powerRun ? " console-grid--power" : ""}`}>
        {!powerRun ? (
          <RunIndex
            snapshot={snapshot}
            filter={blackboardFilter}
            setFilter={setBlackboardFilter}
            setView={setView}
          />
        ) : null}

        <main className="run-workspace" id="run-workspace">
          <div className="view-tabs" role="tablist" aria-label="Run console views">
            {availableTabs.map((tab) => (
              <button
                type="button"
                role="tab"
                id={`tab-${tab.id}`}
                key={tab.id}
                aria-selected={view === tab.id}
                aria-controls={`panel-${tab.id}`}
                tabIndex={view === tab.id ? 0 : -1}
                onClick={() => setView(tab.id)}
                onKeyDown={(event) => onTabKeyDown(event, tab.id)}
              >
                {tab.label}
                {tab.id === "verification" ? (
                  <span className="tab-count" data-state={snapshot.verification.status}>
                    {snapshot.verification.replay_passed}/{snapshot.verification.replay_required}
                  </span>
                ) : null}
              </button>
            ))}
          </div>

          {!powerRun ? <RunContextStrip snapshot={snapshot} /> : null}

          <div
            className="view-panel"
            role="tabpanel"
            id={`panel-${view}`}
            aria-labelledby={`tab-${view}`}
            tabIndex={0}
          >
            {view === "overview" ? (
              <OverviewPanel
                snapshot={snapshot}
                selectedRef={selectedRef}
                navigate={navigate}
                hintTemplates={hintTemplates}
                onCreateHint={onCreateHint}
                onUpdateHint={onUpdateHint}
                onDismissHint={onDismissHint}
                powerSessions={powerSessions}
                onSteerRacer={onSteerRacer}
                candidateSuggestions={candidateSuggestions}
                canRevealInputCandidates={canRevealInputCandidates}
                isRevealingInputCandidates={isRevealingInputCandidates}
                onRevealInputCandidates={onRevealInputCandidates}
                isLoadingRuntimeCandidates={isLoadingRuntimeCandidates}
                isFindingMoreCandidates={isFindingMoreCandidates}
                onFindMoreCandidates={onFindMoreCandidates}
                onMarkCandidate={onMarkCandidate}
                onCancel={onCancel}
                isCancelling={isCancelling}
              />
            ) : null}
            {view === "blackboard" ? (
              <BlackboardPanel
                snapshot={snapshot}
                selectedRef={selectedRef}
                filter={blackboardFilter}
                setFilter={setBlackboardFilter}
                onSelect={(reference) => setSelectedRef(reference)}
              />
            ) : null}
            {view === "trace" ? (
              <TracePanel snapshot={snapshot} selectedRef={selectedRef} onSelect={setSelectedRef} />
            ) : null}
            {view === "verification" ? <VerificationPanel snapshot={snapshot} /> : null}
          </div>
        </main>

        {!powerRun ? (
          <CustodyRail
            nodes={snapshot.custody}
            selectedRef={selectedRef}
            open={custodyOpen}
            drawer={isCustodyDrawer}
            onClose={() => setCustodyOpen(false)}
            onSelect={(node) => {
              navigate(node.ref_id, node.target_view);
              setCustodyOpen(false);
            }}
          />
        ) : null}
      </div>

      <footer className="run-footer" aria-live="polite">
        <span>
          <span className="footer-dot" aria-hidden="true" /> event #{snapshot.run.event_sequence} · projection current
        </span>
        <span>Target scope enforced · sensitive values masked</span>
        <span className="mono">UTC · schema v{snapshot.schema_version}</span>
      </footer>
    </div>
  );
}
