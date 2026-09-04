/** Durable Pi job consumer. It owns no database, target socket, or shell. */

import type { RunnerConfig } from "./config.js";
import { ControlClient } from "./control-client.js";
import { CredentialLeaseStore } from "./credential-lease.js";
import type {
  AgentJob,
  AgentSession as DurableAgentSession,
  ContextManifest,
  PowerPiSession,
  PowerSessionWork,
  TurnWork,
} from "./contracts.js";
import { ControlProtocolError } from "./contracts.js";
import { reviewedRole } from "./roles.js";
import {
  createPowerPiSession,
  createReviewedPiSession,
  type PiSessionHandle,
  type PowerPiSessionHandle,
} from "./session-factory.js";

export interface TurnDriver {
  run(handle: PiSessionHandle, work: TurnWork): Promise<void>;
}

/**
 * Production driver. The prompt is purpose-built from sealed identifiers and
 * an objective; it never includes source files, URLs, an archive path, or a
 * secret. `expandPromptTemplates: false` is an extra guard even though the
 * reviewed loader has no templates.
 */
export class PiSdkTurnDriver implements TurnDriver {
  public async run(handle: PiSessionHandle, work: TurnWork): Promise<void> {
    const evidenceIds = work.context_manifest.evidence_refs
      .map((reference) => reference.observation_id)
      .join(", ");
    const prompt = [
      "Execute one reviewed CTFMesh turn using only this sealed control-plane context.",
      `Objective: ${work.task.objective}`,
      `Available evidence IDs: ${evidenceIds || "none"}`,
      "You have no direct filesystem, shell, network, target, browser, or provider access.",
      "If your role exposes tool.request, use only its reviewed schema; the control plane independently enforces source scope or an exact target alias.",
      "For an exploit_builder task with general.review, inspect source or make a minimal exact-target observation before proposing exactly one reviewed technique; the kernel rejects all unreviewed plans.",
      "If the sealed evidence supports a concise unverified statement, call finding.submit with only listed evidence IDs.",
      "If you are an exploit_builder and can express a replay without code, host, or raw flag, candidate.submit may queue independent verification; it never solves the run.",
      "Otherwise state that the evidence is insufficient. Do not claim a flag or solve.",
    ].join("\n");
    await handle.session.prompt(prompt, { expandPromptTemplates: false });
    await handle.session.waitForIdle();
  }
}

/**
 * The default local/demo driver proves session, event, lease, steer, abort and
 * disposal plumbing without a provider credential or fake flag. It performs
 * no model call and submits no finding. Tests can use this without network.
 */
export class FixtureTurnDriver implements TurnDriver {
  public async run(handle: PiSessionHandle, _work: TurnWork): Promise<void> {
    handle.events.lifecycle("agent.turn.started");
    handle.events.lifecycle("agent.turn.completed");
  }
}

export type SafeRunnerLogger = (code: string) => void;

function defaultLogger(code: string): void {
  // Codes are generated locally from a fixed allowlist. Do not write caught
  // error messages here: SDK/provider errors may contain an authorization or
  // challenge-derived value.
  process.stderr.write(`[ctfmesh-pi-runner] ${code}\n`);
}

function sameDurableSession(left: DurableAgentSession, right: DurableAgentSession): boolean {
  return left.id === right.id
    && left.context_manifest_id === right.context_manifest_id
    && left.role === right.role
    && left.session_store_key === right.session_store_key;
}

function samePowerSession(left: PowerPiSession, right: PowerPiSession): boolean {
  return left.id === right.id
    && left.run_id === right.run_id
    && left.workspace_id === right.workspace_id
    && left.role === right.role
    && left.session_store_key === right.session_store_key;
}

const POWER_BATCH_CONTINUATION = [
  "Continue from the immutable observations already collected.",
  "Do not repeat directory listings or reads unless they test a new hypothesis.",
  "Use the next short batch only for the highest-value validation step.",
  "If a complete candidate is observed, submit it immediately with its exact Evidence handle.",
].join(" ");

// Four focused checkpoints give a simple challenge enough room to move from
// reconnaissance to validation without recreating the unbounded native-tool
// loop that hid usage and starved sibling racers.
/**
 * A racer's batch ceiling is a runaway guard, never the operating limit: the
 * run budget decides when a race ends.  The previous fixed value of four
 * ended every racer after at most forty tool calls, which stopped runs at
 * roughly one percent of a default cost budget and left the run with no
 * further work queued.  `RunnerConfig.powerRacerMaxSolveBatches` now owns the
 * ceiling so a deployment can raise or lower it without a code change.
 */
const POWER_AUTOPROMPTER_MAX_BATCHES = 1;

/**
 * These faults happen below the reviewed job contract.  Do not turn them
 * into a racer/model failure: the existing lease will expire and the durable
 * queue can be safely reclaimed by the runner once the control plane heals.
 */
const TRANSIENT_CONTROL_CODES = new Set([
  "control_transport_failed",
  "control_request_timeout",
  "control_database_unavailable",
]);

function isTransientControlFailure(error: unknown): boolean {
  return error instanceof ControlProtocolError && TRANSIENT_CONTROL_CODES.has(error.code);
}

/**
 * A Pi runner restart intentionally clears the in-memory credential broker.
 * The browser refresh loop can restore the same lease shortly afterwards.
 * Do not terminalize the durable Power job during that short recovery window:
 * letting its lease expire preserves the transcript and lets the normal claim
 * path retry after an operator returns to the local UI.
 */
function isRecoverablePowerCredentialFailure(job: AgentJob, error: unknown): boolean {
  return (job.kind === "power_session_start" || job.kind === "power_steer")
    && error instanceof ControlProtocolError
    && error.code === "pi_credential_lease_unavailable";
}

/**
 * A transient provider outage must not discard a durable racer transcript.
 * After one short, bounded retry burst the runner deliberately leaves the
 * leased job unfinished. PostgreSQL reclaims it after the existing lease
 * expires, and the same Pi session is prompted again from its JSONL state.
 *
 * This is intentionally narrower than the generic control-plane recovery:
 * only a code emitted by `promptWithProviderRetry()` gets this treatment.
 * Authentication, quota, model and tool-schema failures remain terminal.
 */
function isDeferredPowerProviderRetry(job: AgentJob, error: unknown): boolean {
  return (job.kind === "power_session_start" || job.kind === "power_steer")
    && error instanceof ControlProtocolError
    && error.code === "power_pi_provider_retry_deferred";
}

/**
 * Project Pi's final assistant state to a stable, secret-free runner code.
 * Provider error text stays in the runner-only transcript and is never an
 * API/event payload.
 */
export type PowerModelTurnFailureCode =
  | "power_pi_model_turn_missing"
  | "power_pi_model_turn_failed"
  | "power_pi_model_turn_aborted"
  | "power_pi_provider_authentication_failed"
  | "power_pi_provider_rate_limited"
  | "power_pi_provider_quota_exhausted"
  | "power_pi_provider_model_unavailable"
  | "power_pi_provider_tool_schema_rejected"
  | "power_pi_provider_transport_failed"
  | "power_pi_provider_unavailable";

/**
 * Reduce a provider-owned diagnostic to a fixed local code. The raw message
 * can contain an upstream request ID or credential fragment, so it must stay
 * in Pi's private transcript and must never become an event or log field.
 */
function classifiedProviderFailure(errorMessage: string | undefined): PowerModelTurnFailureCode {
  if (errorMessage === undefined) {
    return "power_pi_model_turn_failed";
  }
  if (
    /(?:\b401\b|unauthori[sz]ed|authentication\s+(?:failed|required)|invalid\s+(?:api[ -]?key|credential))/i
      .test(errorMessage)
  ) {
    return "power_pi_provider_authentication_failed";
  }
  if (/(?:\b429\b|rate[ _-]?limit|too many requests)/i.test(errorMessage)) {
    return "power_pi_provider_rate_limited";
  }
  if (/(?:\b402\b|quota\s+(?:exhausted|exceeded)|insufficient\s+(?:balance|credit|quota))/i.test(errorMessage)) {
    return "power_pi_provider_quota_exhausted";
  }
  if (/(?:invalid.{0,120}tools?|tools?.{0,120}(?:invalid|expected\s+pattern|does not match))/i.test(errorMessage)) {
    return "power_pi_provider_tool_schema_rejected";
  }
  if (/model.{0,80}(?:not found|does not exist|invalid|unknown|unavailable|unsupported)/i.test(errorMessage)) {
    return "power_pi_provider_model_unavailable";
  }
  if (/(?:fetch failed|econn|etimedout|enetunreach|enotfound|eai_again|dns|network|proxy|socket|connect)/i.test(errorMessage)) {
    return "power_pi_provider_transport_failed";
  }
  if (/\b5\d\d\b/.test(errorMessage)) {
    return "power_pi_provider_unavailable";
  }
  return "power_pi_model_turn_failed";
}

/**
 * Pi normally records a failed turn as an assistant message, but some
 * Undici/SDK transport faults reject `prompt()` or `waitForIdle()` directly.
 * Classify that path with the same fixed codes without writing its message to
 * the ledger, terminal or browser.
 */
function classifiedThrownProviderFailure(error: unknown): PowerModelTurnFailureCode {
  if (error instanceof ControlProtocolError) {
    throw error;
  }
  const message = error instanceof Error
    ? error.message
    : typeof error === "string"
      ? error
      : undefined;
  if (message !== undefined && /(?:abort(?:ed)?|cancel(?:led)?)/i.test(message)) {
    return "power_pi_model_turn_aborted";
  }
  return classifiedProviderFailure(message);
}

export function powerModelTurnFailureCode(
  messages: readonly {
    readonly role: string;
    readonly stopReason?: string;
    readonly errorMessage?: string;
  }[],
): PowerModelTurnFailureCode | null {
  const latestAssistant = [...messages]
    .reverse()
    .find((message) => message.role === "assistant");
  if (latestAssistant === undefined) {
    return "power_pi_model_turn_missing";
  }
  if (latestAssistant.stopReason === "error") {
    return classifiedProviderFailure(latestAssistant.errorMessage);
  }
  if (latestAssistant.stopReason === "aborted") {
    return "power_pi_model_turn_aborted";
  }
  return null;
}

/**
 * Provider faults a racer can survive by asking again.
 *
 * A transport blip or a rate limit is a property of the network and the
 * provider's queue, not of this racer's work: failing the session for one lost
 * packet discards its whole transcript, ends the run through
 * ``all_power_racers_failed``, and leaves the operator unable even to steer.
 * Authentication, quota, model-availability and tool-schema faults are
 * deliberately absent — retrying those only burns the budget on the same
 * rejection.  ``power_pi_model_turn_aborted`` is absent because an abort is
 * something the control plane asked for.
 */
export const RETRYABLE_POWER_MODEL_FAILURES: ReadonlySet<string> = new Set([
  "power_pi_provider_transport_failed",
  "power_pi_provider_unavailable",
  "power_pi_provider_rate_limited",
  "power_pi_model_turn_failed",
  "power_pi_model_turn_missing",
]);

/**
 * Control-plane answers that mean this racer is finished, not broken.
 *
 * Reporting is fenced the moment the run settles, so the flush after a turn
 * is refused - and a racer that reached its budget cap, or found the flag the
 * whole race exists to find, was recorded as a failed session because of it.
 */
const QUIET_POWER_STOPS: ReadonlySet<string> = new Set([
  "power_pi_budget_exhausted",
  "control_power_pi_budget_exhausted",
  "power_candidate_review_required",
  "control_power_candidate_review_required",
]);

/** Fixed code used only to release a durable job after a retry burst. */
const POWER_PROVIDER_RETRY_DEFERRED = "power_pi_provider_retry_deferred";

/**
 * Spread racers deterministically rather than making A/B/C reconnect on the
 * same millisecond after a proxy or provider blip. It uses only the opaque
 * session identifier and is not a source of randomness or challenge data.
 */
function retryJitter(sessionId: string, attempt: number): number {
  let state = 2_166_136_261 ^ attempt;
  for (let index = 0; index < sessionId.length; index += 1) {
    state = Math.imul(state ^ sessionId.charCodeAt(index), 16_777_619);
  }
  return (state >>> 0) / 0x1_0000_0000;
}

/** Exported for deterministic policy tests; delay is always bounded. */
export function powerProviderRetryDelayMs(
  sessionId: string,
  attempt: number,
  config: Pick<RunnerConfig, "powerProviderRetryBaseDelayMs" | "powerProviderRetryMaxDelayMs">,
): number {
  const exponential = Math.min(
    config.powerProviderRetryMaxDelayMs,
    config.powerProviderRetryBaseDelayMs * (2 ** Math.min(attempt - 1, 16)),
  );
  // Equal jitter keeps a useful lower bound while avoiding synchronized
  // retries. Round and clamp defensively for test-provided configuration.
  return Math.max(1, Math.min(
    config.powerProviderRetryMaxDelayMs,
    Math.round(exponential * (0.5 + (retryJitter(sessionId, attempt) * 0.5))),
  ));
}

function waitForRetry(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

/** Reject an SDK terminal provider error instead of displaying it as ready. */
function requireCompletedPowerModelTurn(handle: PowerPiSessionHandle): void {
  const failure = powerModelTurnFailureCode(handle.session.messages);
  if (failure !== null) {
    // The provider message can contain credential or provider diagnostics.
    // Persist only the stable local code through the normal Power failure
    // route; no transcript text crosses the runner boundary.
    throw new ControlProtocolError(failure);
  }
}

/**
 * Consumes one claimed queue item at a time. A second process may reclaim an
 * expired job, but server-side exact lease checks are still authoritative for
 * every mutation. The local map is only an optimization for live SDK objects.
 */
export class PiRunnerConsumer {
  private readonly sessions = new Map<string, PiSessionHandle>();
  private readonly powerSessions = new Map<string, PowerPiSessionHandle>();
  private readonly credentialLeases: CredentialLeaseStore;

  public constructor(
    private readonly config: RunnerConfig,
    private readonly control = new ControlClient(config),
    private readonly turnDriver: TurnDriver = config.mode === "live"
      ? new PiSdkTurnDriver()
      : new FixtureTurnDriver(),
    private readonly logger: SafeRunnerLogger = defaultLogger,
    credentialLeases?: CredentialLeaseStore,
  ) {
    // Tests and standalone fixture use an otherwise empty local registry. The
    // production entry point passes the broker's same process-local registry.
    this.credentialLeases = credentialLeases ?? new CredentialLeaseStore(config.credentialLeaseMaxTtlSeconds);
  }

  public async consumeOnce(): Promise<AgentJob["kind"] | null> {
    const job = await this.control.claim();
    if (job === null) {
      return null;
    }
    return this.consumeClaimed(job);
  }

  /**
   * Claim first and then process independently so Power's four Pi sessions
   * can race in one runner process.  v0.1 tests retain `consumeOnce()`'s
   * sequential convenience while the production loop bounds concurrency.
   */
  public async beginOnce(): Promise<{
    readonly kind: AgentJob["kind"];
    readonly completion: Promise<AgentJob["kind"]>;
  } | null> {
    const job = await this.control.claim();
    if (job === null) {
      return null;
    }
    return { kind: job.kind, completion: this.consumeClaimed(job) };
  }

  private async consumeClaimed(job: AgentJob): Promise<AgentJob["kind"]> {
    const lease = { jobId: job.id, leaseVersion: job.lease_version };
    try {
      switch (job.kind) {
        case "start_session":
          await this.startSession(lease);
          break;
        case "run_turn":
          await this.runTurn(lease);
          break;
        case "steer":
          await this.applySteer(lease);
          break;
        case "abort":
          await this.abortSession(lease);
          break;
        case "dispose":
          await this.disposeSession(lease);
          break;
        case "power_session_start":
          await this.startPowerSession(lease);
          break;
        case "power_steer":
          await this.applyPowerSteer(lease);
          break;
        case "power_abort":
          await this.abortPowerSession(lease);
          break;
      }
    } catch (error) {
      if (isTransientControlFailure(error)) {
        // Retain the leased record rather than calling failPower(). The lease
        // makes this idempotent after expiry; terminalizing it would make a
        // healthy racer disappear merely because PostgreSQL was momentarily
        // unavailable.
        this.logger("control_job_retry_deferred");
        return job.kind;
      }
      if (isRecoverablePowerCredentialFailure(job, error)) {
        // The per-run browser renewal is the only approved recovery source;
        // no worker invents, persists, or logs a provider key. Leaving this
        // job leased makes its next claim idempotent once that lease arrives.
        this.logger("power_pi_credential_refresh_deferred");
        return job.kind;
      }
      if (isDeferredPowerProviderRetry(job, error)) {
        // Do not terminalize a racer merely because a bounded local retry
        // burst did not outlast a provider outage. The normal versioned lease
        // expiry makes this exact durable job reclaimable; `ensurePowerSession`
        // then reuses the same in-memory/JSONL Pi transcript on the next turn.
        this.logger(POWER_PROVIDER_RETRY_DEFERRED);
        return job.kind;
      }
      const code = this.failureCode(job.kind, error);
      this.logger(code);
      // A lost lease cannot be repaired by the stale consumer. Other failures
      // become durable terminal job records without exposing the raw exception.
      if (code !== "pi_job_lease_lost") {
        try {
          if (
            job.kind === "power_session_start"
            || job.kind === "power_steer"
            || job.kind === "power_abort"
          ) {
            await this.control.failPower(lease, code);
          } else {
            await this.control.fail(lease, code);
          }
        } catch {
          this.logger("pi_failure_recording_rejected");
        }
      }
    }
    return job.kind;
  }

  public async disposeLocalSessions(): Promise<void> {
    for (const handle of this.sessions.values()) {
      handle.unsubscribe();
      handle.session.dispose();
      await handle.releaseCredential();
    }
    this.sessions.clear();
    for (const handle of this.powerSessions.values()) {
      handle.unsubscribe();
      handle.session.dispose();
      await handle.releaseCredential();
    }
    this.powerSessions.clear();
  }

  private async startSession(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getStartSessionWork(lease);
    const reservation = await this.control.reserveSession(lease);
    if (
      reservation.session.run_id !== work.job.run_id
      || reservation.session.task_id !== work.task.id
      || reservation.context_manifest.id !== work.context_manifest.id
    ) {
      throw new ControlProtocolError("session_reservation_does_not_match_start_job");
    }
    const handle = await this.ensureSession(reservation.session, reservation.context_manifest);
    const prompt = reviewedRole(reservation.session.role);
    // Persist only the reviewed prompt contract metadata.  The prompt body,
    // local skill-pack contents, model transcript, and provider credential
    // remain inside the Pi runner boundary.
    handle.events.lifecycle("agent.session.started", {
      prompt_contract_version: prompt.promptContractVersion,
      prompt_contract_digest: prompt.promptContractDigest,
    });
    handle.events.lifecycle("agent.session.ready");
    await this.flushEvents(lease, handle);
    await this.control.activateSession(lease, reservation.session.id);
  }

  private async runTurn(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getTurnWork(lease);
    const handle = await this.ensureSession(work.session, work.context_manifest);
    handle.authority.open({
      jobId: lease.jobId,
      leaseVersion: lease.leaseVersion,
      sessionId: work.session.id,
    });
    handle.findings.reset();
    try {
      await this.turnDriver.run(handle, work);
      await this.flushEvents(lease, handle);
      await this.control.completeTurn(lease, handle.findings.resultRef());
    } finally {
      handle.authority.close();
    }
  }

  private async applySteer(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getSteerWork(lease);
    // There may be no local object after a runner restart.  Reopen the same
    // durable transcript from its sealed context before sending the message;
    // otherwise a successful acknowledgement could drop operator steering.
    const handle = await this.ensureSession(work.session, work.context_manifest);
    if (!handle.session.isIdle) {
      throw new ControlProtocolError("steer_requested_while_pi_not_idle");
    }
    await handle.session.sendCustomMessage(
      {
        customType: "ctfmesh.operator-steer",
        content: work.steer.message,
        display: false,
        details: { steer_id: work.steer.id },
      },
      // The session is idle at the kernel-enforced safe boundary. Appending
      // without `deliverAs: "nextTurn"` makes Pi persist the custom message
      // immediately; Pi's transient next-turn queue would be lost on restart.
      { triggerTurn: false },
    );
    await this.control.completeSteer(lease);
  }

  private async abortSession(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getSessionWork(lease, "abort");
    const handle = this.sessions.get(work.session.id);
    if (handle !== undefined) {
      await handle.session.abort();
    }
    await this.control.completeAbort(lease);
  }

  private async disposeSession(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getSessionWork(lease, "dispose");
    const handle = this.sessions.get(work.session.id);
    if (handle !== undefined) {
      handle.unsubscribe();
      handle.session.dispose();
      await handle.releaseCredential();
      this.sessions.delete(work.session.id);
    }
    await this.control.completeDispose(lease);
  }

  private async startPowerSession(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getPowerSessionWork(lease);
    if (work.job.kind !== "power_session_start") {
      throw new ControlProtocolError("power_session_start_work_kind_invalid");
    }
    const handle = await this.ensurePowerSession(work);
    // Power custom tools are enabled only while this durable startup job is
    // leased.  One Pi prompt may make multiple native tool calls before idle.
    handle.authority.open({ jobId: lease.jobId, leaseVersion: lease.leaseVersion, sessionId: work.session.id });
    const stopHeartbeat = this.config.mode === "live"
      ? this.startPowerLeaseHeartbeat(lease, handle)
      : undefined;
    let heartbeatStopped = false;
    try {
      if (this.config.mode === "live") {
        // This is CTFMesh's generated, structured brief—not Pi's hidden
        // system prompt or provider request envelope. It is redacted and
        // bounded again by the activity reporter before reaching the UI.
        handle.activity.recordPrompt(work.session.brief);
        await this.flushPowerActivity(lease, handle);
        await this.runPowerBatches(lease, handle, work.session.brief);
      }
      // Stop and await any in-flight renewal before completing the job. This
      // prevents a just-started heartbeat from racing the completion endpoint
      // and incorrectly logging a failure for a successfully ready session.
      await stopHeartbeat?.();
      heartbeatStopped = true;
      await this.control.completePowerSessionStart(lease);
    } finally {
      if (!heartbeatStopped) {
        await stopHeartbeat?.();
      }
      handle.authority.close();
    }
  }

  /**
   * Renew the durable lease before a long model turn expires. An abort fence
   * makes renewal fail, which also interrupts the local Pi session.
   */
  private startPowerLeaseHeartbeat(
    lease: { readonly jobId: string; readonly leaseVersion: number },
    handle: PowerPiSessionHandle,
  ): () => Promise<void> {
    let stopped = false;
    let failure: unknown = null;
    let pending = Promise.resolve();
    const renew = (): void => {
      pending = pending.then(async () => {
        if (stopped || failure !== null) {
          return;
        }
        try {
          await this.control.renewPowerSessionStartLease(lease);
        } catch (error) {
          failure = error;
          try {
            await handle.session.abort();
          } catch {
            // Preserve the lease failure; abort is only best-effort cleanup.
          }
        }
      });
    };
    const timer = setInterval(renew, 10_000);
    return async (): Promise<void> => {
      stopped = true;
      clearInterval(timer);
      await pending;
      if (failure !== null) {
        throw failure;
      }
    };
  }

  private async applyPowerSteer(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getPowerSessionWork(lease);
    if (work.job.kind !== "power_steer" || work.steer === undefined) {
      throw new ControlProtocolError("power_steer_work_invalid");
    }
    const handle = await this.ensurePowerSession(work);
    // Pi's steer() is the SDK-supported way to place a human correction
    // between the current tool batch and next model request. This avoids
    // making the operator wait for an hour-long Power turn to become idle.
    handle.activity.recordPrompt(work.steer.message);
    await this.flushPowerActivity(lease, handle);
    const deliveredWhileStreaming = !handle.session.isIdle;
    if (deliveredWhileStreaming) {
      await handle.session.steer(work.steer.message);
    } else {
      // An idle racer needs a new executable model turn, including a fresh
      // per-job authority for any tool calls that it decides to make.
      handle.authority.open({ jobId: lease.jobId, leaseVersion: lease.leaseVersion, sessionId: work.session.id });
      try {
        await this.runPowerBatches(lease, handle, work.steer.message);
      } finally {
        handle.authority.close();
      }
    }
    await this.control.completePowerSteer(lease, deliveredWhileStreaming);
  }

  private async abortPowerSession(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<void> {
    const work = await this.control.getPowerSessionWork(lease);
    if (work.job.kind !== "power_abort") {
      throw new ControlProtocolError("power_abort_work_kind_invalid");
    }
    const handle = this.powerSessions.get(work.session.id);
    if (handle !== undefined) {
      await handle.session.abort();
      handle.unsubscribe();
      handle.session.dispose();
      await handle.releaseCredential();
      this.powerSessions.delete(work.session.id);
    }
    await this.control.completePowerAbort(lease);
  }

  /**
   * A provider may issue many sequential custom-tool calls before it returns
   * a final assistant message. Bound that native loop so the UI receives
   * fresh evidence and usage, operators can steer at the next boundary, and
   * racers reconsider their hypothesis rather than blindly continuing.
   */
  private async runPowerBatches(
    lease: { readonly jobId: string; readonly leaseVersion: number },
    handle: PowerPiSessionHandle,
    initialPrompt: string,
  ): Promise<void> {
    let prompt = initialPrompt;
    const maximumBatches = handle.durable.role === "autoprompter"
      ? POWER_AUTOPROMPTER_MAX_BATCHES
      : this.config.powerRacerMaxSolveBatches;
    for (let batch = 0; batch < maximumBatches; batch += 1) {
      handle.toolBatch.beginTurn();
      if (batch > 0) {
        handle.activity.recordPrompt(prompt);
        await this.flushPowerActivity(lease, handle);
      }
      await this.promptWithProviderRetry(lease, handle, prompt);
      if (handle.toolBatch.candidateReviewRequired) {
        // The control plane has atomically paused the durable run after an
        // observed format match. Do not begin a continuation batch or leave
        // the model in a loop while the local operator reviews candidates.
        return;
      }
      if (!handle.toolBatch.exhausted) {
        requireCompletedPowerModelTurn(handle);
        if (handle.toolBatch.callsInTurn === 0) {
          return;
        }
      }
      // AutoPrompter is intentionally a cheap evidence primer. Its bounded
      // first pass is enough to contribute to the shared ledger; racers own
      // iterative solving and resume with a focused continuation prompt.
      if (handle.durable.role === "autoprompter") {
        return;
      }
      prompt = POWER_BATCH_CONTINUATION;
    }
  }

  /**
   * Run one model turn, asking again when the provider fault is transient.
   *
   * The retry re-prompts rather than replaying: Pi's transcript already holds
   * the failed turn, and ``powerModelTurnFailureCode`` reads only the newest
   * assistant message, so a later success supersedes the earlier error. Usage
   * and activity are flushed after every attempt, which keeps the budget and
   * the operator feed honest about work a failed attempt already paid for.
   */
  private async promptWithProviderRetry(
    lease: { readonly jobId: string; readonly leaseVersion: number },
    handle: PowerPiSessionHandle,
    prompt: string,
  ): Promise<void> {
    for (let attempt = 1; ; attempt += 1) {
      let thrownFailure: PowerModelTurnFailureCode | null = null;
      try {
        await handle.session.prompt(prompt, { expandPromptTemplates: false });
        await handle.session.waitForIdle();
      } catch (error) {
        // Some provider transports reject the SDK promise without creating an
        // assistant error message. Treat it exactly like Pi's recorded error
        // path, but retain only a fixed classification outside the session.
        thrownFailure = classifiedThrownProviderFailure(error);
      }
      await this.flushPowerActivity(lease, handle);
      try {
        await this.flushPowerUsage(lease, handle);
      } catch (error) {
        if (error instanceof ControlProtocolError && QUIET_POWER_STOPS.has(error.code)) {
          // The control plane has already settled this run - a budget cap
          // reached, or a candidate gate holding the session for an operator
          // decision. Both fence this session's reporting, so the flush that
          // follows the turn is refused; propagating that would report the
          // race finding a flag as a session failure.
          this.logger(error.code);
          return;
        }
        throw error;
      }
      if (handle.toolBatch.candidateReviewRequired || handle.toolBatch.exhausted) {
        return;
      }
      const failure = thrownFailure ?? powerModelTurnFailureCode(handle.session.messages);
      if (failure === null) {
        return;
      }
      if (!RETRYABLE_POWER_MODEL_FAILURES.has(failure)) {
        // Authentication, exhausted quota, an invalid model/tool schema and
        // an explicit abort cannot improve by retrying. Surface their typed
        // error through the normal Power failure route.
        throw new ControlProtocolError(failure);
      }
      if (attempt >= this.config.powerProviderRetryAttempts) {
        // End this burst without marking the durable racer failed. The queue
        // will reclaim its lease after the existing 30-second cooldown, which
        // provides an outage backoff without trusting model text or creating
        // a duplicate session/transcript.
        throw new ControlProtocolError(POWER_PROVIDER_RETRY_DEFERRED);
      }
      this.logger("power_pi_model_turn_retry");
      await waitForRetry(powerProviderRetryDelayMs(handle.durable.id, attempt, this.config));
    }
  }

  private async ensureSession(
    durable: DurableAgentSession,
    context: ContextManifest,
  ): Promise<PiSessionHandle> {
    const existing = this.sessions.get(durable.id);
    if (existing !== undefined) {
      if (!sameDurableSession(existing.durable, durable)) {
        throw new ControlProtocolError("local_session_descriptor_conflict");
      }
      return existing;
    }
    const created = await createReviewedPiSession(
      this.config,
      this.control,
      durable,
      context,
      this.credentialLeases,
    );
    this.sessions.set(durable.id, created);
    return created;
  }

  private async ensurePowerSession(work: PowerSessionWork): Promise<PowerPiSessionHandle> {
    const existing = this.powerSessions.get(work.session.id);
    if (existing !== undefined) {
      if (!samePowerSession(existing.durable, work.session)) {
        throw new ControlProtocolError("local_power_session_descriptor_conflict");
      }
      return existing;
    }
    const created = await createPowerPiSession(
      this.config,
      this.control,
      work.session,
      this.credentialLeases,
    );
    this.powerSessions.set(work.session.id, created);
    return created;
  }

  private async flushEvents(
    lease: { readonly jobId: string; readonly leaseVersion: number },
    handle: PiSessionHandle,
  ): Promise<void> {
    const events = handle.events.drain();
    for (let offset = 0; offset < events.length; offset += 128) {
      await this.control.appendEvents(lease, events.slice(offset, offset + 128));
    }
  }

  /**
   * Usage is read from Pi's settled session statistics, never assistant text.
   * Keep the acknowledgement local until the API commits the one-way budget
   * debit so a transient control error retries the same counters rather than
   * silently dropping them.
   */
  private async flushPowerUsage(
    lease: { readonly jobId: string; readonly leaseVersion: number },
    handle: PowerPiSessionHandle,
  ): Promise<void> {
    const usage = handle.usage.pending();
    if (usage === null) {
      return;
    }
    await this.control.reportPowerUsage(
      { ...lease, sessionId: handle.durable.id },
      usage,
    );
    handle.usage.acknowledge();
  }

  /** Keep transcript telemetry non-fatal; actions and model turns remain authoritative. */
  private async flushPowerActivity(
    lease: { readonly jobId: string; readonly leaseVersion: number },
    handle: PowerPiSessionHandle,
  ): Promise<void> {
    try {
      await handle.activity.flush({ ...lease, sessionId: handle.durable.id });
    } catch {
      // A pending item stays in the reporter and is retried at the next safe
      // tool/turn boundary. Never retry a solver action merely for UI feed.
    }
  }

  private failureCode(kind: AgentJob["kind"], error: unknown): string {
    if (error instanceof ControlProtocolError && error.code.startsWith("power_pi_model_turn_")) {
      return error.code;
    }
    if (error instanceof ControlProtocolError && error.code.startsWith("power_pi_provider_")) {
      return error.code;
    }
    if (error instanceof ControlProtocolError && error.code === "power_pi_budget_exhausted") {
      // Reaching a configured cap is the run ending as asked, not a fault.
      // Reporting it as the generic start failure made a correct stop look
      // like a crash to anyone reading the run.
      return error.code;
    }
    if (error instanceof ControlProtocolError && (
      error.code === "control_agent_job_lease_lost"
      || error.code === "control_agent_job_lease_expired"
      || error.code === "control_agent_turn_not_reclaimable"
      || error.code === "control_pi_job_run_not_active"
      || error.code === "control_pi_teardown_run_not_cancelled"
      || error.code === "control_agent_turn_branch_not_active"
      || error.code === "control_power_pi_job_lease_lost"
      || error.code === "control_power_pi_job_lease_expired"
      || error.code === "control_power_pi_job_run_not_active"
      || error.code === "control_power_pi_teardown_run_not_terminal"
    )) {
      return "pi_job_lease_lost";
    }
    const byKind: Record<AgentJob["kind"], string> = {
      start_session: "pi_session_start_failed",
      run_turn: "pi_turn_failed",
      steer: "pi_steer_failed",
      abort: "pi_abort_failed",
      dispose: "pi_dispose_failed",
      power_session_start: "power_pi_session_start_failed",
      power_steer: "power_pi_steer_failed",
      power_abort: "power_pi_abort_failed",
    };
    return byKind[kind];
  }
}
