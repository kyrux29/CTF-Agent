/** Authenticated, target-free client for the control-plane runner protocol. */

import type { RunnerConfig } from "./config.js";
import type {
  PowerArtifactReadRequest,
  PowerArtifactWindow,
  PowerChannelReceipt,
  PowerExecRequest,
  PowerFlagSubmissionReceipt,
  PowerFlagSubmissionRequest,
  PowerPtyCloseRequest,
  PowerPtyReadRequest,
  PowerPtySendRequest,
  PowerPtyStartRequest,
  PowerToolObservation,
  PowerTubeCloseRequest,
  PowerTubeConnectRequest,
  PowerTubeReceiveRequest,
  PowerTubeSendRequest,
  PowerToolName,
} from "./power-tools.js";
import type { TurnLease } from "./tools.js";
import type { PowerUsageDelta } from "./power-usage.js";
import type { PowerActivityKind, PowerToolTranscript } from "./power-activity.js";
import {
  type AgentBridgeEvent,
  type AgentJob,
  type AgentSession,
  type AgentSteer,
  type ExploitCandidateSubmission,
  type FlagCapturePatterns,
  type FindingSubmission,
  type GatewayToolRequest,
  type PiRunState,
  type PowerSessionWork,
  type SessionWork,
  type StartSessionWork,
  type SteerWork,
  type TaskDelegationRequest,
  type ToolGatewayResponse,
  type TurnWork,
  ControlProtocolError,
  controlContract,
  validateBridgeEvent,
  validateFindingSubmission,
  validateCandidateSubmission,
  validateGatewayToolRequest,
  validateTaskDelegation,
} from "./contracts.js";

interface Lease {
  readonly jobId: string;
  readonly leaseVersion: number;
}

function safeServerCode(value: unknown): string | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const detail = (value as Record<string, unknown>).detail;
  if (detail === null || typeof detail !== "object" || Array.isArray(detail)) {
    return null;
  }
  const code = (detail as Record<string, unknown>).code;
  return typeof code === "string" && /^[a-z][a-z0-9_:-]{0,159}$/.test(code) ? code : null;
}

function protocolError(code: string): never {
  throw new ControlProtocolError(code);
}

/** Validate the control plane's artifact window before a racer sees any of it. */
function parsePowerArtifactWindow(value: unknown): PowerArtifactWindow {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    protocolError("power_tool_artifact_window_invalid");
  }
  const payload = value as Record<string, unknown>;
  const artifactId = payload.artifact_id;
  const offset = payload.offset;
  const totalBytes = payload.total_bytes;
  const returnedBytes = payload.returned_bytes;
  const text = payload.text;
  if (
    typeof artifactId !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(artifactId)
    || !Number.isSafeInteger(offset)
    || (offset as number) < 0
    || !Number.isSafeInteger(totalBytes)
    || (totalBytes as number) < 0
    || !Number.isSafeInteger(returnedBytes)
    || (returnedBytes as number) < 0
    || typeof text !== "string"
  ) {
    protocolError("power_tool_artifact_window_invalid");
  }
  return {
    artifactId,
    offset: offset as number,
    totalBytes: totalBytes as number,
    returnedBytes: returnedBytes as number,
    text,
  };
}

function parsePowerObservation(value: unknown): PowerToolObservation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    protocolError("power_tool_observation_invalid");
  }
  const payload = value as Record<string, unknown>;
  const expected = new Set([
    "artifact", "stdout", "stderr", "exitCode", "timedOut", "outputTruncated", "candidateReviewRequired", "candidateCount", "interactiveId", "interactiveKind",
  ]);
  if (
    Object.keys(payload).some((key) => !expected.has(key))
    || payload.artifact === null
    || typeof payload.artifact !== "object"
    || Array.isArray(payload.artifact)
    || typeof payload.stdout !== "string"
    || typeof payload.stderr !== "string"
    || (payload.exitCode !== null && !Number.isSafeInteger(payload.exitCode))
    || typeof payload.timedOut !== "boolean"
    || typeof payload.outputTruncated !== "boolean"
  ) {
    protocolError("power_tool_observation_invalid");
  }
  const artifact = payload.artifact as Record<string, unknown>;
  if (
    Object.keys(artifact).length !== 3
    || typeof artifact.id !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(artifact.id)
    || typeof artifact.sha256 !== "string"
    || !/^[0-9a-f]{64}$/.test(artifact.sha256)
    || !Number.isSafeInteger(artifact.sizeBytes)
    || (artifact.sizeBytes as number) < 0
    || (artifact.sizeBytes as number) > 64 * 1024
    || payload.stdout.length > 64 * 1024
    || payload.stderr.length > 64 * 1024
  ) {
    protocolError("power_tool_observation_invalid");
  }
  const interactiveId = payload.interactiveId;
  const interactiveKind = payload.interactiveKind;
  const rawCandidateReviewRequired = payload.candidateReviewRequired;
  const rawCandidateCount = payload.candidateCount;
  if (
    (interactiveId === undefined) !== (interactiveKind === undefined)
    || (interactiveId !== undefined && typeof interactiveId !== "string")
    || (interactiveKind !== undefined && interactiveKind !== "pty" && interactiveKind !== "gdb" && interactiveKind !== "tube")
    || (rawCandidateReviewRequired !== undefined && typeof rawCandidateReviewRequired !== "boolean")
    || (rawCandidateCount !== undefined
      && (typeof rawCandidateCount !== "number"
        || !Number.isSafeInteger(rawCandidateCount)
        || rawCandidateCount < 0
        || rawCandidateCount > 1_024))
  ) {
    protocolError("power_tool_observation_invalid");
  }
  const candidateReviewRequired = rawCandidateReviewRequired === undefined
    ? false
    : rawCandidateReviewRequired as boolean;
  const candidateCount = rawCandidateCount === undefined ? 0 : rawCandidateCount as number;
  if (candidateReviewRequired !== (candidateCount > 0)) {
    protocolError("power_tool_observation_invalid");
  }
  return {
    artifact: { id: artifact.id, sha256: artifact.sha256, sizeBytes: artifact.sizeBytes as number },
    stdout: payload.stdout,
    stderr: payload.stderr,
    exitCode: payload.exitCode as number | null,
    timedOut: payload.timedOut,
    outputTruncated: payload.outputTruncated,
    candidateReviewRequired,
    candidateCount,
    ...(interactiveId === undefined ? {} : { interactiveId, interactiveKind: interactiveKind as "pty" | "gdb" | "tube" }),
  };
}

/**
 * This is deliberately the only fetch-capable object in Pi Runner. The base
 * URL is allowlisted by RunnerConfig and every call uses a static internal
 * route prefix, which prevents a model/custom-tool argument becoming a URL.
 */
export class ControlClient {
  public constructor(private readonly config: RunnerConfig) {}

  public async claim(): Promise<AgentJob | null> {
    const response = await this.post("/internal/agent-jobs/claim", {
      runner_id: this.config.runnerId,
      lease_seconds: 30,
    });
    return controlContract.claimedJob(response);
  }

  public async getStartSessionWork(lease: Lease): Promise<StartSessionWork> {
    return controlContract.startSessionWork(await this.leasePost(lease, "/work"));
  }

  public async reserveSession(lease: Lease): Promise<{
    readonly session: AgentSession;
    readonly task: StartSessionWork["task"];
    readonly context_manifest: StartSessionWork["context_manifest"];
  }> {
    return controlContract.sessionReservation(await this.leasePost(lease, "/session-reservation"));
  }

  public async activateSession(lease: Lease, sessionId: string): Promise<AgentSession> {
    return controlContract.agentSession(await this.leasePost(lease, "/session-activation", { session_id: sessionId }));
  }

  public async getTurnWork(lease: Lease): Promise<TurnWork> {
    return controlContract.turnWork(await this.leasePost(lease, "/work"));
  }

  public async getSteerWork(lease: Lease): Promise<SteerWork> {
    return controlContract.steerWork(await this.leasePost(lease, "/work"));
  }

  public async getSessionWork(lease: Lease, kind: "abort" | "dispose"): Promise<SessionWork> {
    return controlContract.sessionWork(await this.leasePost(lease, "/work"), kind);
  }

  /** Resolve an M-PI-2 Power job without falling through the v0.1 kernel ABI. */
  public async getPowerSessionWork(lease: Lease): Promise<PowerSessionWork> {
    return controlContract.powerSessionWork(await this.leasePost(lease, "/power-work"));
  }

  public async completePowerSessionStart(lease: Lease): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/power-start-completion"));
  }

  /** Renew only the potentially long-running Power model/start lease. */
  public async renewPowerSessionStartLease(lease: Lease): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/power-start-lease-renewal"));
  }

  public async completePowerSteer(
    lease: Lease,
    deliveredWhileStreaming: boolean,
  ): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/power-steer-completion", {
      delivered_while_streaming: deliveredWhileStreaming,
    }));
  }

  public async completePowerAbort(lease: Lease): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/power-abort-completion"));
  }

  /**
   * Persist one cumulative Pi usage delta after a Power model turn settles.
   * The API derives the run/session identity from the live lease; the runner
   * sends only counters and never a transcript, model output or credential.
   */
  public async reportPowerUsage(lease: TurnLease, usage: PowerUsageDelta): Promise<void> {
    if (!lease.sessionId) {
      protocolError("power_usage_session_id_invalid");
    }
    const payload = await this.leasePost(lease, "/power-usage", {
      session_id: lease.sessionId,
      input_tokens: usage.inputTokens,
      output_tokens: usage.outputTokens,
      cache_read_tokens: usage.cacheReadTokens,
      cache_write_tokens: usage.cacheWriteTokens,
      cost_usd: usage.costUsd,
      compacted: usage.compacted,
    });
    if (
      payload === null
      || typeof payload !== "object"
      || Array.isArray(payload)
      || Object.keys(payload).length !== 1
      || typeof (payload as Record<string, unknown>).accepted !== "boolean"
    ) {
      protocolError("power_usage_receipt_invalid");
    }
    if ((payload as Record<string, unknown>).accepted !== true) {
      protocolError("power_pi_budget_exhausted");
    }
  }

  /**
   * Send one runner-redacted, visible Pi snippet. This static endpoint is
   * telemetry only; callers keep it best-effort so a display outage cannot
   * cause a sandbox action or model turn to be replayed.
   */
  public async reportPowerActivity(
    lease: TurnLease,
    kind: PowerActivityKind,
    content: string,
  ): Promise<void> {
    if (!lease.sessionId) {
      protocolError("power_activity_session_id_invalid");
    }
    if ((kind !== "prompt" && kind !== "response") || content.length < 1 || content.length > 2_000) {
      protocolError("power_activity_invalid");
    }
    const payload = await this.leasePost(lease, "/power-activity", {
      session_id: lease.sessionId,
      kind,
      content,
    });
    if (
      payload === null
      || typeof payload !== "object"
      || Array.isArray(payload)
      || Object.keys(payload).length !== 1
      || (payload as Record<string, unknown>).accepted !== true
    ) {
      protocolError("power_activity_receipt_invalid");
    }
  }

  /**
   * Persist one runner-redacted terminal record for a completed Power tool.
   * This is telemetry only: callers retain it locally if the display route is
   * unavailable so that an already completed sandbox action is never replayed.
   */
  public async reportPowerToolTranscript(
    lease: TurnLease,
    transcript: PowerToolTranscript,
    idempotencyKey: string,
  ): Promise<void> {
    if (!lease.sessionId) {
      protocolError("power_tool_transcript_session_id_invalid");
    }
    if (
      !/^ctf_[a-z0-9_]{2,59}$/.test(transcript.tool)
      || transcript.command.length < 1
      || transcript.command.length > 2_000
      || transcript.output.length < 1
      || transcript.output.length > 6_000
      || (transcript.exitCode !== null && (!Number.isSafeInteger(transcript.exitCode) || transcript.exitCode < -255 || transcript.exitCode > 255))
      || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(idempotencyKey)
    ) {
      protocolError("power_tool_transcript_invalid");
    }
    const payload = await this.leasePost(lease, "/power-tool-transcript", {
      session_id: lease.sessionId,
      tool: transcript.tool,
      command: transcript.command,
      output: transcript.output,
      exit_code: transcript.exitCode,
      timed_out: transcript.timedOut,
      output_truncated: transcript.outputTruncated,
      idempotency_key: idempotencyKey,
    });
    if (
      payload === null
      || typeof payload !== "object"
      || Array.isArray(payload)
      || Object.keys(payload).length !== 1
      || (payload as Record<string, unknown>).accepted !== true
    ) {
      protocolError("power_tool_transcript_receipt_invalid");
    }
  }

  public async appendEvents(lease: Lease, events: readonly AgentBridgeEvent[]): Promise<void> {
    if (events.length === 0 || events.length > 128) {
      protocolError("agent_event_batch_invalid");
    }
    const validated = events.map(validateBridgeEvent);
    const response = await this.leasePost(lease, "/events", { events: validated });
    controlContract.eventBatchAck(response);
  }

  public async completeTurn(lease: Lease, resultRef: string): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/turn-completion", { result_ref: resultRef }));
  }

  public async completeSteer(lease: Lease): Promise<AgentSteer> {
    return controlContract.agentSteer(await this.leasePost(lease, "/steer-completion"));
  }

  public async completeAbort(lease: Lease): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/abort-completion"));
  }

  public async completeDispose(lease: Lease): Promise<AgentJob> {
    return controlContract.agentJob(await this.leasePost(lease, "/dispose-completion"));
  }

  public async submitFinding(lease: Lease, finding: FindingSubmission): Promise<{ readonly findingId: string }> {
    const response = await this.leasePost(lease, "/finding-submissions", {
      finding: validateFindingSubmission(finding),
    });
    return { findingId: controlContract.findingSubmission(response).finding_id };
  }

  /** Submit a declarative plan to the static candidate route; no target URL is sent. */
  public async submitCandidate(
    lease: Lease,
    candidate: ExploitCandidateSubmission,
  ): Promise<{ readonly candidateId: string }> {
    const response = await this.leasePost(lease, "/candidate-submissions", {
      candidate: validateCandidateSubmission(candidate),
    });
    return controlContract.candidateSubmission(response);
  }

  public async delegateTask(
    lease: Lease,
    delegation: TaskDelegationRequest,
  ): Promise<{ readonly taskId: string; readonly sessionJobId: string }> {
    const response = await this.leasePost(lease, "/task-delegations", {
      delegation: validateTaskDelegation(delegation),
    });
    const parsed = controlContract.taskDelegation(response);
    return { taskId: parsed.task.id, sessionJobId: parsed.session_job.id };
  }

  public async getState(lease: Lease, sessionId: string): Promise<PiRunState> {
    return controlContract.piRunState(await this.leasePost(lease, "/session-state", { session_id: sessionId }));
  }

  /**
   * Give an exploit builder the small, manifest-derived capture contract it
   * needs to form a candidate. This is deliberately separate from state.get
   * so the builder receives no operator hints or broader coordination state.
   */
  public async getFlagCapturePatterns(
    lease: Lease,
    sessionId: string,
  ): Promise<FlagCapturePatterns> {
    return controlContract.flagCapturePatterns(
      await this.leasePost(lease, "/flag-capture-patterns", { session_id: sessionId }),
    );
  }

  /**
   * Send a source-only custom-tool call to the static control API route. The
   * runner can neither choose the next hop nor learn a sandbox slot address;
   * the API and gateway bind it to the active lease independently.
   */
  public async requestTool(
    lease: Lease,
    request: GatewayToolRequest,
  ): Promise<ToolGatewayResponse> {
    const validated = validateGatewayToolRequest(request);
    const response = await this.leasePost(lease, "/tool-requests", {
      session_id: validated.session_id,
      call: { ...validated.call },
    });
    return controlContract.toolGatewayResponse(response, validated);
  }

  public async fail(lease: Lease, reason: string): Promise<AgentJob> {
    if (!/^[a-z][a-z0-9_:-]{0,159}$/.test(reason)) {
      protocolError("runner_failure_reason_invalid");
    }
    return controlContract.agentJob(await this.leasePost(lease, "/failure", { reason }));
  }

  public async failPower(lease: Lease, reason: string): Promise<AgentJob> {
    if (!/^[a-z][a-z0-9_:-]{0,159}$/.test(reason)) {
      protocolError("runner_failure_reason_invalid");
    }
    return controlContract.agentJob(await this.leasePost(lease, "/power-failure", { reason }));
  }

  /**
   * Power's typed tool facade. Workspace IDs are intentionally discarded at
   * this hop: the API derives them from the active job/session lease.
   */
  public async exec(lease: TurnLease, request: PowerExecRequest): Promise<PowerToolObservation> {
    return this.powerObservation(lease, "exec", {
      command: [...request.command], timeout_seconds: request.timeoutSeconds, working_directory: request.workingDirectory,
    }, request.toolName);
  }

  public async ptyStart(lease: TurnLease, request: PowerPtyStartRequest): Promise<PowerToolObservation> {
    return this.powerObservation(lease, "pty_start", {
      command: [...request.command], timeout_seconds: request.timeoutSeconds, working_directory: request.workingDirectory,
    });
  }

  public async ptySend(lease: TurnLease, request: PowerPtySendRequest): Promise<PowerChannelReceipt> {
    return this.powerChannel(lease, "pty_send", { pty_id: request.ptyId, data: request.data });
  }

  public async ptyRead(lease: TurnLease, request: PowerPtyReadRequest): Promise<PowerToolObservation> {
    return this.powerObservation(lease, "pty_read", {
      pty_id: request.ptyId, max_bytes: request.maxBytes, wait_ms: request.waitMs, kind: request.kind,
    });
  }

  public async ptyClose(lease: TurnLease, request: PowerPtyCloseRequest): Promise<PowerChannelReceipt> {
    return this.powerChannel(lease, "pty_close", { pty_id: request.ptyId });
  }

  public async tubeConnect(lease: TurnLease, request: PowerTubeConnectRequest): Promise<PowerToolObservation> {
    return this.powerObservation(lease, "tube_connect", {
      host: request.host, port: request.port, timeout_seconds: request.timeoutSeconds,
    });
  }

  public async tubeSend(lease: TurnLease, request: PowerTubeSendRequest): Promise<PowerChannelReceipt> {
    return this.powerChannel(lease, "tube_send", { tube_id: request.tubeId, data_base64: request.dataBase64 });
  }

  public async tubeReceive(lease: TurnLease, request: PowerTubeReceiveRequest): Promise<PowerToolObservation> {
    return this.powerObservation(lease, "tube_receive", {
      tube_id: request.tubeId,
      delimiter_base64: request.delimiterBase64,
      max_bytes: request.maxBytes,
      timeout_seconds: request.timeoutSeconds,
    });
  }

  public async tubeClose(lease: TurnLease, request: PowerTubeCloseRequest): Promise<PowerChannelReceipt> {
    return this.powerChannel(lease, "tube_close", { tube_id: request.tubeId });
  }

  public async submitFlag(
    lease: TurnLease,
    request: PowerFlagSubmissionRequest,
  ): Promise<PowerFlagSubmissionReceipt> {
    return this.powerFlag(lease, {
      candidate: request.candidate,
      observation_artifact_id: request.observationArtifactId,
      observation_sha256: request.observationSha256,
    });
  }

  /**
   * Re-read a window of an already stored observation.
   *
   * This crosses no sandbox boundary: the bytes are committed evidence in the
   * local CAS, and the control plane re-checks that they belong to this run
   * and were produced by sandboxd before returning any of them.
   */
  public async readArtifact(
    lease: TurnLease,
    request: PowerArtifactReadRequest,
  ): Promise<PowerArtifactWindow> {
    const payload = await this.powerRequest(lease, "artifact_read", {
      artifact_id: request.artifactId,
      offset: request.offset,
      length: request.length,
    });
    return parsePowerArtifactWindow(payload);
  }

  private async leasePost(lease: Lease, suffix: string, extra: Record<string, unknown> = {}): Promise<unknown> {
    return this.post(`/internal/agent-jobs/${encodeURIComponent(lease.jobId)}${suffix}`, {
      runner_id: this.config.runnerId,
      lease_version: lease.leaseVersion,
      ...extra,
    });
  }

  private async powerRequest(
    lease: TurnLease,
    action: string,
    arguments_: Record<string, unknown>,
    toolName?: PowerToolName,
  ): Promise<unknown> {
    if (!lease.sessionId) {
      protocolError("power_tool_session_id_invalid");
    }
    return this.leasePost(lease, "/power-tool-requests", {
      session_id: lease.sessionId,
      action,
      arguments: arguments_,
      ...(toolName === undefined ? {} : { tool_name: toolName }),
    });
  }

  private async powerObservation(
    lease: TurnLease,
    action: string,
    arguments_: Record<string, unknown>,
    toolName?: PowerToolName,
  ): Promise<PowerToolObservation> {
    const payload = await this.powerRequest(lease, action, arguments_, toolName);
    return parsePowerObservation(payload);
  }

  private async powerChannel(
    lease: TurnLease,
    action: string,
    arguments_: Record<string, unknown>,
  ): Promise<PowerChannelReceipt> {
    const payload = await this.powerRequest(lease, action, arguments_);
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      protocolError("power_tool_channel_receipt_invalid");
    }
    const record = payload as Record<string, unknown>;
    if (Object.keys(record).length !== 1 || (record.state !== "open" && record.state !== "closed")) {
      protocolError("power_tool_channel_receipt_invalid");
    }
    return { state: record.state };
  }

  private async powerFlag(
    lease: TurnLease,
    arguments_: Record<string, unknown>,
  ): Promise<PowerFlagSubmissionReceipt> {
    const payload = await this.powerRequest(lease, "flag_submit", arguments_);
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      protocolError("power_tool_flag_receipt_invalid");
    }
    const record = payload as Record<string, unknown>;
    if (Object.keys(record).length !== 1 || typeof record.accepted !== "boolean") {
      protocolError("power_tool_flag_receipt_invalid");
    }
    return { accepted: record.accepted };
  }

  private async post(path: string, payload: Record<string, unknown>): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      let response: Response;
      try {
        response = await fetch(`${this.config.controlBaseUrl}${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-ctfmesh-runner-token": this.config.controlToken,
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") {
          protocolError("control_request_timeout");
        }
        protocolError("control_transport_failed");
      }
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        protocolError("control_response_not_json");
      }
      if (!response.ok) {
        const code = safeServerCode(body);
        protocolError(code === null ? "control_request_rejected" : `control_${code}`);
      }
      return body;
    } finally {
      clearTimeout(timeout);
    }
  }
}
