/**
 * Secret-free Pi usage accounting for one durable Power session.
 *
 * Pi owns provider communication and its session transcript.  The control
 * plane only receives deltas made of counters and a provider-calculated cost;
 * no prompt, completion, tool argument, error, credential or flag can cross
 * this seam.  A positive observed cost may debit the run budget, but a usage
 * report can never refund or enlarge that budget.
 */

import type { AgentSession, AgentSessionEvent } from "@earendil-works/pi-coding-agent";

import { ControlProtocolError } from "./contracts.js";

export interface PowerUsageDelta {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens: number;
  readonly cacheWriteTokens: number;
  readonly costUsd: number;
  readonly compacted: number;
}

interface PowerUsageTotals {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadTokens: number;
  readonly cacheWriteTokens: number;
  readonly costUsd: number;
}

const MAX_USAGE_TOKENS = 10_000_000;
const MAX_USAGE_COST_USD = 1_000_000;

function nonNegativeInteger(value: number, code: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_USAGE_TOKENS) {
    throw new ControlProtocolError(code);
  }
  return value;
}

function nonNegativeCost(value: number): number {
  if (!Number.isFinite(value) || value < 0 || value > MAX_USAGE_COST_USD) {
    throw new ControlProtocolError("power_pi_usage_cost_invalid");
  }
  return value;
}

function sessionTotals(session: AgentSession): PowerUsageTotals {
  const stats = session.getSessionStats();
  return {
    inputTokens: nonNegativeInteger(stats.tokens.input, "power_pi_usage_input_invalid"),
    outputTokens: nonNegativeInteger(stats.tokens.output, "power_pi_usage_output_invalid"),
    cacheReadTokens: nonNegativeInteger(stats.tokens.cacheRead, "power_pi_usage_cache_read_invalid"),
    cacheWriteTokens: nonNegativeInteger(stats.tokens.cacheWrite, "power_pi_usage_cache_write_invalid"),
    costUsd: nonNegativeCost(stats.cost),
  };
}

function changed(current: PowerUsageTotals, previous: PowerUsageTotals): PowerUsageDelta {
  const inputTokens = current.inputTokens - previous.inputTokens;
  const outputTokens = current.outputTokens - previous.outputTokens;
  const cacheReadTokens = current.cacheReadTokens - previous.cacheReadTokens;
  const cacheWriteTokens = current.cacheWriteTokens - previous.cacheWriteTokens;
  const costUsd = current.costUsd - previous.costUsd;
  if (
    inputTokens < 0
    || outputTokens < 0
    || cacheReadTokens < 0
    || cacheWriteTokens < 0
    || costUsd < -Number.EPSILON
  ) {
    // A reopened transcript must have monotonically increasing cumulative
    // counters. Reporting a lower value could otherwise manufacture a refund.
    throw new ControlProtocolError("power_pi_usage_not_monotonic");
  }
  return {
    inputTokens,
    outputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    costUsd: Math.max(0, costUsd),
    compacted: 0,
  };
}

/** Collect per-job deltas from Pi without exposing its transcript. */
export class PowerUsageReporter {
  private reported: PowerUsageTotals;
  private successfulCompactions = 0;

  public constructor(private readonly session: AgentSession) {
    // A reopened durable session already contains earlier billed turns. Start
    // from that baseline so a runner restart does not debit them a second time.
    this.reported = sessionTotals(session);
  }

  public capture(event: AgentSessionEvent): void {
    if (event.type === "compaction_end" && event.result !== undefined && !event.aborted) {
      this.successfulCompactions += 1;
    }
  }

  public pending(): PowerUsageDelta | null {
    const delta = changed(sessionTotals(this.session), this.reported);
    const compacted = this.successfulCompactions;
    if (
      delta.inputTokens === 0
      && delta.outputTokens === 0
      && delta.cacheReadTokens === 0
      && delta.cacheWriteTokens === 0
      && delta.costUsd === 0
      && compacted === 0
    ) {
      return null;
    }
    return { ...delta, compacted };
  }

  /** Advance the local checkpoint only after the control plane accepts it. */
  public acknowledge(): void {
    this.reported = sessionTotals(this.session);
    this.successfulCompactions = 0;
  }
}
