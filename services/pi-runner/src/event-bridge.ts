/** Convert Pi SDK lifecycle signals into bounded, secret-free audit events. */

import { createHash } from "node:crypto";

import type { AgentSessionEvent } from "@earendil-works/pi-coding-agent";

import type { AgentBridgeEvent, AgentEventType } from "./contracts.js";
import { validateBridgeEvent } from "./contracts.js";

function sha256(value: unknown): string {
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    encoded = "[unserializable-pi-event]";
  }
  return createHash("sha256").update(encoded ?? "null", "utf8").digest("hex");
}

/**
 * Raw provider output, chain-of-thought, tool arguments and errors never leave
 * Pi through this class. The event record contains only stable lifecycle data
 * plus SHA-256 digests that can be correlated during an authorized audit.
 */
export class EventBridge {
  private sequence = 0;
  private pending: AgentBridgeEvent[] = [];

  public constructor(private readonly sessionId: string) {}

  public lifecycle(type: AgentEventType, fields: Omit<AgentBridgeEvent, "sequence" | "type" | "session_id" | "occurred_at"> = {}): void {
    this.record({ type, ...fields });
  }

  public capture(event: AgentSessionEvent): void {
    switch (event.type) {
      case "agent_start":
        this.record({ type: "agent.turn.started" });
        return;
      case "agent_end":
        this.record(
          event.willRetry
            ? { type: "agent.session.retry", retry_attempt: 1 }
            : { type: "agent.turn.completed" },
        );
        return;
      case "tool_execution_start":
        this.record({
          type: "agent.tool.started",
          tool_name: event.toolName,
          input_digest: sha256(event.args),
        });
        return;
      case "tool_execution_end":
        this.record({
          type: "agent.tool.completed",
          tool_name: event.toolName,
          output_digest: sha256(event.result),
        });
        return;
      case "auto_retry_start":
      case "summarization_retry_scheduled":
        this.record({ type: "agent.session.retry", retry_attempt: event.attempt });
        return;
      case "compaction_end":
        this.record({ type: "agent.session.compacted" });
        return;
      case "auto_retry_end":
        if (!event.success) {
          this.record({ type: "agent.error", error_code: "provider_retry_failed" });
        }
        return;
      default:
        // Message chunks and thinking deltas deliberately have no bridge form.
        return;
    }
  }

  public error(errorCode: string): void {
    this.record({ type: "agent.error", error_code: errorCode });
  }

  public drain(): AgentBridgeEvent[] {
    const drained = this.pending;
    this.pending = [];
    return drained;
  }

  private record(fields: Omit<AgentBridgeEvent, "sequence" | "session_id" | "occurred_at">): void {
    const event = validateBridgeEvent({
      sequence: ++this.sequence,
      session_id: this.sessionId,
      occurred_at: new Date().toISOString(),
      ...fields,
    });
    this.pending.push(event);
  }
}
