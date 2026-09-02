/**
 * Bounded, operator-visible activity from a private Pi session.
 *
 * This is an operator-facing, bounded Pi feed. It records the prompt,
 * visible assistant text, and the exact reviewed tool command/output that Pi
 * received. Thinking blocks and provider diagnostics remain private. Values
 * that could be credentials, session secrets, or raw flags are redacted
 * before they leave the runner; complete command output remains in its
 * immutable observation artifact.
 */

import type { AgentSessionEvent } from "@earendil-works/pi-coding-agent";
import { randomUUID } from "node:crypto";

import type { ControlClient } from "./control-client.js";
import type { TurnLease } from "./tools.js";

export const POWER_ACTIVITY_MAX_CHARS = 2_000;
export const POWER_TOOL_TRANSCRIPT_MAX_CHARS = 6_000;

export type PowerActivityKind = "prompt" | "response";

/** One bounded terminal-like record for a completed custom-tool operation. */
export interface PowerToolTranscript {
  readonly tool: string;
  readonly command: string;
  readonly output: string;
  readonly exitCode: number | null;
  readonly timedOut: boolean;
  readonly outputTruncated: boolean;
}

type PowerActivityItem =
  | { readonly kind: PowerActivityKind; readonly content: string }
  | {
    readonly kind: "tool";
    readonly transcript: PowerToolTranscript;
    /** Stable for retries while this Pi session remains alive. */
    readonly idempotencyKey: string;
  };
const RAW_FLAG = /\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:-]{1,512}\}/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const API_KEY = /\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{16,})\b/g;
const SECRET_ASSIGNMENT = /\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+/gi;

/** Redact before crossing the runner boundary and keep the UI excerpt small. */
export function redactPowerActivityText(
  value: string,
  maximumCharacters = POWER_ACTIVITY_MAX_CHARS,
): string {
  const redacted = value
    .replace(RAW_FLAG, "[REDACTED_FLAG]")
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(API_KEY, "[REDACTED_API_KEY]")
    .replace(SECRET_ASSIGNMENT, "[REDACTED_SECRET]")
    .trim();
  if (redacted.length <= maximumCharacters) {
    return redacted;
  }
  return `${redacted.slice(0, maximumCharacters - 24)}…[TRUNCATED]`;
}

/**
 * Extract visible assistant prose only. Pi's `ThinkingContent` and tool call
 * blocks intentionally have no representation here, even when a provider
 * streams them alongside normal text.
 */
export function visibleAssistantText(event: AgentSessionEvent): string | null {
  if (event.type !== "message_end" || event.message.role !== "assistant") {
    return null;
  }
  const text = event.message.content
    .filter((block): block is { readonly type: "text"; readonly text: string } => (
      block.type === "text" && typeof block.text === "string"
    ))
    .map((block) => block.text)
    .join("\n");
  const safe = redactPowerActivityText(text);
  return safe || null;
}

/**
 * A loss of activity telemetry must never replay or fail a completed tool
 * action. Pending items therefore remain local until a successful static API
 * acknowledgement, while callers choose when to best-effort flush them.
 */
export class PowerActivityReporter {
  private pending: PowerActivityItem[] = [];
  private readonly transcriptEpoch = randomUUID();
  private nextToolTranscript = 1;

  public constructor(
    private readonly control: Pick<ControlClient, "reportPowerActivity" | "reportPowerToolTranscript">,
  ) {}

  public recordPrompt(content: string): void {
    this.record("prompt", content);
  }

  public capture(event: AgentSessionEvent): void {
    const text = visibleAssistantText(event);
    if (text !== null) {
      this.record("response", text);
    }
  }

  /**
   * Queue the terminal record that describes a completed typed tool call.
   * The tool adapter replaces write/send/flag payloads with byte-count
   * summaries before this point, so sensitive input never becomes activity.
   */
  public recordTool(transcript: PowerToolTranscript): void {
    if (!/^ctf_[a-z0-9_]{2,59}$/.test(transcript.tool)) {
      return;
    }
    const command = redactPowerActivityText(transcript.command, POWER_ACTIVITY_MAX_CHARS);
    const output = redactPowerActivityText(transcript.output, POWER_TOOL_TRANSCRIPT_MAX_CHARS);
    if (!command || !output) {
      return;
    }
    this.pending.push({
      kind: "tool",
      transcript: {
        tool: transcript.tool,
        command,
        output,
        exitCode: transcript.exitCode,
        timedOut: transcript.timedOut,
        outputTruncated: transcript.outputTruncated || output.includes("[TRUNCATED]"),
      },
      idempotencyKey: `tool-${this.transcriptEpoch}-${this.nextToolTranscript++}`,
    });
  }

  public async flush(lease: TurnLease): Promise<void> {
    while (this.pending.length > 0) {
      const item = this.pending[0];
      if (item === undefined) {
        return;
      }
      if (item.kind === "tool") {
        await this.control.reportPowerToolTranscript(lease, item.transcript, item.idempotencyKey);
      } else {
        await this.control.reportPowerActivity(lease, item.kind, item.content);
      }
      this.pending.shift();
    }
  }

  private record(kind: PowerActivityKind, content: string): void {
    const safe = redactPowerActivityText(content);
    if (safe) {
      this.pending.push({ kind, content: safe });
    }
  }
}
