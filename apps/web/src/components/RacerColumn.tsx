import { useState, type FormEvent } from "react";

export type RacerViewState =
  | "queued"
  | "briefing"
  | "running"
  | "bumped"
  | "verifying"
  | "stopped"
  | "failed"
  | "cancelled"
  | "solved";

interface RacerColumnProps {
  label: "A" | "B" | "C";
  lane: string;
  state: RacerViewState;
  actionCount: number;
  observationCount: number;
  lastAction: string;
  fingerprint?: string;
  activity?: readonly RacerActivityMessage[];
  transcripts?: readonly RacerToolTranscript[];
  onSteer?: (message: string) => Promise<void>;
}

export interface RacerActivityMessage {
  id: string;
  kind: "prompt" | "response";
  content: string;
  occurredAt: string;
}

/** A server-reviewed terminal record for one completed Pi custom-tool call. */
export interface RacerToolTranscript {
  id: string;
  tool: string;
  command: string;
  output: string;
  exitCode: number | null;
  timedOut: boolean;
  outputTruncated: boolean;
  occurredAt: string;
}

const STATE_LABELS: Record<RacerViewState, string> = {
  queued: "Queued",
  briefing: "Briefing",
  running: "Running",
  bumped: "Bumped",
  verifying: "Verifying",
  stopped: "Stopped",
  failed: "Failed",
  cancelled: "Cancelled",
  solved: "Solved",
};

/**
 * One fixed phrase per custom tool.
 *
 * Section 4.5 of the design guide asks the racer column for a settled
 * vocabulary rather than argv: the operator needs to know which move the
 * racer made, and the exact bytes belong to the observation trail.
 */
const TOOL_ACTIONS: Record<string, string> = {
  ctf_artifact_read: "Reread a sealed artifact",
  ctf_flag_submit: "Submitted a flag candidate",
  ctf_fs_list: "Listed a workspace directory",
  ctf_fs_read: "Read a workspace file",
  ctf_fs_write: "Wrote a workspace file",
  ctf_gdb_close: "Closed the debugger",
  ctf_gdb_cmd: "Ran a debugger command",
  ctf_gdb_read: "Read debugger output",
  ctf_gdb_start: "Started the debugger",
  ctf_pty_close: "Closed a terminal",
  ctf_pty_read: "Read from a terminal",
  ctf_pty_send: "Sent input to a terminal",
  ctf_pty_start: "Started a terminal",
  ctf_shell_exec: "Ran a workspace command",
  ctf_tube_close: "Closed the target connection",
  ctf_tube_connect: "Opened the target connection",
  ctf_tube_recv: "Read from the target",
  ctf_tube_send: "Sent bytes to the target",
};

/** Size of one captured result, in the units an operator scans for. */
function captured(output: string): string {
  const bytes = output.length;
  return bytes < 1_024 ? `${bytes} B captured` : `${(bytes / 1_024).toFixed(1)} KB captured`;
}

/**
 * Render one live Power racer projection.
 *
 * The parent passes only server-reviewed values: Pi prose plus bounded tool
 * command/output records. This component never receives an arbitrary event
 * payload, raw flag, provider credential, or immutable artifact body.
 */
export function RacerColumn({
  label,
  lane,
  state,
  actionCount,
  observationCount,
  lastAction,
  fingerprint,
  activity = [],
  transcripts = [],
  onSteer,
}: RacerColumnProps) {
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const latestTranscript = transcripts.at(-1);
  const isLive = state === "briefing" || state === "running";

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const trimmed = message.trim();
    if (!trimmed || !onSteer || sending) return;
    setSending(true);
    setError(null);
    try {
      await onSteer(trimmed);
      setMessage("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Suggestion was not accepted.");
    } finally {
      setSending(false);
    }
  }

  return (
    <li className="power-racer-column" data-state={state} aria-label={`Racer ${label}`}>
      <header>
        <span className="power-racer-letter" aria-hidden="true">{label}</span>
        <span className="power-racer-name">
          <strong>Racer {label}</strong>
          <small>{lane}</small>
        </span>
        <span className="power-racer-state">
          <i aria-hidden="true" /> {STATE_LABELS[state]}
        </span>
      </header>
      <dl>
        <div>
          <dt>Actions</dt>
          <dd>{actionCount}</dd>
        </div>
        <div>
          <dt>Observations</dt>
          <dd>{observationCount}</dd>
        </div>
      </dl>
      <p>
        <span>Last action</span>
        <strong>{lastAction}</strong>
      </p>
      {fingerprint ? <code title={fingerprint}>fp {fingerprint.slice(0, 8)}</code> : null}
      <section
        className="power-racer-live-io"
        data-live={isLive}
        aria-label={`Racer ${label} latest receipt`}
        aria-live={isLive ? "polite" : "off"}
      >
        <header>
          <span>Latest receipt</span>
          <small>{isLive ? "updating" : "last result"}</small>
        </header>
        {latestTranscript ? (
          <>
            <footer>
              <code>{latestTranscript.tool}</code>
              <span>{latestTranscript.exitCode === null ? "n/a" : `exit ${latestTranscript.exitCode}`}</span>
              {latestTranscript.timedOut ? <span className="power-terminal-timeout">timeout</span> : null}
              <span>{captured(latestTranscript.output)}</span>
              {latestTranscript.outputTruncated ? <span>capped</span> : null}
            </footer>
          </>
        ) : <p>{isLive ? "Waiting for the first move…" : "No move yet."}</p>}
      </section>
      <details className="power-racer-terminal">
        <summary title="Reviewed command and bounded output. Credentials and raw flags are redacted.">
          History <span>{transcripts.length}</span>
        </summary>
        {transcripts.length > 0 ? (
          <ol aria-label={`Racer ${label} tool terminal`}>
            {transcripts.slice(-8).map((item) => (
              <li key={item.id}>
                <header>
                  <code>{item.tool}</code>
                  <span>{item.exitCode === null ? "n/a" : `exit ${item.exitCode}`}</span>
                  {item.timedOut ? <span className="power-terminal-timeout">timeout</span> : null}
                  <span>{captured(item.output)}</span>
                </header>
                <strong>{TOOL_ACTIONS[item.tool] ?? "Ran a tool"}</strong>
                <details className="power-racer-bytes">
                  <summary>Bytes</summary>
                  <pre aria-label={`Racer ${label} command`}><code>$ {item.command}</code></pre>
                  <pre aria-label={`Racer ${label} output`}>{item.output}</pre>
                  {item.outputTruncated ? <small>… output capped</small> : null}
                </details>
              </li>
            ))}
          </ol>
        ) : <p className="power-racer-feed-empty">Waiting for the first tool result.</p>}
      </details>
      <details className="power-racer-feed">
        <summary>Pi feed <span>{activity.length}</span></summary>
        {activity.length > 0 ? (
          <ol aria-label={`Racer ${label} Pi activity`}>
            {activity.slice(-4).map((item) => (
              <li key={item.id} data-kind={item.kind}>
                <span>{item.kind === "prompt" ? "IN" : "OUT"}</span>
                <p>{item.content}</p>
              </li>
            ))}
          </ol>
        ) : <p className="power-racer-feed-empty">No visible Pi message yet.</p>}
        {onSteer ? (
          <form onSubmit={(event) => void submit(event)}>
            <label htmlFor={`racer-${label}-steer`}>Direct racer {label}</label>
            <div>
              <input
                id={`racer-${label}-steer`}
                value={message}
                maxLength={2_000}
                placeholder="Suggest a next evidence path…"
                onChange={(event) => setMessage(event.target.value)}
              />
              <button type="submit" disabled={!message.trim() || sending}>
                {sending ? "…" : "Send"}
              </button>
            </div>
            {error ? <small role="alert">{error}</small> : null}
          </form>
        ) : null}
      </details>
    </li>
  );
}
