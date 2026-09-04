import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";

export type RacerViewState =
  | "queued"
  | "briefing"
  | "running"
  | "review"
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
  /** Whether this lane shows the full terminal stream rather than a receipt. */
  followed?: boolean;
  onToggleFollow?: () => void;
  /** Release one observation's sealed bytes to the operator's machine. */
  onSaveArtifact?: (artifactId: string) => Promise<void>;
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
  /**
   * The immutable observation this receipt summarises, when the runner
   * supplied it. The rendered output is redacted and capped, so this is the
   * only route from a receipt to the evidence behind it.
   */
  artifactId?: string;
  occurredAt: string;
}

/** One reviewed record rendered in the compact, terminal-shaped racer stream. */
type RacerTerminalEntry =
  | { id: string; kind: "prompt" | "response"; content: string; occurredAt: string }
  | { id: string; kind: "tool"; transcript: RacerToolTranscript; occurredAt: string };

function terminalTime(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(date);
}

function terminalEntries(
  activity: readonly RacerActivityMessage[],
  transcripts: readonly RacerToolTranscript[],
): RacerTerminalEntry[] {
  // The API already validates/redacts every record. Sort only that reviewed
  // projection so command, result, and Pi status read in their actual order.
  return [
    ...activity.map((item) => ({
      id: `pi-${item.id}`,
      kind: item.kind,
      content: item.content,
      occurredAt: item.occurredAt,
    }) as RacerTerminalEntry),
    ...transcripts.map((transcript) => ({
      id: `tool-${transcript.id}`,
      kind: "tool" as const,
      transcript,
      occurredAt: transcript.occurredAt,
    })),
  ]
    .sort((left, right) => {
      const leftTime = Date.parse(left.occurredAt);
      const rightTime = Date.parse(right.occurredAt);
      if (Number.isNaN(leftTime) || Number.isNaN(rightTime)) {
        return left.id.localeCompare(right.id);
      }
      return leftTime - rightTime || left.id.localeCompare(right.id);
    })
    // A constantly noisy racer must not make the three-lane overview unusable.
    .slice(-12);
}

/**
 * One fixed phrase per custom tool.
 *
 * A lane the operator is not following gets a named move and its numbers
 * rather than argv, which is what section 4.5 of the design guide asks the
 * standing column for. The full stream is one click away for the one lane
 * they are actually steering.
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

const STATE_LABELS: Record<RacerViewState, string> = {
  queued: "Queued",
  briefing: "Briefing",
  running: "Running",
  review: "Review",
  bumped: "Bumped",
  verifying: "Verifying",
  stopped: "Stopped",
  failed: "Failed",
  cancelled: "Cancelled",
  solved: "Solved",
};

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
  followed = false,
  onToggleFollow,
  onSaveArtifact,
  onSteer,
}: RacerColumnProps) {
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [steerQueued, setSteerQueued] = useState(false);
  const [savingArtifact, setSavingArtifact] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const streamRef = useRef<HTMLOListElement>(null);
  const followsStream = useRef(true);
  const isLive = state === "briefing" || state === "running";
  const stream = useMemo(() => terminalEntries(activity, transcripts), [activity, transcripts]);
  const latestTranscript = transcripts.at(-1);

  useEffect(() => {
    // Follow only while the operator has not scrolled up to inspect older
    // evidence. This makes updates feel live without stealing their place.
    const streamElement = streamRef.current;
    if (followsStream.current && streamElement) {
      if (typeof streamElement.scrollTo === "function") {
        streamElement.scrollTo({ top: streamElement.scrollHeight, behavior: "smooth" });
      } else {
        // JSDOM and a few older embedded WebViews have no Element#scrollTo.
        streamElement.scrollTop = streamElement.scrollHeight;
      }
    }
  }, [stream]);

  useEffect(() => {
    // A new reviewed terminal record is the acknowledgement that makes a
    // previous steer visible. Do not invent an acknowledgement before that.
    if (stream.length > 0) setSteerQueued(false);
  }, [stream.length]);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const trimmed = message.trim();
    if (!trimmed || !onSteer || sending) return;
    setSending(true);
    setError(null);
    try {
      await onSteer(trimmed);
      setMessage("");
      setSteerQueued(true);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Suggestion was not accepted.");
    } finally {
      setSending(false);
    }
  }

  function sendOnShortcut(event: KeyboardEvent<HTMLTextAreaElement>): void {
    if (event.key !== "Enter" || (!event.ctrlKey && !event.metaKey)) return;
    event.preventDefault();
    event.currentTarget.form?.requestSubmit();
  }

  async function save(artifactId: string): Promise<void> {
    if (!onSaveArtifact || savingArtifact !== null) return;
    setSavingArtifact(artifactId);
    setSaveError(null);
    try {
      await onSaveArtifact(artifactId);
    } catch (reason) {
      setSaveError(reason instanceof Error ? reason.message : "Those bytes were not released.");
    } finally {
      setSavingArtifact(null);
    }
  }

  function trackStreamPosition(): void {
    const streamElement = streamRef.current;
    if (!streamElement) return;
    followsStream.current = streamElement.scrollHeight - streamElement.scrollTop - streamElement.clientHeight < 28;
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
        data-followed={followed}
        aria-label={`Racer ${label} live terminal`}
      >
        <header>
          <span>Pi terminal</span>
          <code>{stream.length} records</code>
          <small>{state === "review" ? "held for review" : isLive ? "following" : "last result"}</small>
        </header>
        {!followed ? (
          // Three lanes advance at once and only one is being steered. A lane
          // the operator is not reading shows what it just did and how it
          // ended; opening it swaps in the full stream below.
          <div className="power-racer-receipt">
            {latestTranscript ? (
              <>
                <strong>{TOOL_ACTIONS[latestTranscript.tool] ?? "Ran a tool"}</strong>
                <p>
                  <code>{latestTranscript.tool}</code>
                  <span>
                    {latestTranscript.exitCode === null ? "n/a" : `exit ${latestTranscript.exitCode}`}
                  </span>
                  {latestTranscript.timedOut ? (
                    <span className="power-terminal-timeout">timeout</span>
                  ) : null}
                  <span>{captured(latestTranscript.output)}</span>
                  {latestTranscript.outputTruncated ? <span>capped</span> : null}
                </p>
              </>
            ) : (
              <p>{isLive ? "Waiting for the first move…" : "No move yet."}</p>
            )}
            {onToggleFollow ? (
              <button type="button" onClick={onToggleFollow}>
                Follow lane {label}
              </button>
            ) : null}
          </div>
        ) : null}
        {followed && stream.length > 0 ? (
          <ol ref={streamRef} onScroll={trackStreamPosition} aria-label={`Racer ${label} live input and output`}>
            {stream.map((entry) => {
              if (entry.kind === "tool") {
                const { transcript } = entry;
                return (
                  <li key={entry.id} data-kind="tool">
                    <header>
                      <time dateTime={entry.occurredAt}>{terminalTime(entry.occurredAt)}</time>
                      <span>TOOL</span>
                      <code>{transcript.tool}</code>
                    </header>
                    <pre aria-label={`Racer ${label} live command`}><code>$ {transcript.command}</code></pre>
                    <pre aria-label={`Racer ${label} live output`}>{transcript.output}</pre>
                    <footer>
                      <span>{transcript.exitCode === null ? "n/a" : `exit ${transcript.exitCode}`}</span>
                      {transcript.timedOut ? <span className="power-terminal-timeout">timeout</span> : null}
                      {transcript.outputTruncated ? <span>output capped</span> : null}
                    </footer>
                  </li>
                );
              }
              return (
                <li key={entry.id} data-kind={entry.kind}>
                  <time dateTime={entry.occurredAt}>{terminalTime(entry.occurredAt)}</time>
                  <span>{entry.kind === "prompt" ? "CTX" : "PI"}</span>
                  <pre>{entry.content}</pre>
                </li>
              );
            })}
          </ol>
        ) : null}
        {followed && stream.length === 0 ? (
          <p>{isLive ? "Waiting for reviewed output…" : "No reviewed output yet."}</p>
        ) : null}
        {followed && onToggleFollow ? (
          <footer className="power-racer-follow">
            <button type="button" onClick={onToggleFollow}>
              Collapse lane {label}
            </button>
          </footer>
        ) : null}
        <span className="sr-only" aria-live={isLive && followed ? "polite" : "off"}>
          {followed && stream.length > 0 ? `Racer ${label} terminal updated.` : ""}
        </span>
      </section>
      <details className="power-racer-terminal">
        <summary title="Reviewed tool records. Credentials and raw flags are redacted.">
          Tool history <span>{transcripts.length}</span>
        </summary>
        {transcripts.length > 0 ? (
          <ol aria-label={`Racer ${label} tool terminal`}>
            {transcripts.slice(-8).map((item) => (
              <li key={item.id}>
                <header>
                  <code>{item.tool}</code>
                  <span>{item.exitCode === null ? "n/a" : `exit ${item.exitCode}`}</span>
                  {item.timedOut ? <span className="power-terminal-timeout">timeout</span> : null}
                </header>
                <pre aria-label={`Racer ${label} command`}><code>$ {item.command}</code></pre>
                <pre aria-label={`Racer ${label} output`}>{item.output}</pre>
                <footer>
                  {item.outputTruncated ? <small>… output capped</small> : null}
                  {item.artifactId && onSaveArtifact ? (
                    // The rendered output above is redacted and capped, so a
                    // script or a dump a racer produced is only complete in
                    // the sealed observation. This is the way out of the run.
                    <button
                      type="button"
                      onClick={() => void save(item.artifactId as string)}
                      disabled={savingArtifact !== null}
                      title="Download the full sealed bytes of this observation."
                    >
                      {savingArtifact === item.artifactId ? "Saving…" : "Save bytes"}
                    </button>
                  ) : null}
                </footer>
              </li>
            ))}
          </ol>
        ) : <p className="power-racer-feed-empty">Waiting for the first tool result.</p>}
        {saveError ? <small role="alert">{saveError}</small> : null}
      </details>
      {onSteer ? (
        <form className="power-racer-steer" onSubmit={(event) => void submit(event)}>
          <label htmlFor={`racer-${label}-steer`}>Steer racer {label}</label>
          <div>
            <textarea
              id={`racer-${label}-steer`}
              value={message}
              maxLength={2_000}
              rows={2}
              placeholder="Suggest the next evidence path…"
              onChange={(event) => {
                setMessage(event.target.value);
                setSteerQueued(false);
              }}
              onKeyDown={sendOnShortcut}
            />
            <button type="submit" disabled={!message.trim() || sending}>
              {sending ? "Sending…" : "Steer"}
            </button>
          </div>
          <small>{steerQueued ? "Steer queued — waiting for Pi." : "Ctrl/⌘ + Enter to send"}</small>
          {error ? <small role="alert">{error}</small> : null}
        </form>
      ) : null}
    </li>
  );
}
