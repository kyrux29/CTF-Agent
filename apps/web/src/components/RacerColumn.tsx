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
  onSteer,
}: RacerColumnProps) {
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [steerQueued, setSteerQueued] = useState(false);
  const streamRef = useRef<HTMLOListElement>(null);
  const followsStream = useRef(true);
  const isLive = state === "briefing" || state === "running";
  const stream = useMemo(() => terminalEntries(activity, transcripts), [activity, transcripts]);

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
        aria-label={`Racer ${label} live terminal`}
      >
        <header>
          <span>Pi terminal</span>
          <code>{stream.length} records</code>
          <small>{state === "review" ? "held for review" : isLive ? "following" : "last result"}</small>
        </header>
        {stream.length > 0 ? (
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
        ) : <p>{isLive ? "Waiting for reviewed output…" : "No reviewed output yet."}</p>}
        <span className="sr-only" aria-live={isLive ? "polite" : "off"}>
          {stream.length > 0 ? `Racer ${label} terminal updated.` : ""}
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
                {item.outputTruncated ? <small>… output capped</small> : null}
              </li>
            ))}
          </ol>
        ) : <p className="power-racer-feed-empty">Waiting for the first tool result.</p>}
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
