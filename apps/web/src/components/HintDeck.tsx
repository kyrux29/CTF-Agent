import { useEffect, useMemo, useState, type FormEvent } from "react";

import type { HintCardDraft } from "../api";
import type {
  HintCard,
  HintDirective,
  HintStatus,
  HintTemplate,
  SchedulerBranch,
  TraceEvent,
} from "../types";

interface HintDeckProps {
  readonly hints: readonly HintCard[];
  readonly branches: readonly SchedulerBranch[];
  readonly events: readonly TraceEvent[];
  readonly templates: readonly HintTemplate[];
  readonly runStatus: string;
  readonly onCreate?: (draft: HintCardDraft) => Promise<void>;
  readonly onUpdate?: (
    hintId: string,
    draft: Omit<HintCardDraft, "template_id">,
  ) => Promise<void>;
  readonly onDismiss?: (hintId: string) => Promise<void>;
  readonly onNavigateEvent: (eventId: string) => void;
  readonly onNavigateEvidence: (reference: string) => void;
}

const DIRECTIVES: ReadonlyArray<{ readonly value: HintDirective; readonly label: string }> = [
  { value: "explore", label: "Explore" },
  { value: "prioritize", label: "Prioritize" },
  { value: "require_probe", label: "Require control" },
  { value: "avoid", label: "Avoid" },
];

const LIFECYCLE: readonly HintStatus[] = [
  "active",
  "fulfilled",
  "contradicted",
  "dismissed",
  "expired",
];

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

function createDraft(template: HintTemplate | undefined): HintCardDraft {
  return {
    template_id: template?.id ?? "",
    directive: template?.default_directive ?? "explore",
    target_ref: "run:all",
    priority: 3,
    note: "",
  };
}

function scopeMatches(branchScope: string, hintScope: string): boolean {
  return hintScope === "run:all" || branchScope === hintScope;
}

function impactCopy(directive: HintDirective): string {
  switch (directive) {
    case "explore":
      return "Queues one bounded reviewed branch only when a worker slot and sealed preflight evidence are available.";
    case "prioritize":
      return "Raises the scheduler score for matching branches; it does not establish a fact or bypass evidence gates.";
    case "require_probe":
      return "Queues a bounded reviewed control/probe task; the exact target remains constrained by the manifest.";
    case "avoid":
      return "Suspends matching queued work and denies later tool requests for that technique/scope until the card is removed.";
  }
}

function Timeline({
  card,
  events,
  onNavigateEvent,
  onNavigateEvidence,
}: {
  readonly card: HintCard;
  readonly events: readonly TraceEvent[];
  readonly onNavigateEvent: (eventId: string) => void;
  readonly onNavigateEvidence: (reference: string) => void;
}) {
  const relevant = events
    .filter((event) => event.related_refs.includes(card.id) || card.evidence_refs.some((ref) => event.related_refs.includes(ref)))
    .slice(-4)
    .reverse();

  return (
    <div className="hint-timeline" aria-label={`Evidence timeline for ${card.id}`}>
      <div className="hint-timeline-heading">
        <span>Evidence timeline</span>
        <span className="mono">{card.evidence_refs.length} refs</span>
      </div>
      {card.evidence_refs.length > 0 ? (
        <div className="hint-evidence-links" aria-label="Linked evidence">
          {card.evidence_refs.map((reference) => (
            <button type="button" key={reference} onClick={() => onNavigateEvidence(reference)}>
              <span className="mono">{reference}</span>
              <span aria-hidden="true">↗</span>
            </button>
          ))}
        </div>
      ) : null}
      {relevant.length > 0 ? (
        <ol>
          {relevant.map((event) => (
            <li key={event.id}>
              <button type="button" onClick={() => onNavigateEvent(event.id)}>
                <span className="mono">#{event.sequence}</span>
                <span>{event.title}</span>
              </button>
            </li>
          ))}
        </ol>
      ) : (
        <p>No linked audit event yet. This card remains a human hypothesis.</p>
      )}
    </div>
  );
}

function BranchImpact({
  techniqueId,
  scope,
  branches,
}: {
  readonly techniqueId: string;
  readonly scope: string;
  readonly branches: readonly SchedulerBranch[];
}) {
  const matching = branches.filter(
    (branch) => branch.technique_id === techniqueId && scopeMatches(branch.branch_scope, scope),
  );
  return (
    <div className="hint-impact" aria-label="Scheduler impact preview">
      <span className="hint-impact-label">Scheduler impact</span>
      {matching.length > 0 ? (
        <ul>
          {matching.slice(0, 3).map((branch) => (
            <li key={branch.id} data-state={branch.state}>
              <span className="status-dot" aria-hidden="true" />
              <span className="mono">{branch.id}</span>
              <span>{humanize(branch.state)}</span>
              <strong>{branch.score.toFixed(2)}</strong>
            </li>
          ))}
        </ul>
      ) : (
        <p>No matching branch exists yet. The kernel will keep the card pending until its fixed evidence/capacity checks pass.</p>
      )}
    </div>
  );
}

export function HintDeck({
  hints,
  branches,
  events,
  templates,
  runStatus,
  onCreate,
  onUpdate,
  onDismiss,
  onNavigateEvent,
  onNavigateEvidence,
}: HintDeckProps) {
  const [draft, setDraft] = useState<HintCardDraft>(() => createDraft(templates[0]));
  const [editing, setEditing] = useState<HintCard | null>(null);
  const [pending, setPending] = useState<"create" | "update" | "dismiss" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [filterQuery, setFilterQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<HintStatus | "all">("all");
  const enabled = runStatus === "running" || runStatus === "paused";
  const selectedTemplate = useMemo(
    () => templates.find((template) => template.id === draft.template_id),
    [draft.template_id, templates],
  );
  const visibleHints = useMemo(() => {
    const query = filterQuery.trim().toLocaleLowerCase();
    return hints.filter((card) => {
      if (statusFilter !== "all" && card.status !== statusFilter) {
        return false;
      }
      if (!query) {
        return true;
      }
      // Search only reviewed metadata and the declared scope. The note is
      // deliberately not a discovery surface because it is untrusted data.
      const templateLabel = templates.find((template) => template.id === card.template_id)?.label ?? "";
      return [templateLabel, card.technique_id, card.category, card.target_ref]
        .some((value) => value.toLocaleLowerCase().includes(query));
    });
  }, [filterQuery, hints, statusFilter, templates]);

  useEffect(() => {
    if (templates.length > 0 && !templates.some((template) => template.id === draft.template_id)) {
      setDraft(createDraft(templates[0]));
    }
  }, [draft.template_id, templates]);

  function resetComposer(): void {
    setEditing(null);
    setDraft(createDraft(templates[0]));
  }

  function beginEdit(card: HintCard): void {
    setEditing(card);
    setNotice(null);
    setDraft({
      template_id: card.template_id,
      directive: card.directive,
      target_ref: card.target_ref,
      priority: card.priority,
      note: card.note,
    });
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!enabled || selectedTemplate === undefined) {
      return;
    }
    setNotice(null);
    setPending(editing === null ? "create" : "update");
    try {
      if (editing === null) {
        await onCreate?.(draft);
        setNotice("Hint attached. Its effect remains an unverified scheduler proposal until evidence is recorded.");
      } else {
        await onUpdate?.(editing.id, {
          directive: draft.directive,
          target_ref: draft.target_ref,
          priority: draft.priority,
          note: draft.note,
        });
        setNotice("Hint updated. The audit record retains its prior lifecycle.");
      }
      resetComposer();
    } catch {
      // API responses are already generic, but never reflect a local note back
      // into the page on a failure because a note may contain accidental data.
      setNotice("The Hint Card could not be saved. Verify its fields and try again.");
    } finally {
      setPending(null);
    }
  }

  async function dismiss(card: HintCard): Promise<void> {
    if (!enabled || onDismiss === undefined) {
      return;
    }
    setNotice(null);
    setPending("dismiss");
    try {
      await onDismiss(card.id);
      if (editing?.id === card.id) {
        resetComposer();
      }
      setNotice("Hint dismissed. Existing audit evidence remains available.");
    } catch {
      setNotice("The Hint Card could not be dismissed. Try again after refreshing evidence.");
    } finally {
      setPending(null);
    }
  }

  return (
    <section className="hint-deck workspace-section" aria-labelledby="hint-deck-heading">
      <div className="section-heading-row hint-deck-heading">
        <div>
          <p className="section-kicker">Operator guidance</p>
          <h2 id="hint-deck-heading">Hint Deck</h2>
          <p>Cards guide scheduling only. They are never facts, flags, verification, or prompt authority.</p>
        </div>
        <span className="hint-count" aria-label={`${hints.length} Hint Cards`}>
          <strong>{hints.length}</strong>
          <span>cards</span>
        </span>
      </div>

      <div className="hint-deck-layout">
        <div className="hint-card-list" aria-label="Attached Hint Cards">
          {hints.length > 0 ? (
            <div className="hint-filter-bar" aria-label="Filter attached Hint Cards">
              <label>
                <span>Find guidance</span>
                <input
                  type="search"
                  value={filterQuery}
                  onChange={(event) => setFilterQuery(event.target.value)}
                  placeholder="Technique, category, scope"
                  aria-label="Filter attached Hint Cards"
                />
              </label>
              <label>
                <span>Lifecycle</span>
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value as HintStatus | "all")}
                  aria-label="Filter Hint Cards by lifecycle"
                >
                  <option value="all">All states</option>
                  {LIFECYCLE.map((status) => <option key={status} value={status}>{humanize(status)}</option>)}
                </select>
              </label>
              <p aria-live="polite">
                {visibleHints.length} of {hints.length} shown
              </p>
            </div>
          ) : null}
          {hints.length === 0 ? (
            <p className="hint-empty">No Hint Cards attached. Choose a reviewed template to give the bounded scheduler a lead.</p>
          ) : visibleHints.length === 0 ? (
            <p className="hint-empty">No attached Hint Card matches this reviewed metadata filter.</p>
          ) : (
            visibleHints.map((card) => (
              <article className="hint-card" data-status={card.status} key={card.id}>
                <header>
                  <div>
                    <span className="mono hint-technique">{card.technique_id}</span>
                    <h3>{templates.find((template) => template.id === card.template_id)?.label ?? card.template_id}</h3>
                  </div>
                  <span className="hint-status" data-status={card.status}>{humanize(card.status)}</span>
                </header>
                <div className="hint-card-meta">
                  <span className="hint-directive">{humanize(card.directive)}</span>
                  <span className="mono">{card.target_ref}</span>
                  <span aria-label={`Priority ${card.priority} of 5`}>P{card.priority}/5</span>
                </div>
                {card.note ? <p className="hint-note">{card.note}</p> : <p className="hint-note muted">No local note added.</p>}
                <BranchImpact techniqueId={card.technique_id} scope={card.target_ref} branches={branches} />
                <Timeline
                  card={card}
                  events={events}
                  onNavigateEvent={onNavigateEvent}
                  onNavigateEvidence={onNavigateEvidence}
                />
                <div className="hint-card-actions">
                  <span className="hint-hypothesis-label">Human hypothesis · evidence required</span>
                  {card.status === "active" && enabled ? (
                    <div>
                      <button type="button" className="text-button" onClick={() => beginEdit(card)} disabled={pending !== null || onUpdate === undefined}>
                        Adjust
                      </button>
                      <button type="button" className="text-button danger-text-button" onClick={() => void dismiss(card)} disabled={pending !== null || onDismiss === undefined}>
                        Dismiss
                      </button>
                    </div>
                  ) : null}
                </div>
              </article>
            ))
          )}
        </div>

        <form className="hint-composer" onSubmit={(event) => void submit(event)} aria-describedby="hint-composer-boundary">
          <div className="hint-composer-title">
            <p className="section-kicker">{editing ? "Revise guidance" : "Attach guidance"}</p>
            <h3>{editing ? "Adjust active Hint Card" : "Add a reviewed Hint Card"}</h3>
          </div>
          <p id="hint-composer-boundary" className="hint-composer-boundary">
            The template fixes allowed roles and tools. Your note is local untrusted data, never a system instruction.
          </p>
          {templates.length === 0 ? (
            <p className="hint-empty">The reviewed Hint Template catalog is unavailable. Refresh evidence to try again.</p>
          ) : (
            <>
              <label>
                Reviewed template
                <select
                  value={draft.template_id}
                  disabled={!enabled || editing !== null || pending !== null}
                  onChange={(event) => {
                    const nextTemplate = templates.find((template) => template.id === event.target.value);
                    setDraft((current) => ({
                      ...current,
                      template_id: event.target.value,
                      directive: nextTemplate?.default_directive ?? current.directive,
                    }));
                  }}
                >
                  {templates.map((template) => <option key={template.id} value={template.id}>{template.label}</option>)}
                </select>
              </label>
              <label>
                Scheduler directive
                <select
                  value={draft.directive}
                  disabled={!enabled || pending !== null}
                  onChange={(event) => setDraft((current) => ({ ...current, directive: event.target.value as HintDirective }))}
                >
                  {DIRECTIVES.map((directive) => <option key={directive.value} value={directive.value}>{directive.label}</option>)}
                </select>
              </label>
              <label>
                Scope reference
                <input
                  value={draft.target_ref}
                  pattern="[A-Za-z0-9][A-Za-z0-9_.:-]*"
                  maxLength={160}
                  disabled={!enabled || pending !== null}
                  onChange={(event) => setDraft((current) => ({ ...current, target_ref: event.target.value }))}
                />
              </label>
              <label className="hint-priority-input">
                <span>Priority <strong>{draft.priority}/5</strong></span>
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={draft.priority}
                  disabled={!enabled || pending !== null}
                  onChange={(event) => setDraft((current) => ({ ...current, priority: Number(event.target.value) }))}
                />
              </label>
              <label>
                Local note <span className="hint-optional">optional · 500 max</span>
                <textarea
                  value={draft.note}
                  maxLength={500}
                  rows={3}
                  disabled={!enabled || pending !== null}
                  onChange={(event) => setDraft((current) => ({ ...current, note: event.target.value }))}
                />
              </label>
              <div className="hint-draft-impact">
                <span className="hint-impact-label">Impact preview</span>
                <p>{impactCopy(draft.directive)}</p>
                {selectedTemplate ? (
                  <p className="hint-template-detail">
                    Roles: <span className="mono">{selectedTemplate.recommended_roles.join(", ")}</span>
                    <br />
                    Tools: <span className="mono">{selectedTemplate.recommended_tools.join(", ")}</span>
                  </p>
                ) : null}
              </div>
              <div className="hint-composer-actions">
                {editing ? <button type="button" className="text-button" onClick={resetComposer} disabled={pending !== null}>Cancel edit</button> : null}
                <button type="submit" className="primary-button" disabled={!enabled || pending !== null || selectedTemplate === undefined || (editing === null && onCreate === undefined)}>
                  {pending === "create" ? "Attaching…" : pending === "update" ? "Saving…" : editing ? "Save guidance" : "Attach Hint Card"}
                </button>
              </div>
            </>
          )}
          {!enabled ? <p className="hint-run-state">Hint Cards can be changed only while the run is running or paused.</p> : null}
          {notice ? <p className="hint-notice" role="status">{notice}</p> : null}
        </form>
      </div>

      <ol className="hint-lifecycle" aria-label="Hint Card lifecycle">
        {LIFECYCLE.map((status) => (
          <li key={status} data-active={hints.some((card) => card.status === status)}>
            <span aria-hidden="true" />
            {humanize(status)}
          </li>
        ))}
      </ol>
    </section>
  );
}
