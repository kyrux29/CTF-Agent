import {
  type FormEvent,
  useEffect,
  useMemo,
  useState,
} from "react";

import type { ArchiveIntakeSummary, TrackedRunSummary } from "../api";

const HISTORY_PREFERENCES_KEY = "ctfmesh.history-preferences/v1";
const MAX_ALIAS_LENGTH = 80;
const MAX_SAVED_ALIASES = 200;
const MAX_HIDDEN_ITEMS = 500;

interface HistoryPreferences {
  aliases: Record<string, string>;
  hidden: string[];
}

interface HistoryEntry {
  key: string;
  originalName: string;
  meta: string;
  /** What removal destroys here, so the confirmation names the real thing. */
  removalNoun: "archive" | "run";
  onOpen: () => void;
  onPermanentRemove?: () => Promise<void>;
}

/** Removal copy per entry kind. A run and an archive lose different things. */
const REMOVAL_COPY = {
  archive: {
    prompt: "Remove archive and files?",
    done: "Archive removed permanently.",
    failed: "Archive could not be removed.",
  },
  run: {
    prompt: "Remove run, its ledger and its evidence?",
    done: "Run removed permanently.",
    failed: "Run could not be removed.",
  },
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function emptyPreferences(): HistoryPreferences {
  return { aliases: {}, hidden: [] };
}

function loadPreferences(): HistoryPreferences {
  try {
    const parsed: unknown = JSON.parse(
      window.localStorage.getItem(HISTORY_PREFERENCES_KEY) ?? "null",
    );
    if (!isRecord(parsed)) return emptyPreferences();

    const aliases = isRecord(parsed.aliases)
      ? Object.fromEntries(
          Object.entries(parsed.aliases)
            .filter(
              (entry): entry is [string, string] => {
                const [key, value] = entry;
                return (
                  key.length <= 240 &&
                  typeof value === "string" &&
                  value.trim().length > 0 &&
                  value.length <= MAX_ALIAS_LENGTH
                );
              },
            )
            .slice(-MAX_SAVED_ALIASES),
        )
      : {};
    const hidden = Array.isArray(parsed.hidden)
      ? parsed.hidden
          .filter(
            (key): key is string =>
              typeof key === "string" && key.length <= 240,
          )
          .slice(-MAX_HIDDEN_ITEMS)
      : [];
    return { aliases, hidden: [...new Set(hidden)] };
  } catch {
    return emptyPreferences();
  }
}

function savePreferences(value: HistoryPreferences): boolean {
  try {
    window.localStorage.setItem(HISTORY_PREFERENCES_KEY, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function historyKey(kind: "archive" | "run", id: string): string {
  return `${kind}:${id}`;
}

function formatRunTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : new Intl.DateTimeFormat("en", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(date);
}

function compactIdentifier(value: string): string {
  return value.length > 22 ? `${value.slice(0, 18)}…` : value;
}

function HistoryGroup({
  title,
  entries,
  preferences,
  query,
  activeMenu,
  editingKey,
  editValue,
  hidingKey,
  removingKey,
  removalPendingKey,
  onOpenMenu,
  onStartRename,
  onEditValue,
  onSaveRename,
  onCancelRename,
  onStartHide,
  onStartPermanentRemove,
  onCancelConfirmation,
  onHide,
  onPermanentRemove,
}: {
  title: string;
  entries: readonly HistoryEntry[];
  preferences: HistoryPreferences;
  query: string;
  activeMenu: string | null;
  editingKey: string | null;
  editValue: string;
  hidingKey: string | null;
  removingKey: string | null;
  removalPendingKey: string | null;
  onOpenMenu: (key: string) => void;
  onStartRename: (entry: HistoryEntry) => void;
  onEditValue: (value: string) => void;
  onSaveRename: (entry: HistoryEntry) => void;
  onCancelRename: () => void;
  onStartHide: (key: string) => void;
  onStartPermanentRemove: (key: string) => void;
  onCancelConfirmation: () => void;
  onHide: (entry: HistoryEntry) => void;
  onPermanentRemove: (entry: HistoryEntry) => void;
}) {
  const hidden = new Set(preferences.hidden);
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visible = entries.filter((entry) => {
    if (hidden.has(entry.key)) return false;
    if (!normalizedQuery) return true;
    const alias = preferences.aliases[entry.key] ?? "";
    return `${alias} ${entry.originalName} ${entry.meta}`
      .toLocaleLowerCase()
      .includes(normalizedQuery);
  });

  return (
    <section className="power-history-group" aria-label={`${title} history`}>
      <header>
        <h3>{title}</h3>
        <span>{visible.length}</span>
      </header>
      {visible.length ? (
        <ol>
          {visible.map((entry) => {
            const alias = preferences.aliases[entry.key];
            const displayName = alias || compactIdentifier(entry.originalName);
            const editing = editingKey === entry.key;
            const menuOpen = activeMenu === entry.key;
            const confirmingHide = hidingKey === entry.key;
            const confirmingRemove = removingKey === entry.key;
            const confirming = confirmingHide || confirmingRemove;
            const removing = removalPendingKey === entry.key;
            return (
              <li className="power-history-item" key={entry.key}>
                {editing ? (
                  <form
                    className="power-history-rename"
                    onSubmit={(event: FormEvent) => {
                      event.preventDefault();
                      onSaveRename(entry);
                    }}
                  >
                    <input
                      autoFocus
                      aria-label={`Display name for ${entry.originalName}`}
                      maxLength={MAX_ALIAS_LENGTH}
                      value={editValue}
                      onChange={(event) => onEditValue(event.target.value)}
                    />
                    <div>
                      <button type="submit" disabled={!editValue.trim()}>
                        Save
                      </button>
                      <button type="button" onClick={onCancelRename}>
                        Cancel
                      </button>
                    </div>
                  </form>
                ) : (
                  <>
                    <button
                      type="button"
                      className="power-history-open"
                      title={
                        alias
                          ? `${alias} — ${entry.originalName}`
                          : entry.originalName
                      }
                      onClick={entry.onOpen}
                    >
                      <strong>{displayName}</strong>
                      <small>
                        {alias
                          ? `${compactIdentifier(entry.originalName)} · `
                          : ""}
                        {entry.meta}
                      </small>
                    </button>
                    <button
                      type="button"
                      className="power-history-more"
                      aria-label={`Actions for ${displayName}`}
                      aria-haspopup="menu"
                      aria-expanded={menuOpen}
                      onClick={() => onOpenMenu(entry.key)}
                    >
                      <svg aria-hidden="true" viewBox="0 0 20 20">
                        <circle cx="4" cy="10" r="1.25" />
                        <circle cx="10" cy="10" r="1.25" />
                        <circle cx="16" cy="10" r="1.25" />
                      </svg>
                    </button>
                    {menuOpen ? (
                      <div
                        className="power-history-menu"
                        role={confirming ? "group" : "menu"}
                        aria-label={
                          confirmingHide
                            ? `Hide ${displayName} from history`
                            : confirmingRemove
                              ? `Remove ${displayName} permanently`
                              : undefined
                        }
                      >
                        {confirmingHide ? (
                          <>
                            <span>Hide from History?</span>
                            <button type="button" onClick={onCancelConfirmation}>
                              Cancel
                            </button>
                            <button
                              type="button"
                              onClick={() => onHide(entry)}
                            >
                              Confirm hide
                            </button>
                          </>
                        ) : confirmingRemove ? (
                          <>
                            <span>{REMOVAL_COPY[entry.removalNoun].prompt}</span>
                            <button
                              type="button"
                              onClick={onCancelConfirmation}
                              disabled={removing}
                            >
                              Cancel
                            </button>
                            <button
                              type="button"
                              className="power-history-danger"
                              onClick={() => onPermanentRemove(entry)}
                              disabled={removing}
                            >
                              {removing ? "Removing…" : "Remove permanently"}
                            </button>
                          </>
                        ) : (
                          <>
                            <button
                              type="button"
                              role="menuitem"
                              onClick={() => onStartRename(entry)}
                            >
                              Rename
                            </button>
                            <button
                              type="button"
                              role="menuitem"
                              onClick={() => onStartHide(entry.key)}
                            >
                              Hide
                            </button>
                            {entry.onPermanentRemove ? (
                              <button
                                type="button"
                                role="menuitem"
                                className="power-history-danger"
                                onClick={() => onStartPermanentRemove(entry.key)}
                              >
                                Remove
                              </button>
                            ) : null}
                          </>
                        )}
                      </div>
                    ) : null}
                  </>
                )}
              </li>
            );
          })}
        </ol>
      ) : (
        <p>{query ? "No match." : `No ${title.toLocaleLowerCase()}.`}</p>
      )}
    </section>
  );
}

export function HistoryPanel({
  archives,
  runs,
  onOpenArchive,
  onOpenRun,
  onRemoveArchive,
  onRemoveRun,
}: {
  archives: readonly ArchiveIntakeSummary[];
  runs: readonly TrackedRunSummary[];
  onOpenArchive: (archive: ArchiveIntakeSummary) => void;
  onOpenRun: (runId: string) => void;
  onRemoveArchive: (archive: ArchiveIntakeSummary) => Promise<void>;
  onRemoveRun?: (runId: string) => Promise<void>;
}) {
  const [preferences, setPreferences] =
    useState<HistoryPreferences>(loadPreferences);
  const [query, setQuery] = useState("");
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [hidingKey, setHidingKey] = useState<string | null>(null);
  const [removingKey, setRemovingKey] = useState<string | null>(null);
  const [removalPendingKey, setRemovalPendingKey] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  const archiveEntries = useMemo<HistoryEntry[]>(
    () =>
      archives.map((archive) => ({
        key: historyKey("archive", archive.intake_id),
        originalName: archive.name,
        meta: `${archive.category} · ${archive.file_count} files`,
        removalNoun: "archive",
        onOpen: () => onOpenArchive(archive),
        onPermanentRemove: () => onRemoveArchive(archive),
      })),
    [archives, onOpenArchive, onRemoveArchive],
  );
  const runEntries = useMemo<HistoryEntry[]>(
    () =>
      runs.map((run) => ({
        key: historyKey("run", run.id),
        originalName: run.id,
        meta: `${run.status} · ${formatRunTime(run.updatedAt)}`,
        removalNoun: "run",
        onOpen: () => onOpenRun(run.id),
        // Hiding a run only affects this browser. Removing it erases the
        // ledger, the transcripts a continuation would resume from, and the
        // observations a racer sealed - so it is offered on the same
        // deliberate path archives already use, never as a tidy-up.
        ...(onRemoveRun === undefined
          ? {}
          : { onPermanentRemove: () => onRemoveRun(run.id) }),
      })),
    [runs, onOpenRun, onRemoveRun],
  );

  useEffect(() => {
    const closeMenu = (event: KeyboardEvent): void => {
      if (event.key !== "Escape") return;
      setActiveMenu(null);
      setEditingKey(null);
      setHidingKey(null);
      setRemovingKey(null);
    };
    document.addEventListener("keydown", closeMenu);
    return () => document.removeEventListener("keydown", closeMenu);
  }, []);

  function commit(next: HistoryPreferences, message: string): void {
    setPreferences(next);
    setNotice(
      savePreferences(next)
        ? message
        : "History preference could not be saved in this browser.",
    );
  }

  function startRename(entry: HistoryEntry): void {
    setEditingKey(entry.key);
    setEditValue(preferences.aliases[entry.key] ?? entry.originalName);
    setActiveMenu(null);
    setHidingKey(null);
    setRemovingKey(null);
  }

  function saveRename(entry: HistoryEntry): void {
    const alias = editValue.trim();
    if (!alias) return;
    const aliases = { ...preferences.aliases };
    if (alias === entry.originalName) delete aliases[entry.key];
    else aliases[entry.key] = alias;
    const boundedAliases = Object.fromEntries(
      Object.entries(aliases).slice(-MAX_SAVED_ALIASES),
    );
    commit(
      { ...preferences, aliases: boundedAliases },
      alias === entry.originalName
        ? "Original name restored."
        : "Display name saved.",
    );
    setEditingKey(null);
    setEditValue("");
  }

  function hide(entry: HistoryEntry): void {
    const hidden = [...new Set([...preferences.hidden, entry.key])].slice(
      -MAX_HIDDEN_ITEMS,
    );
    commit(
      { ...preferences, hidden },
      "Hidden from History. Server data was not deleted.",
    );
    setActiveMenu(null);
    setHidingKey(null);
  }

  async function removePermanently(entry: HistoryEntry): Promise<void> {
    if (!entry.onPermanentRemove || removalPendingKey) return;
    setRemovalPendingKey(entry.key);
    setNotice("");
    try {
      await entry.onPermanentRemove();
      const aliases = { ...preferences.aliases };
      delete aliases[entry.key];
      const next = {
        aliases,
        hidden: preferences.hidden.filter((key) => key !== entry.key),
      };
      setPreferences(next);
      savePreferences(next);
      setNotice(REMOVAL_COPY[entry.removalNoun].done);
      setActiveMenu(null);
      setRemovingKey(null);
    } catch (reason: unknown) {
      setNotice(
        reason instanceof Error
          ? reason.message
          : REMOVAL_COPY[entry.removalNoun].failed,
      );
    } finally {
      setRemovalPendingKey(null);
    }
  }

  function restoreHidden(): void {
    commit({ ...preferences, hidden: [] }, "Hidden history restored.");
  }

  return (
    <div className="power-history">
      <div className="power-history-tools">
        <label>
          <span className="sr-only">Search history</span>
          <input
            type="search"
            value={query}
            placeholder="Filter history"
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        {preferences.hidden.length ? (
          <button type="button" onClick={restoreHidden}>
            Restore {preferences.hidden.length}
          </button>
        ) : null}
      </div>
      <HistoryGroup
        title="Archives"
        entries={archiveEntries}
        preferences={preferences}
        query={query}
        activeMenu={activeMenu}
        editingKey={editingKey}
        editValue={editValue}
        hidingKey={hidingKey}
        removingKey={removingKey}
        removalPendingKey={removalPendingKey}
        onOpenMenu={(key) => {
          setActiveMenu((current) => (current === key ? null : key));
          setHidingKey(null);
          setRemovingKey(null);
        }}
        onStartRename={startRename}
        onEditValue={setEditValue}
        onSaveRename={saveRename}
        onCancelRename={() => {
          setEditingKey(null);
          setEditValue("");
        }}
        onStartHide={setHidingKey}
        onStartPermanentRemove={setRemovingKey}
        onCancelConfirmation={() => {
          setHidingKey(null);
          setRemovingKey(null);
        }}
        onHide={hide}
        onPermanentRemove={(entry) => void removePermanently(entry)}
      />
      <HistoryGroup
        title="Runs"
        entries={runEntries}
        preferences={preferences}
        query={query}
        activeMenu={activeMenu}
        editingKey={editingKey}
        editValue={editValue}
        hidingKey={hidingKey}
        removingKey={removingKey}
        removalPendingKey={removalPendingKey}
        onOpenMenu={(key) => {
          setActiveMenu((current) => (current === key ? null : key));
          setHidingKey(null);
          setRemovingKey(null);
        }}
        onStartRename={startRename}
        onEditValue={setEditValue}
        onSaveRename={saveRename}
        onCancelRename={() => {
          setEditingKey(null);
          setEditValue("");
        }}
        onStartHide={setHidingKey}
        onStartPermanentRemove={setRemovingKey}
        onCancelConfirmation={() => {
          setHidingKey(null);
          setRemovingKey(null);
        }}
        onHide={hide}
        onPermanentRemove={(entry) => void removePermanently(entry)}
      />
      <p className="power-history-notice" aria-live="polite">
        {notice}
      </p>
    </div>
  );
}
