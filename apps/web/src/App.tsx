import {
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  type ArchiveIntake,
  type ArchiveIntakeSummary,
  type ArchiveProviderId,
  type PowerRacerLaunch,
  type PowerSession,
  type RuntimeCapabilities,
  type TrackedRunSummary,
  cancelTrackedRun,
  confirmRuntimeCandidateReview,
  getArchiveIntake,
  getConsoleSnapshot,
  getRuntimeCapabilities,
  launchPowerRun,
  listPowerSessions,
  listArchiveIntakes,
  listTrackedRuns,
  removeArchiveIntake,
  revealArchiveCandidateFlags,
  revealRuntimeCandidateFlags,
  revealVerifiedFlag,
  rejectRuntimeCandidateReview,
  steerPowerSession,
  uploadArchive,
} from "./api";
import {
  RunConsole,
  type PowerCandidateStatus,
  type PowerCandidateSuggestion,
} from "./components/RunConsole";
import { HistoryPanel } from "./components/HistoryPanel";
import { PowerLaunch } from "./components/PowerLaunch";
import {
  clearStoredCredentialVault,
  hasStoredCredentialVault,
  loadStoredCredentialVault,
  saveStoredCredentialVault,
  type ProviderCredentialVault,
} from "./credentialVault";
import type { ConsoleSnapshot } from "./types";

const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const SETTINGS_KEY = "ctfmesh.power-settings/v1";
const SETTINGS_FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");
const POWER_PROVIDERS: ReadonlyArray<{
  id: ArchiveProviderId;
  label: string;
  models: readonly string[];
}> = [
  {
    id: "openai-responses",
    label: "OpenAI",
    models: ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"],
  },
  {
    id: "gemini-openai-compat",
    label: "Gemini",
    models: ["gemini-3.7-flash", "gemini-3.6-flash", "gemini-3.5-flash"],
  },
  {
    id: "deepseek-chat",
    label: "DeepSeek",
    models: ["deepseek-v4-pro", "deepseek-v4-flash"],
  },
];

type RacerLabel = "A" | "B" | "C";
type OperatorView = "history" | "progress" | "stats" | "help";
interface LastPowerLaunch {
  target?: { host: string; port: number };
  authorizedTarget: boolean;
  contestOffline: boolean;
  flagFormat: string;
  challengeDescription: string;
}

function OperatorIcon({ name }: { name: OperatorView | "settings" }) {
  const paths: Record<typeof name, ReactNode> = {
    history: (
      <>
        <circle cx="12" cy="12" r="8" />
        <path d="M12 7v5l3 2" />
      </>
    ),
    progress: <path d="M3 12h4l2.2-6 4.2 12 2.1-6H21" />,
    stats: (
      <>
        <path d="M5 19V11" />
        <path d="M12 19V5" />
        <path d="M19 19v-6" />
      </>
    ),
    help: (
      <>
        <circle cx="12" cy="12" r="8" />
        <path d="M9.8 9a2.3 2.3 0 0 1 4.4 1c0 1.8-2.2 2-2.2 3.5" />
        <path d="M12 17h.01" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.4 1A8 8 0 0 0 15 6l-.4-2.5h-4L10.2 6a8 8 0 0 0-1.5.9l-2.4-1-2 3.4 2 1.5a7 7 0 0 0 0 2.2l-2 1.5 2 3.4 2.4-1A8 8 0 0 0 10.2 18l.4 2.5h4L15 18a8 8 0 0 0 1.5-.9l2.4 1 2-3.4-2-1.5a7 7 0 0 0 .1-1.2Z" />
      </>
    ),
  };
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none">
      <g stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
        {paths[name]}
      </g>
    </svg>
  );
}

function OperatorViewButton({
  view,
  label,
  active,
  onToggle,
}: {
  view: OperatorView;
  label: string;
  active: boolean;
  onToggle: (view: OperatorView) => void;
}) {
  return (
    <button
      type="button"
      className="power-activity-button"
      aria-label={label}
      aria-pressed={active}
      title={label}
      onClick={() => onToggle(view)}
    >
      <OperatorIcon name={view} />
    </button>
  );
}

interface RacerSettings extends PowerRacerLaunch {}

interface PowerSettings {
  racers: Record<RacerLabel, RacerSettings>;
  wallTimeSeconds: number;
  maxCostUsd: number;
  maxTurnCostUsd: number;
}

function emptyCredentials(): ProviderCredentialVault {
  return {
    "openai-responses": "",
    "gemini-openai-compat": "",
    "deepseek-chat": "",
  };
}

const DEFAULT_SETTINGS: PowerSettings = {
  racers: {
    A: {
      label: "A",
      provider: "deepseek-chat",
      model: "deepseek-v4-pro",
      temperature: 0.2,
    },
    B: {
      label: "B",
      provider: "deepseek-chat",
      model: "deepseek-v4-pro",
      temperature: 0.5,
    },
    C: {
      label: "C",
      provider: "deepseek-chat",
      model: "deepseek-v4-pro",
      temperature: 0.8,
    },
  },
  wallTimeSeconds: 3_600,
  maxCostUsd: 10,
  maxTurnCostUsd: 0.05,
};

function cloneSettings(value: PowerSettings): PowerSettings {
  return {
    ...value,
    racers: {
      A: { ...value.racers.A },
      B: { ...value.racers.B },
      C: { ...value.racers.C },
    },
  };
}

function isFiniteNumber(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isProvider(value: unknown): value is ArchiveProviderId {
  return POWER_PROVIDERS.some((provider) => provider.id === value);
}

function isRacer(value: unknown, label: RacerLabel): value is RacerSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const racer = value as Partial<RacerSettings>;
  return (
    racer.label === label &&
    isProvider(racer.provider) &&
    typeof racer.model === "string" &&
    racer.model.length > 0 &&
    isFiniteNumber(racer.temperature, 0, 2)
  );
}

function loadSettings(): PowerSettings {
  try {
    const parsed: unknown = JSON.parse(
      window.localStorage.getItem(SETTINGS_KEY) ?? "null",
    );
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return cloneSettings(DEFAULT_SETTINGS);
    const value = parsed as Partial<PowerSettings>;
    const racers = value.racers;
    if (
      !racers ||
      !isRacer(racers.A, "A") ||
      !isRacer(racers.B, "B") ||
      !isRacer(racers.C, "C")
    ) {
      return cloneSettings(DEFAULT_SETTINGS);
    }
    if (
      !isFiniteNumber(value.wallTimeSeconds, 60, 86_400) ||
      !isFiniteNumber(value.maxCostUsd, 0.01, 1_000) ||
      !isFiniteNumber(value.maxTurnCostUsd, 0.001, 1_000)
    ) {
      return cloneSettings(DEFAULT_SETTINGS);
    }
    return {
      racers: { A: { ...racers.A }, B: { ...racers.B }, C: { ...racers.C } },
      wallTimeSeconds: value.wallTimeSeconds,
      maxCostUsd: value.maxCostUsd,
      maxTurnCostUsd: value.maxTurnCostUsd,
    };
  } catch {
    return cloneSettings(DEFAULT_SETTINGS);
  }
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

function modelOptions(providerId: ArchiveProviderId): readonly string[] {
  return (
    POWER_PROVIDERS.find((provider) => provider.id === providerId)?.models ?? []
  );
}

function readRunId(): string | null {
  const value = new URLSearchParams(window.location.search).get("run");
  return value && /^[A-Za-z0-9_.:-]{1,160}$/.test(value) ? value : null;
}

function navigateToRun(runId: string | null): void {
  const url = new URL(window.location.href);
  if (runId) url.searchParams.set("run", runId);
  else url.searchParams.delete("run");
  window.history.pushState(null, "", url);
}

function PowerSettingsDialog({
  value,
  credentials,
  hasSavedKeys,
  onClose,
  onSave,
  onForgetKeys,
}: {
  value: PowerSettings;
  credentials: ProviderCredentialVault;
  hasSavedKeys: boolean;
  onClose: () => void;
  onSave: (
    settings: PowerSettings,
    credentials: ProviderCredentialVault,
  ) => Promise<void>;
  onForgetKeys: () => void;
}) {
  const [draft, setDraft] = useState<PowerSettings>(() => cloneSettings(value));
  const [keys, setKeys] = useState<ProviderCredentialVault>(() => ({
    ...credentials,
  }));
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const dialog = dialogRef.current;
    const previousFocus =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    if (!dialog) return undefined;

    closeButtonRef.current?.focus({ preventScroll: true });

    const handleKeyDown = (event: globalThis.KeyboardEvent): void => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;

      const controls = Array.from(
        dialog.querySelectorAll<HTMLElement>(SETTINGS_FOCUSABLE),
      ).filter(
        (control) =>
          !control.hasAttribute("disabled") &&
          control.getAttribute("aria-hidden") !== "true",
      );
      const first = controls[0];
      const last = controls.at(-1);
      if (!first || !last) {
        event.preventDefault();
        dialog.focus({ preventScroll: true });
        return;
      }

      const active = document.activeElement;
      if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previousFocus?.isConnected) {
        previousFocus.focus({ preventScroll: true });
      }
    };
  }, []);

  const updateRacer = (label: RacerLabel, patch: Partial<RacerSettings>) => {
    setDraft((current) => ({
      ...current,
      racers: {
        ...current.racers,
        [label]: { ...current.racers[label], ...patch },
      },
    }));
  };

  async function save(): Promise<void> {
    setSaving(true);
    setError(null);
    try {
      await onSave(draft, keys);
      onClose();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Settings could not be saved.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="power-settings-backdrop"
      role="presentation"
      onMouseDown={onClose}
    >
      <section
        ref={dialogRef}
        className="power-settings-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Power settings"
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <p>POWER SETTINGS</p>
            <h2>Racers and keys</h2>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            className="power-icon-button"
            aria-label="Close settings"
            onClick={onClose}
          >
            ×
          </button>
        </header>
        <section
          className="power-settings-section"
          aria-labelledby="provider-keys-heading"
        >
          <h3 id="provider-keys-heading">Provider keys</h3>
          {POWER_PROVIDERS.map((provider) => (
            <label className="power-key-row" key={provider.id}>
              <span>{provider.label}</span>
              <input
                type="password"
                aria-label={`${provider.label} API key`}
                value={keys[provider.id]}
                placeholder="API key"
                onChange={(event) =>
                  setKeys((current) => ({
                    ...current,
                    [provider.id]: event.target.value,
                  }))
                }
                autoComplete="off"
              />
            </label>
          ))}
          <p className="power-setting-note">Saved locally in this browser.</p>
          {hasSavedKeys ? (
            <button
              type="button"
              className="power-text-button"
              onClick={() => {
                setKeys(emptyCredentials());
                onForgetKeys();
              }}
            >
              Remove saved keys
            </button>
          ) : null}
        </section>
        <section
          className="power-settings-section"
          aria-labelledby="racer-settings-heading"
        >
          <h3 id="racer-settings-heading">Racer map</h3>
          {(["A", "B", "C"] as const).map((label) => {
            const racer = draft.racers[label];
            return (
              <div className="power-racer-setting" key={label}>
                <strong>{label}</strong>
                <select
                  aria-label={`Racer ${label} provider`}
                  value={racer.provider}
                  onChange={(event) => {
                    const provider = event.target.value as ArchiveProviderId;
                    updateRacer(label, {
                      provider,
                      model: modelOptions(provider)[0] ?? "",
                    });
                  }}
                >
                  {POWER_PROVIDERS.map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))}
                </select>
                <input
                  aria-label={`Racer ${label} model`}
                  list={`power-models-${label}`}
                  value={racer.model}
                  onChange={(event) =>
                    updateRacer(label, { model: event.target.value })
                  }
                />
                <datalist id={`power-models-${label}`}>
                  {modelOptions(racer.provider).map((model) => (
                    <option key={model} value={model} />
                  ))}
                </datalist>
                <input
                  aria-label={`Racer ${label} temperature`}
                  type="number"
                  min="0"
                  max="2"
                  step="0.1"
                  value={racer.temperature}
                  onChange={(event) =>
                    updateRacer(label, {
                      temperature: Number(event.target.value),
                    })
                  }
                />
              </div>
            );
          })}
        </section>
        <section
          className="power-settings-section power-limit-grid"
          aria-labelledby="limits-heading"
        >
          <h3 id="limits-heading">Race caps</h3>
          <label>
            Minutes
            <input
              type="number"
              min="1"
              max="1440"
              value={Math.ceil(draft.wallTimeSeconds / 60)}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  wallTimeSeconds: Number(event.target.value) * 60,
                }))
              }
            />
          </label>
          <label>
            Race cap (USD)
            <input
              type="number"
              min="0.01"
              max="1000"
              step="0.01"
              value={draft.maxCostUsd}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  maxCostUsd: Number(event.target.value),
                }))
              }
            />
          </label>
          <label>
            Reserve/call
            <input
              type="number"
              min="0.001"
              max="1000"
              step="0.001"
              value={draft.maxTurnCostUsd}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  maxTurnCostUsd: Number(event.target.value),
                }))
              }
            />
          </label>
        </section>
        {error ? (
          <p className="power-form-error" role="alert">
            {error}
          </p>
        ) : null}
        <footer>
          <button type="button" className="power-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="power-primary"
            onClick={() => void save()}
            disabled={saving}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </footer>
      </section>
    </div>
  );
}

export default function App() {
  const [settings, setSettings] = useState<PowerSettings>(loadSettings);
  const [credentials, setCredentials] =
    useState<ProviderCredentialVault>(loadStoredCredentialVault);
  const [hasSavedKeys, setHasSavedKeys] = useState(hasStoredCredentialVault);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [archives, setArchives] = useState<ArchiveIntakeSummary[]>([]);
  const [runs, setRuns] = useState<TrackedRunSummary[]>([]);
  const [capabilities, setCapabilities] = useState<RuntimeCapabilities | null>(
    null,
  );
  const [intake, setIntake] = useState<ArchiveIntake | null>(null);
  const [busy, setBusy] = useState<"idle" | "uploading" | "launching">("idle");
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<OperatorView | null>("history");
  const [runId, setRunId] = useState<string | null>(readRunId);
  const [snapshot, setSnapshot] = useState<ConsoleSnapshot | null>(null);
  const [powerSessions, setPowerSessions] = useState<PowerSession[]>([]);
  const [runError, setRunError] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [revealedFlag, setRevealedFlag] = useState<string | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [candidateSuggestions, setCandidateSuggestions] = useState<PowerCandidateSuggestion[]>([]);
  const [revealingInputCandidates, setRevealingInputCandidates] = useState(false);
  const [revealingRuntimeCandidates, setRevealingRuntimeCandidates] = useState(false);
  const [findingMoreCandidates, setFindingMoreCandidates] = useState(false);
  const [lastPowerLaunch, setLastPowerLaunch] = useState<LastPowerLaunch | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const candidateSequence = useRef(0);

  const refreshWorkspace = async (): Promise<void> => {
    const [nextArchives, nextRuns, nextCapabilities] = await Promise.all([
      listArchiveIntakes(),
      listTrackedRuns(),
      getRuntimeCapabilities(),
    ]);
    setArchives(nextArchives);
    setRuns(nextRuns);
    setCapabilities(nextCapabilities);
  };

  useEffect(() => {
    void refreshWorkspace().catch((reason: unknown) =>
      setWorkspaceError(
        reason instanceof Error ? reason.message : "Could not load workspace.",
      ),
    );
  }, []);
  useEffect(() => {
    const onPopState = () => setRunId(readRunId());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  useEffect(() => {
    if (!runId) return;
    const controller = new AbortController();
    setRunError(null);
    void getConsoleSnapshot(runId, controller.signal)
      .then(async (nextSnapshot) => {
        setSnapshot(nextSnapshot);
        if (nextSnapshot.run.provider_label === "power-swarm") {
          // Session identities are only used for the fixed steer endpoint;
          // this response contains no workspace, provider key, or transcript.
          setPowerSessions(await listPowerSessions(runId, controller.signal));
        } else {
          setPowerSessions([]);
        }
      })
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError"))
          setRunError(
            reason instanceof Error ? reason.message : "Could not load run.",
          );
      });
    return () => controller.abort();
  }, [runId, refreshTick]);
  const runLive = snapshot
    ? ["queued", "ready", "running", "verifying"].includes(snapshot.run.status)
    : false;
  useEffect(() => {
    if (!runLive) return;
    const timer = window.setInterval(
      () => setRefreshTick((current) => current + 1),
      3_000,
    );
    return () => window.clearInterval(timer);
  }, [runLive]);
  const raceCapacity = useMemo(
    () => Math.floor(settings.maxCostUsd / settings.maxTurnCostUsd),
    [settings],
  );
  const activeRuns = useMemo(
    () =>
      runs.filter((run) =>
        ["queued", "ready", "running", "racing", "verifying"].includes(
          run.status,
        ),
      ),
    [runs],
  );
  const solvedRuns = useMemo(
    () => runs.filter((run) => run.status === "solved").length,
    [runs],
  );

  function toggleView(view: OperatorView): void {
    setActiveView((current) => (current === view ? null : view));
  }

  function openRun(nextRunId: string): void {
    navigateToRun(nextRunId);
    setRunId(nextRunId);
    setSnapshot(null);
    setPowerSessions([]);
    setRevealedFlag(null);
    setCandidateSuggestions([]);
  }
  async function chooseArchive(summary: ArchiveIntakeSummary): Promise<void> {
    try {
      setWorkspaceError(null);
      setIntake(await getArchiveIntake(summary.intake_id));
      setCandidateSuggestions([]);
      setLastPowerLaunch(null);
    } catch (reason) {
      setWorkspaceError(
        reason instanceof Error ? reason.message : "Could not open archive.",
      );
    }
  }
  function upload(file: File): void {
    if (file.size === 0 || file.size > MAX_ARCHIVE_BYTES) {
      setWorkspaceError("Choose a non-empty archive up to 128 MiB.");
      return;
    }
    setBusy("uploading");
    setWorkspaceError(null);
    void uploadArchive(file)
      .then((nextIntake) => {
        setIntake(nextIntake);
        setCandidateSuggestions([]);
        setLastPowerLaunch(null);
        return refreshWorkspace();
      })
      .catch((reason: unknown) =>
        setWorkspaceError(
          reason instanceof Error
            ? reason.message
            : "Archive could not be inspected.",
        ),
      )
      .finally(() => setBusy("idle"));
  }
  function start(
    target: { host: string; port: number } | undefined,
    acknowledged: boolean,
    offline: boolean,
    flagFormat: string,
    challengeDescription: string,
  ): void {
    if (!intake) return;
    const racers = [settings.racers.A, settings.racers.B, settings.racers.C];
    const providerKeys: Partial<Record<ArchiveProviderId, string>> = {};
    for (const racer of racers)
      providerKeys[racer.provider] = credentials[racer.provider];
    setLastPowerLaunch({
      target,
      authorizedTarget: acknowledged,
      contestOffline: offline,
      flagFormat,
      challengeDescription,
    });
    setBusy("launching");
    setWorkspaceError(null);
    void launchPowerRun(intake.intake_id, {
      target,
      authorizedTarget: acknowledged,
      contestOffline: offline,
      flagFormat,
      challengeDescription,
      racers,
      providerKeys,
      budget: {
        wallTimeSeconds: settings.wallTimeSeconds,
        maxCostUsd: settings.maxCostUsd,
        maxTurnCostUsd: settings.maxTurnCostUsd,
      },
    })
      .then((run) => {
        openRun(run.runId);
        return refreshWorkspace();
      })
      .catch((reason: unknown) =>
        setWorkspaceError(
          reason instanceof Error
            ? reason.message
            : "Power run could not start.",
        ),
      )
      .finally(() => setBusy("idle"));
  }
  function addCandidateSuggestions(
    values: readonly string[],
    source: PowerCandidateSuggestion["source"],
    status: PowerCandidateStatus = "unreviewed",
    racerLabels?: readonly ("auto" | "A" | "B" | "C")[],
  ): void {
    setCandidateSuggestions((current) => {
      const next = current.map((candidate) => ({ ...candidate }));
      for (const value of values) {
        const trimmed = value.trim();
        if (!trimmed || trimmed.length > 1_024) continue;
        const existing = next.find((candidate) => candidate.value === trimmed);
        if (existing) {
          if (status === "verified") existing.status = "verified";
          if (racerLabels?.length) {
            existing.racerLabels = [...new Set([
              ...(existing.racerLabels ?? []),
              ...racerLabels,
            ])];
          }
          continue;
        }
        candidateSequence.current += 1;
        next.push({
          id: `candidate-${candidateSequence.current}`,
          value: trimmed,
          source,
          status,
          createdAt: new Date().toISOString(),
          racerLabels,
        });
      }
      return next;
    });
  }
  async function markCandidate(id: string, status: PowerCandidateStatus): Promise<void> {
    const candidate = candidateSuggestions.find((item) => item.id === id);
    if (!candidate) return;
    const candidateGatePending = snapshot?.run.status === "paused";
    if (candidate.source === "runtime" && candidateGatePending) {
      if (!runId) return;
      if (status === "manual_valid") {
        const decision = await confirmRuntimeCandidateReview(runId, candidate.value);
        // A negative independent verdict reopens the same race server-side.
        // Reflect it as rejected locally; no raw candidate is included in the
        // continuation steer sent to Pi.
        if (!decision.accepted) status = "manual_rejected";
      } else if (status === "manual_rejected") {
        await rejectRuntimeCandidateReview(runId);
      }
      setRefreshTick((current) => current + 1);
    }
    setCandidateSuggestions((current) =>
      current.map((candidate) =>
        candidate.id === id ? { ...candidate, status } : candidate,
      ),
    );
  }
  async function revealInputCandidates(): Promise<void> {
    if (!intake || revealingInputCandidates) return;
    setRevealingInputCandidates(true);
    try {
      const reveal = await revealArchiveCandidateFlags(intake.intake_id);
      addCandidateSuggestions(reveal.candidate_flags, "archive");
      if (reveal.candidate_flags.length === 0) {
        setRunError("No archive candidate flags were found.");
      }
    } finally {
      setRevealingInputCandidates(false);
    }
  }
  async function revealRuntimeCandidates(): Promise<void> {
    if (!runId || revealingRuntimeCandidates) return;
    setRevealingRuntimeCandidates(true);
    setRunError(null);
    try {
      const reveal = await revealRuntimeCandidateFlags(runId);
      for (const candidate of reveal.candidates) {
        addCandidateSuggestions(
          [candidate.value],
          "runtime",
          "unreviewed",
          candidate.racerLabels,
        );
      }
      if (!reveal.scanComplete) {
        setRunError(
          `${reveal.unavailableArtifactCount} runtime observation(s) could not be read; the candidate list may be incomplete.`,
        );
      } else if (reveal.candidateCount === 0) {
        setRunError("No runtime candidate flags were found yet.");
      }
    } finally {
      setRevealingRuntimeCandidates(false);
    }
  }
  async function findMoreCandidates(): Promise<void> {
    if (!runId || findingMoreCandidates) return;
    if (snapshot?.run.status === "paused") {
      setFindingMoreCandidates(true);
      try {
        await rejectRuntimeCandidateReview(runId);
        setRefreshTick((current) => current + 1);
      } finally {
        setFindingMoreCandidates(false);
      }
      return;
    }
    const targets = powerSessions.filter(
      (session) =>
        session.role === "racer"
        && (session.state === "ready" || session.state === "running"),
    );
    setFindingMoreCandidates(true);
    try {
      if (targets.length > 0) {
        await Promise.all(
          targets.map((session) =>
            steerPowerSession(
              runId,
              session.id,
              "Search a distinct evidence path and avoid repeating prior reads. A new format-matching candidate will pause for operator review.",
            ),
          ),
        );
        setRefreshTick((current) => current + 1);
        return;
      }
      if (!intake || !lastPowerLaunch) {
        throw new Error("No active racer is available. Start a new Power run to search again.");
      }
      const racers = [settings.racers.A, settings.racers.B, settings.racers.C];
      const providerKeys: Partial<Record<ArchiveProviderId, string>> = {};
      for (const racer of racers) {
        providerKeys[racer.provider] = credentials[racer.provider];
      }
      const restarted = await launchPowerRun(intake.intake_id, {
        ...lastPowerLaunch,
        racers,
        providerKeys,
        budget: {
          wallTimeSeconds: settings.wallTimeSeconds,
          maxCostUsd: settings.maxCostUsd,
          maxTurnCostUsd: settings.maxTurnCostUsd,
        },
      });
      openRun(restarted.runId);
      await refreshWorkspace();
    } finally {
      setFindingMoreCandidates(false);
    }
  }
  async function saveSettings(
    next: PowerSettings,
    nextCredentials: ProviderCredentialVault,
  ): Promise<void> {
    if (
      !Object.values(next.racers).every(
        (racer) =>
          racer.model.trim() && isFiniteNumber(racer.temperature, 0, 2),
      )
    )
      throw new Error(
        "Each racer needs a provider, model, and temperature from 0 to 2.",
      );
    if (
      !isFiniteNumber(next.wallTimeSeconds, 60, 86_400) ||
      !isFiniteNumber(next.maxCostUsd, 0.01, 1_000) ||
      !isFiniteNumber(next.maxTurnCostUsd, 0.001, 1_000)
    )
      throw new Error("Race caps are outside the supported range.");
    if (Object.values(nextCredentials).some((value) => value.trim().length > 0)) {
      saveStoredCredentialVault(nextCredentials);
      setHasSavedKeys(true);
    } else {
      clearStoredCredentialVault();
      setHasSavedKeys(false);
    }
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
    setSettings(cloneSettings(next));
    setCredentials({ ...nextCredentials });
  }
  async function cancelRun(): Promise<void> {
    if (!runId || cancelling) return;
    setCancelling(true);
    try {
      await cancelTrackedRun(runId);
      setRefreshTick((current) => current + 1);
    } catch (reason) {
      setRunError(
        reason instanceof Error ? reason.message : "Could not stop run.",
      );
    } finally {
      setCancelling(false);
    }
  }
  async function revealFlag(): Promise<void> {
    if (!runId || revealing || revealedFlag) return;
    setRevealing(true);
    try {
      const flag = (await revealVerifiedFlag(runId)).flag;
      setRevealedFlag(flag);
      addCandidateSuggestions([flag], "verified", "verified");
    } catch (reason) {
      const error =
        reason instanceof Error ? reason : new Error("Could not reveal flag.");
      setRunError(error.message);
      throw error;
    } finally {
      setRevealing(false);
    }
  }
  async function steerRacer(label: RacerLabel, message: string): Promise<void> {
    if (!runId) throw new Error("Open a Power run before directing a racer.");
    const racer = powerSessions.find((session) => session.label === label && session.role === "racer");
    if (!racer) throw new Error(`Racer ${label} is not ready for a suggestion yet.`);
    await steerPowerSession(runId, racer.id, message);
    setRefreshTick((current) => current + 1);
  }

  return (
    <div className="power-shell">
      <header className="power-header">
        <a href="/" className="power-brand" aria-label="CTFMesh Power home">
          <span>CM</span>
          <strong>CTFMesh</strong>
          <small>Operator Desk</small>
        </a>
        <span className="power-header-state">
          <i aria-hidden="true" /> Power
        </span>
      </header>
      <div className="power-layout" data-panel-open={activeView !== null}>
        <nav className="power-activity-bar" aria-label="Operator views">
          <div>
            <OperatorViewButton
              view="history"
              label="History"
              active={activeView === "history"}
              onToggle={toggleView}
            />
            <OperatorViewButton
              view="progress"
              label="Progress"
              active={activeView === "progress"}
              onToggle={toggleView}
            />
            <OperatorViewButton
              view="stats"
              label="Stats"
              active={activeView === "stats"}
              onToggle={toggleView}
            />
            <OperatorViewButton
              view="help"
              label="Help"
              active={activeView === "help"}
              onToggle={toggleView}
            />
          </div>
          <button
            type="button"
            className="power-activity-button"
            aria-label="Settings"
            title="Settings"
            onClick={() => setSettingsOpen(true)}
          >
            <OperatorIcon name="settings" />
          </button>
        </nav>
        {activeView ? (
          <aside className="power-side-panel" aria-label={`${activeView} panel`}>
            <header>
              <span>OPERATOR</span>
              <h2>{activeView}</h2>
            </header>
            {activeView === "history" ? (
              <HistoryPanel
                archives={archives}
                runs={runs}
                onOpenArchive={(archive) => void chooseArchive(archive)}
                onOpenRun={openRun}
                onRemoveArchive={async (archive) => {
                  await removeArchiveIntake(archive.intake_id);
                  setArchives((current) =>
                    current.filter((item) => item.intake_id !== archive.intake_id),
                  );
                  setIntake((current) =>
                    current?.intake_id === archive.intake_id ? null : current,
                  );
                }}
              />
            ) : null}
            {activeView === "progress" ? (
              <section className="power-panel-list" aria-label="Active runs">
                {activeRuns.length ? (
                  <ol>
                    {activeRuns.map((run) => (
                      <li key={run.id}>
                        <button type="button" onClick={() => openRun(run.id)}>
                          <strong>{run.id.slice(0, 18)}…</strong>
                          <small>
                            {run.status} · {formatRunTime(run.updatedAt)}
                          </small>
                        </button>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p>No active run.</p>
                )}
              </section>
            ) : null}
            {activeView === "stats" ? (
              <dl className="power-stat-grid">
                <div>
                  <dt>Runs</dt>
                  <dd>{runs.length}</dd>
                </div>
                <div>
                  <dt>Solved</dt>
                  <dd>{solvedRuns}</dd>
                </div>
                <div>
                  <dt>Active</dt>
                  <dd>{activeRuns.length}</dd>
                </div>
                <div>
                  <dt>Turn cap</dt>
                  <dd>{raceCapacity}</dd>
                </div>
              </dl>
            ) : null}
            {activeView === "help" ? (
              <section className="power-help-panel">
                <p>Drop an archive, inspect the receipt, then start Power.</p>
                <p>Provider keys and racer models live in Settings.</p>
                <p>Open Progress to follow active runs.</p>
              </section>
            ) : null}
          </aside>
        ) : null}
        <main className="power-main">
          <PowerLaunch
            key={intake?.intake_id ?? "cold"}
            intake={intake}
            racers={[
              settings.racers.A,
              settings.racers.B,
              settings.racers.C,
            ]}
            credentials={credentials}
            capabilities={capabilities}
            budget={{
              wallTimeSeconds: settings.wallTimeSeconds,
              maxCostUsd: settings.maxCostUsd,
            }}
            onUpload={upload}
            onStart={start}
            onOpenSettings={() => setSettingsOpen(true)}
            busy={busy}
            error={workspaceError}
          />
        </main>
      </div>
      {settingsOpen ? (
        <PowerSettingsDialog
          value={settings}
          credentials={credentials}
          hasSavedKeys={hasSavedKeys}
          onClose={() => setSettingsOpen(false)}
          onSave={saveSettings}
          onForgetKeys={() => {
            clearStoredCredentialVault();
            setHasSavedKeys(false);
            setCredentials(emptyCredentials());
          }}
        />
      ) : null}
      {runId ? (
        <section className="power-run-window" aria-label="Power run workspace">
          {!snapshot ? (
            <div className="power-run-loading">
              <strong>{runError ?? "Opening run…"}</strong>
              <button
                type="button"
                className="power-secondary"
                onClick={() => {
                  navigateToRun(null);
                  setRunId(null);
                }}
              >
                Close
              </button>
            </div>
          ) : (
            <>
              {runError ? (
                <p className="power-form-error" role="alert">
                  {runError}
                </p>
              ) : null}
              <RunConsole
                snapshot={snapshot}
                embedded
                isCancelling={cancelling}
                onCancel={() => void cancelRun()}
                revealedFlag={revealedFlag}
                isRevealing={revealing}
                onRevealFlag={revealFlag}
                candidateSuggestions={candidateSuggestions}
                canRevealInputCandidates={Boolean(
                  intake?.analysis.static.candidate_flags.reveal_available,
                )}
                isRevealingInputCandidates={revealingInputCandidates}
                onRevealInputCandidates={revealInputCandidates}
                canRevealRuntimeCandidates
                isRevealingRuntimeCandidates={revealingRuntimeCandidates}
                onRevealRuntimeCandidates={revealRuntimeCandidates}
                isFindingMoreCandidates={findingMoreCandidates}
                onFindMoreCandidates={findMoreCandidates}
                onMarkCandidate={markCandidate}
                onOpenSessions={() => {
                  navigateToRun(null);
                  setRunId(null);
                }}
                onRefresh={() => setRefreshTick((current) => current + 1)}
                powerSessions={powerSessions}
                onSteerRacer={steerRacer}
              />
            </>
          )}
        </section>
      ) : null}
    </div>
  );
}
