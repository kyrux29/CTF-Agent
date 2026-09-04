import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  type ArchiveIntake,
  type ArchiveIntakeSummary,
  type PowerProviderId,
  CUSTOM_POWER_PROVIDER,
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
  removeRun,
  releaseRunWorkspaces,
  revealArchiveCandidateFlags,
  loadRuntimeCandidateReviewQueue,
  refreshPowerCredentials,
  revealVerifiedFlag,
  rejectRuntimeCandidateReview,
  steerPowerSession,
  downloadRunArtifact,
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
// This is deliberately shorter than both the 30-second credential wait and
// the durable job lease. If the local Pi runner restarts, the browser
// re-deposits its locally stored key before a Power session can time out.
const POWER_CREDENTIAL_REFRESH_INTERVAL_MS = 3_000;
const SETTINGS_KEY = "ctfmesh.power-settings/v1";
const SETTINGS_FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");
// The model lists are suggestions in a free-text field, not a closed set: a
// provider ships new ids faster than this file is edited, and an operator
// knows which one they are paying for.
const POWER_PROVIDERS: ReadonlyArray<{
  id: PowerProviderId;
  label: string;
  models: readonly string[];
}> = [
  {
    id: "openai-responses",
    label: "OpenAI",
    models: ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"],
  },
  {
    id: "anthropic",
    label: "Anthropic",
    models: ["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"],
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
  {
    id: "openrouter",
    label: "OpenRouter",
    models: ["anthropic/claude-opus-5", "openai/gpt-5.6-sol", "qwen/qwen3-coder"],
  },
  { id: "groq", label: "Groq", models: ["llama-3.3-70b-versatile", "qwen3-32b"] },
  {
    id: "together",
    label: "Together",
    models: ["Qwen/Qwen3-Coder-480B", "deepseek-ai/DeepSeek-V3"],
  },
  { id: "mistral", label: "Mistral", models: ["mistral-large-latest", "codestral-latest"] },
  { id: "xai", label: "xAI", models: ["grok-4", "grok-code-fast-1"] },
  { id: "cerebras", label: "Cerebras", models: ["qwen-3-coder-480b", "llama-3.3-70b"] },
  {
    id: "fireworks",
    label: "Fireworks",
    models: ["accounts/fireworks/models/qwen3-coder-480b-a35b-instruct"],
  },
  {
    id: CUSTOM_POWER_PROVIDER,
    label: "Custom (OpenAI-compatible)",
    // Nothing to suggest: this is whatever the operator's own server serves.
    models: [],
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
  /**
   * Endpoint for the custom provider: a self-hosted gateway, or a model
   * server on this machine. Not a credential, but it is where the custom
   * provider's key is sent, so it is set here beside it.
   */
  customBaseUrl: string;
}

function emptyCredentials(): ProviderCredentialVault {
  return {};
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
  customBaseUrl: "",
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

function isProvider(value: unknown): value is PowerProviderId {
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
      customBaseUrl: typeof value.customBaseUrl === "string" ? value.customBaseUrl : "",
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

function modelOptions(providerId: PowerProviderId): readonly string[] {
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
          {POWER_PROVIDERS.some(
            (provider) =>
              provider.id === CUSTOM_POWER_PROVIDER && (keys[provider.id] ?? "").trim(),
          ) || Object.values(draft.racers).some(
            (racer) => racer.provider === CUSTOM_POWER_PROVIDER,
          ) ? (
            <label className="power-key-row">
              <span>Custom endpoint</span>
              <input
                type="url"
                aria-label="Custom provider base URL"
                value={draft.customBaseUrl}
                placeholder="http://192.168.1.50:11434/v1"
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    customBaseUrl: event.target.value,
                  }))
                }
                autoComplete="off"
              />
            </label>
          ) : null}
          <p className="power-setting-note">
            Saved locally in this browser. A custom endpoint must also be on the
            provider proxy&rsquo;s allowlist, and a plain http:// one sends the key
            unencrypted &mdash; keep it to a machine you own.
          </p>
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
                    const provider = event.target.value as PowerProviderId;
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
  const queuedCandidateQueueVersion = useRef<string | null>(null);
  const credentialRefreshInFlight = useRef(false);
  const credentialRefreshFailures = useRef(0);

  const addCandidateSuggestions = useCallback(
    (
      values: readonly string[],
      source: PowerCandidateSuggestion["source"],
      status: PowerCandidateStatus = "unreviewed",
      racerLabels?: readonly ("auto" | "A" | "B" | "C")[],
      reviewEligible = false,
      racerSessionIds?: readonly string[],
    ): void => {
      setCandidateSuggestions((current) => {
        const next = current.map((candidate) => ({ ...candidate }));
        for (const value of values) {
          const trimmed = value.trim();
          if (!trimmed || trimmed.length > 1_024) continue;
          const existing = next.find((candidate) => candidate.value === trimmed);
          if (existing) {
            if (status === "verified") existing.status = "verified";
            if (reviewEligible) existing.reviewEligible = true;
            if (racerLabels?.length) {
              existing.racerLabels = [...new Set([
                ...(existing.racerLabels ?? []),
                ...racerLabels,
              ])];
            }
            if (racerSessionIds?.length) {
              existing.racerSessionIds = [...new Set([
                ...(existing.racerSessionIds ?? []),
                ...racerSessionIds,
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
            reviewEligible,
            racerSessionIds,
          });
        }
        return next;
      });
    },
    [],
  );

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
    ? ["queued", "ready", "running", "paused", "verifying"].includes(snapshot.run.status)
    : false;
  useEffect(() => {
    if (!runLive) return;
    const timer = window.setInterval(
      () => setRefreshTick((current) => current + 1),
      1_000,
    );
    return () => window.clearInterval(timer);
  }, [runLive]);
  useEffect(() => {
    const activePowerRun = Boolean(
      runId
      && snapshot?.run.id === runId
      && snapshot.run.provider_label === "power-swarm"
      && (snapshot.run.status === "running" || snapshot.run.status === "paused"),
    );
    if (!activePowerRun || !runId) {
      credentialRefreshFailures.current = 0;
      return;
    }

    // Send every non-empty vault entry. The API derives which provider/model
    // each durable racer actually uses, so editing Settings mid-run cannot
    // retarget an existing racer and a run can still recover after reload.
    const providerKeys: Partial<Record<PowerProviderId, string>> = {};
    for (const provider of POWER_PROVIDERS) {
      const key = (credentials[provider.id] ?? "").trim();
      if (key) providerKeys[provider.id] = key;
    }
    if (Object.keys(providerKeys).length === 0) {
      setRunError("Open Settings and restore the local provider key to keep this race running.");
      return;
    }

    let disposed = false;
    const refreshCredentialLease = (): void => {
      if (disposed || credentialRefreshInFlight.current) return;
      credentialRefreshInFlight.current = true;
      void refreshPowerCredentials(runId, providerKeys)
        .then(() => {
          credentialRefreshFailures.current = 0;
        })
        .catch(() => {
          credentialRefreshFailures.current += 1;
          // Avoid a transient local restart becoming a flashing UI warning.
          // Three failed renewal windows mean the racer could lose its next
          // lease, so surface one clear operator action instead.
          if (!disposed && credentialRefreshFailures.current >= 3) {
            setRunError("Could not renew the local model credential. Check Settings and the Power runtime.");
          }
        })
        .finally(() => {
          credentialRefreshInFlight.current = false;
        });
    };
    const refreshWhenVisible = (): void => {
      if (document.visibilityState === "visible") refreshCredentialLease();
    };

    refreshCredentialLease();
    const timer = window.setInterval(
      refreshCredentialLease,
      POWER_CREDENTIAL_REFRESH_INTERVAL_MS,
    );
    window.addEventListener("focus", refreshCredentialLease);
    window.addEventListener("online", refreshCredentialLease);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      disposed = true;
      window.clearInterval(timer);
      window.removeEventListener("focus", refreshCredentialLease);
      window.removeEventListener("online", refreshCredentialLease);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [credentials, runId, snapshot?.run.id, snapshot?.run.provider_label, snapshot?.run.status]);
  useEffect(() => {
    const heldRacerSessionIds = powerSessions
      .filter((session) => session.role === "racer" && session.state === "awaiting_review")
      .map((session) => session.id)
      .sort();
    const isPendingRuntimeQueue = Boolean(
      runId
      && snapshot?.run.id === runId
      && snapshot.run.provider_label === "power-swarm"
      && (heldRacerSessionIds.length > 0 || snapshot.run.status === "paused"),
    );
    const queueSequence = snapshot?.run.event_sequence;
    if (!isPendingRuntimeQueue || !runId || queueSequence === undefined) {
      queuedCandidateQueueVersion.current = null;
      return;
    }
    // A durable per-racer hold is the source of truth. The session IDs let a
    // second racer add a candidate while the first stays held; the ref avoids
    // duplicate reads during React renders and fast polls.
    const queueVersion = `${runId}:${queueSequence}:${heldRacerSessionIds.join(":")}`;
    if (queuedCandidateQueueVersion.current === queueVersion) return;
    queuedCandidateQueueVersion.current = queueVersion;
    let cancelled = false;
    setRevealingRuntimeCandidates(true);
    setRunError(null);
    void loadRuntimeCandidateReviewQueue(runId)
      .then((queue) => {
        if (cancelled) return;
        for (const candidate of queue.candidates) {
          addCandidateSuggestions(
            [candidate.value],
            "runtime",
            "unreviewed",
            candidate.racerLabels,
            true,
            candidate.racerSessionIds,
          );
        }
        if (!queue.scanComplete) {
          setRunError(
            `${queue.unavailableArtifactCount} candidate observation(s) could not be read; stop the run or inspect its trace.`,
          );
        }
      })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setRunError(
            reason instanceof Error
              ? reason.message
              : "The pending candidate queue could not be loaded.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setRevealingRuntimeCandidates(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    addCandidateSuggestions,
    runId,
    snapshot?.run.event_sequence,
    snapshot?.run.id,
    snapshot?.run.provider_label,
    snapshot?.run.status,
    powerSessions,
  ]);
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
    queuedCandidateQueueVersion.current = null;
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
    // The custom provider is the only one whose endpoint this deployment does
    // not already know, so the API refuses the pair apart. Saying which half
    // is missing here beats letting that come back as a validation code.
    if (
      racers.some((racer) => racer.provider === CUSTOM_POWER_PROVIDER)
      && !settings.customBaseUrl.trim()
    ) {
      setWorkspaceError(
        "Open Settings and enter the custom endpoint, or pick a provider that has its own.",
      );
      return;
    }
    const providerKeys: Partial<Record<PowerProviderId, string>> = {};
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
      customBaseUrl: settings.customBaseUrl.trim(),
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
  async function markCandidate(id: string, status: PowerCandidateStatus): Promise<void> {
    const candidate = candidateSuggestions.find((item) => item.id === id);
    if (!candidate) return;
    const heldRacerSessionIds = new Set(
      powerSessions
        .filter((session) => session.role === "racer" && session.state === "awaiting_review")
        .map((session) => session.id),
    );
    const sourceSessionId = candidate.racerSessionIds?.find((sessionId) =>
      heldRacerSessionIds.has(sessionId),
    );
    const legacyGatePending = snapshot?.run.status === "paused";
    if (
      candidate.source === "runtime"
      && candidate.reviewEligible
      && (sourceSessionId !== undefined || legacyGatePending)
    ) {
      if (!runId) return;
      if (status === "manual_valid") {
        const decision = await confirmRuntimeCandidateReview(
          runId,
          candidate.value,
          sourceSessionId,
        );
        status = decision.accepted ? "verified" : "manual_rejected";
      } else if (status === "manual_rejected") {
        await rejectRuntimeCandidateReview(runId, sourceSessionId);
      }
      // A failed verification or explicit rejection resumes exactly the
      // source lane. If the same value was independently observed by another
      // held racer, keep that second source in the review queue.
      if (sourceSessionId) {
        setCandidateSuggestions((current) =>
          current.map((item) => {
            if (item.id !== id) return item;
            const remainingSessionIds = item.racerSessionIds?.filter(
              (sessionId) => sessionId !== sourceSessionId,
            );
            return {
              ...item,
              racerSessionIds: remainingSessionIds,
              status: remainingSessionIds?.length ? "unreviewed" : status,
            };
          }),
        );
      } else {
        setCandidateSuggestions((current) =>
          current.map((item) => item.id === id ? { ...item, status } : item),
        );
      }
      setRefreshTick((current) => current + 1);
      return;
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
  async function findMoreCandidates(): Promise<void> {
    if (!runId || findingMoreCandidates) return;
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
      if (powerSessions.some(
        (session) => session.role === "racer" && session.state === "awaiting_review",
      )) {
        throw new Error("Review or dismiss the held racer candidate before searching from that lane.");
      }
      if (!intake || !lastPowerLaunch) {
        throw new Error("No active racer is available. Start a new Power run to search again.");
      }
      const racers = [settings.racers.A, settings.racers.B, settings.racers.C];
      const providerKeys: Partial<Record<PowerProviderId, string>> = {};
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

  async function continueRun(): Promise<void> {
    const source = snapshot?.run;
    if (!source?.source_intake_id) {
      throw new Error("This run does not name the archive it came from.");
    }
    const racers = (["A", "B", "C"] as const).map((label) => ({
      label,
      provider: settings.racers[label].provider,
      model: settings.racers[label].model,
      temperature: settings.racers[label].temperature,
    }));
    const providerKeys: Partial<Record<PowerProviderId, string>> = {};
    for (const racer of racers) {
      const key = (credentials[racer.provider] ?? "").trim();
      if (!key) {
        throw new Error(`Open Settings and add the ${racer.provider} key first.`);
      }
      providerKeys[racer.provider] = key;
    }
    // Reuse the target this run was scoped to. Continuing against a different
    // one would resume transcripts that describe somewhere else.
    if (
      racers.some((racer) => racer.provider === CUSTOM_POWER_PROVIDER)
      && !settings.customBaseUrl.trim()
    ) {
      throw new Error(
        "Open Settings and enter the custom endpoint, or pick a provider that has its own.",
      );
    }
    const scope = /^tcp:\/\/(.+):(\d+)$/.exec(source.target_scope ?? "");
    const target = scope ? { host: scope[1]!, port: Number(scope[2]) } : undefined;
    const run = await launchPowerRun(source.source_intake_id, {
      ...(target ? { target } : {}),
      authorizedTarget: target !== undefined,
      contestOffline: lastPowerLaunch?.contestOffline ?? false,
      flagFormat: lastPowerLaunch?.flagFormat ?? "",
      challengeDescription: lastPowerLaunch?.challengeDescription ?? "",
      racers,
      providerKeys,
      customBaseUrl: settings.customBaseUrl.trim(),
      continueFromRunId: source.id,
      budget: {
        wallTimeSeconds: settings.wallTimeSeconds,
        maxCostUsd: settings.maxCostUsd,
        maxTurnCostUsd: settings.maxTurnCostUsd,
      },
    });
    openRun(run.runId);
    await refreshWorkspace();
  }

  async function releaseWorkspaces(): Promise<number> {
    if (!runId) throw new Error("Open a run before releasing its workspaces.");
    const released = await releaseRunWorkspaces(runId);
    setRefreshTick((current) => current + 1);
    return released;
  }

  async function saveArtifact(artifactId: string): Promise<void> {
    if (!runId) throw new Error("Open a run before saving its evidence.");
    const blob = await downloadRunArtifact(runId, artifactId);
    // Name the file after the digest that identifies it, so a saved script or
    // dump stays matched to the observation and the receipt that named it.
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${artifactId.replace(":", "-")}.bin`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
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
                onRemoveRun={async (id) => {
                  await removeRun(id);
                  setRuns((current) => current.filter((item) => item.id !== id));
                  // Leaving the console open on a run that no longer exists
                  // would show a snapshot the API can no longer refresh.
                  if (runId === id) {
                    navigateToRun(null);
                    setRunId(null);
                  }
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
                isLoadingRuntimeCandidates={revealingRuntimeCandidates}
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
                onSaveArtifact={saveArtifact}
                onReleaseWorkspaces={releaseWorkspaces}
                onContinueRun={continueRun}
              />
            </>
          )}
        </section>
      ) : null}
    </div>
  );
}
