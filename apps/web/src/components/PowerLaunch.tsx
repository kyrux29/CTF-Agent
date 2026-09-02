import { type ChangeEvent, type DragEvent, useState } from "react";

import type {
  ArchiveIntake,
  ArchiveProviderId,
  PowerRacerLaunch,
  RuntimeCapabilities,
} from "../api";
import type { ProviderCredentialVault } from "../credentialVault";

type BusyState = "idle" | "uploading" | "launching";

const PROVIDER_LABELS: Record<ArchiveProviderId, string> = {
  "openai-responses": "OpenAI",
  "gemini-openai-compat": "Gemini",
  "deepseek-chat": "DeepSeek",
};

function formatBytes(value: number): string {
  if (value < 1_024) return `${value} B`;
  if (value < 1_024 * 1_024) return `${Math.round(value / 1_024)} KiB`;
  return `${(value / (1_024 * 1_024)).toFixed(1)} MiB`;
}

function formatCost(value: number): string {
  return `$${value.toLocaleString("en", { maximumFractionDigits: 2 })}`;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

export function PowerLaunch({
  intake,
  racers,
  credentials,
  capabilities,
  budget,
  onUpload,
  onStart,
  onOpenSettings,
  busy,
  error,
}: {
  intake: ArchiveIntake | null;
  racers: readonly PowerRacerLaunch[];
  credentials: ProviderCredentialVault;
  capabilities: RuntimeCapabilities | null;
  budget: { wallTimeSeconds: number; maxCostUsd: number };
  onUpload: (file: File) => void;
  onStart: (
    target: { host: string; port: number } | undefined,
    acknowledged: boolean,
    offline: boolean,
    flagFormat: string,
    challengeDescription: string,
  ) => void;
  onOpenSettings: () => void;
  busy: BusyState;
  error: string | null;
}) {
  const [dragging, setDragging] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [offline, setOffline] = useState(false);
  const [flagFormat, setFlagFormat] = useState("");
  const [challengeDescription, setChallengeDescription] = useState("");

  const portNumber = Number(port);
  const hasTargetInput = Boolean(host.trim() || port.trim());
  const target = hasTargetInput
    ? host.trim() &&
      Number.isInteger(portNumber) &&
      portNumber >= 1 &&
      portNumber <= 65_535
      ? { host: host.trim(), port: portNumber }
      : undefined
    : undefined;
  const targetValid = !hasTargetInput || target !== undefined;
  const requiredProviders = unique(racers.map((racer) => racer.provider));
  const missingCodes: string[] = [];

  if (capabilities === null) {
    missingCodes.push("capability_check");
  } else if (!capabilities.power.ready) {
    missingCodes.push(...capabilities.power.missing);
  }
  for (const racer of racers) {
    if (!racer.model.trim()) missingCodes.push(`racer_model:${racer.label}`);
  }
  const missingProviders = requiredProviders.filter(
    (provider) => !credentials[provider].trim(),
  );
  if (missingProviders.length > 0) {
    missingCodes.push(
      ...missingProviders.map((provider) => `provider_key:${provider}`),
    );
  }
  if (!targetValid) missingCodes.push("target_host_port");
  if (target && !acknowledged) missingCodes.push("target_authorization");

  const blockers = unique(missingCodes);
  const ready = intake !== null && blockers.length === 0;

  function choose(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0];
    if (file) onUpload(file);
    event.target.value = "";
  }

  function drop(event: DragEvent<HTMLLabelElement>): void {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) onUpload(file);
  }

  if (!intake) {
    return (
      <section
        className="power-launch-card"
        aria-label="Power launch"
        data-empty="true"
      >
        <div className="power-launch-title">
          <p>POWER</p>
          <h1>New challenge</h1>
        </div>
        <label
          className="power-dropzone"
          data-dragging={dragging}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={drop}
        >
          <input
            type="file"
            accept=".zip,.tar,.tgz,.tar.gz,.tbz,.tar.bz2,.txz,.tar.xz"
            onChange={choose}
            disabled={busy !== "idle"}
          />
          <span aria-hidden="true">⇩</span>
          <strong>
            {busy === "uploading"
              ? "Inspecting archive…"
              : "No case yet. Drop ZIP or TAR."}
          </strong>
          <small>ZIP · TAR · up to 128 MiB</small>
        </label>
        <div className="power-cold-note">
          <span>Provider keys stay in</span>
          <button
            type="button"
            className="power-text-button"
            onClick={onOpenSettings}
          >
            Settings
          </button>
        </div>
        {error ? (
          <p className="power-form-error" role="alert">
            {error}
          </p>
        ) : null}
      </section>
    );
  }

  const categories = intake.analysis.static.category_hints
    .slice(0, 2)
    .map((hint) => hint.category)
    .join(" · ");

  return (
    <section className="power-launch-card" aria-label="Power launch">
      <div className="power-launch-title power-launch-title-row">
        <div>
          <p>POWER</p>
          <h1>{intake.archive.name}</h1>
        </div>
        <label className="power-replace-archive">
          Replace
          <input
            type="file"
            accept=".zip,.tar,.tgz,.tar.gz,.tbz,.tar.bz2,.txz,.tar.xz"
            onChange={choose}
            disabled={busy !== "idle"}
          />
        </label>
      </div>

      <section className="power-receipt" aria-label="Archive receipt">
        <div className="power-section-heading">
          <h2>Receipt</h2>
          <span>{categories || "unclassified"} · suggested</span>
        </div>
        <dl>
          <div>
            <dt>Format</dt>
            <dd>{intake.archive.format.toUpperCase()}</dd>
          </div>
          <div>
            <dt>Entries</dt>
            <dd>{intake.inventory.file_count}</dd>
          </div>
          <div>
            <dt>Expanded</dt>
            <dd>{formatBytes(intake.inventory.expanded_size_bytes)}</dd>
          </div>
          <div>
            <dt>SHA-256</dt>
            <dd title={intake.archive.sha256}>
              {intake.archive.sha256.slice(0, 12)}…
            </dd>
          </div>
        </dl>
      </section>

      <section className="power-racer-board" aria-label="Configured racers">
        <div className="power-section-heading">
          <h2>Racers</h2>
          <button
            type="button"
            className="power-text-button"
            onClick={onOpenSettings}
          >
            Edit in Settings
          </button>
        </div>
        {racers.map((racer) => (
          <div
            key={racer.label}
            className="power-racer-line"
            data-ready={Boolean(credentials[racer.provider] && racer.model)}
          >
            <strong>{racer.label}</strong>
            <span>{PROVIDER_LABELS[racer.provider]}</span>
            <code>{racer.model || "No model"}</code>
            <em>t={racer.temperature.toFixed(1)}</em>
          </div>
        ))}
      </section>

      <details className="power-target-card">
        <summary>Target · optional</summary>
        <div className="power-target-inputs">
          <input
            aria-label="TCP host"
            value={host}
            onChange={(event) => {
              setHost(event.target.value);
              setAcknowledged(false);
            }}
            placeholder="host"
            autoComplete="off"
            spellCheck={false}
          />
          <input
            aria-label="TCP port"
            type="number"
            min="1"
            max="65535"
            value={port}
            onChange={(event) => {
              setPort(event.target.value);
              setAcknowledged(false);
            }}
            placeholder="port"
          />
        </div>
        {host.trim() ? (
          <label className="power-check-row">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <span>Authorized CTF target</span>
          </label>
        ) : null}
      </details>

      <label className="power-flag-format" title="Optional literal template. Examples: picoCTF{...}, DUCTF{...}. This is not a regular expression.">
        <span>Flag format <em>optional</em></span>
        <input
          aria-label="Flag format"
          value={flagFormat}
          onChange={(event) => setFlagFormat(event.target.value)}
          placeholder="picoCTF{...}"
          maxLength={96}
          autoComplete="off"
          spellCheck={false}
        />
      </label>

      <label
        className="power-challenge-description"
        title="Optional challenge context for every racer. It is included in the first Pi brief."
      >
        <span>Description <em>optional</em></span>
        <textarea
          aria-label="Challenge description"
          value={challengeDescription}
          onChange={(event) => setChallengeDescription(event.target.value)}
          placeholder="Objective, supplied hint, or known behavior"
          maxLength={1000}
          rows={3}
          spellCheck={false}
        />
      </label>

      <div className="power-limit-line" aria-label="Power limits">
        <span>{Math.round(budget.wallTimeSeconds / 60)} min</span>
        <span>{formatCost(budget.maxCostUsd)}</span>
        <span>{racers.length} racers</span>
      </div>
      <div className="power-launch-actions">
        <label className="power-check-row">
          <input
            type="checkbox"
            checked={offline}
            onChange={(event) => setOffline(event.target.checked)}
          />
          <span>Contest offline</span>
        </label>
        <button
          type="button"
          className="power-primary"
          onClick={() => onStart(target, acknowledged, offline, flagFormat, challengeDescription)}
          disabled={!ready || busy !== "idle"}
        >
          {busy === "launching" ? "Starting…" : "Start Power"}
        </button>
      </div>
      {blockers.length > 0 ? (
        <p className="power-readiness" role="status" aria-live="polite">
          <span>missing:</span> <code>{blockers.join(" · ")}</code>
        </p>
      ) : (
        <p className="power-readiness" data-ready="true" role="status">
          ready
        </p>
      )}
      {error ? (
        <p className="power-form-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
