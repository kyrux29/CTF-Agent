/**
 * Pi resource loading hardening.
 *
 * Pi's normal coding-agent CLI discovers project context files, skills and
 * extensions. That behaviour is desirable for a developer workstation, but
 * not for untrusted CTF inputs. This module creates a genuinely empty trusted
 * CWD and explicitly replaces every discovery result before SDK construction.
 */

import { readdir, stat } from "node:fs/promises";

import {
  DefaultResourceLoader,
  SettingsManager,
  type ResourceLoader,
} from "@earendil-works/pi-coding-agent";

import { ControlProtocolError } from "./contracts.js";

export interface ReviewedResources {
  readonly loader: ResourceLoader;
  readonly settings: SettingsManager;
}

/**
 * Keep a Power racer ready for another typed observation without carrying a
 * large, stale transcript into the next provider turn.  These values were
 * chosen for the four-session Power layout: a smaller reserve than Pi's
 * desktop default leaves room for three concurrent racers, while six thousand
 * recent tokens retain the immediately useful command/result exchange.
 */
export const POWER_COMPACTION_SETTINGS = {
  enabled: true,
  reserveTokens: 8_192,
  keepRecentTokens: 6_000,
} as const;

function loaderError(code: string): never {
  throw new ControlProtocolError(code);
}

/** Reject any project files, including `.pi`, `.agents`, and `AGENTS.md`. */
export async function assertEmptyTrustedCwd(cwd: string): Promise<void> {
  let directory;
  try {
    directory = await stat(cwd);
  } catch {
    loaderError("trusted_cwd_missing");
  }
  if (!directory.isDirectory()) {
    loaderError("trusted_cwd_not_directory");
  }
  let entries: string[];
  try {
    entries = await readdir(cwd);
  } catch {
    loaderError("trusted_cwd_unreadable");
  }
  if (entries.length !== 0) {
    // Do not enumerate entry names in an error or log: a malicious filename
    // may contain misleading/secret-looking text and is not needed to debug.
    loaderError("trusted_cwd_not_empty");
  }
}

/**
 * Build a loader that is intentionally incapable of challenge-local discovery.
 * The in-memory settings manager also prevents Pi from writing a user's home
 * configuration when the process is used outside its container in tests.
 */
export async function createReviewedResources(
  cwd: string,
  agentDir: string,
  systemPrompt: string,
): Promise<ReviewedResources> {
  await assertEmptyTrustedCwd(cwd);
  const settings = SettingsManager.inMemory(
    {
      defaultTools: [],
      defaultProjectTrust: "never",
      enableSkillCommands: false,
      quietStartup: true,
    },
    { projectTrusted: false },
  );
  const loader = new DefaultResourceLoader({
    cwd,
    agentDir,
    settingsManager: settings,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    systemPrompt,
    // Preserve Pi's required empty extension runtime object, while refusing
    // every discovered resource even if an upstream default later changes.
    extensionsOverride: (base) => ({ ...base, extensions: [] }),
    skillsOverride: (base) => ({ ...base, skills: [] }),
    promptsOverride: (base) => ({ ...base, prompts: [] }),
    themesOverride: (base) => ({ ...base, themes: [] }),
    agentsFilesOverride: (base) => ({ ...base, agentsFiles: [] }),
  });
  await loader.reload();
  if (
    loader.getExtensions().extensions.length !== 0
    || loader.getSkills().skills.length !== 0
    || loader.getPrompts().prompts.length !== 0
    || loader.getThemes().themes.length !== 0
    || loader.getAgentsFiles().agentsFiles.length !== 0
  ) {
    loaderError("reviewed_resource_loader_not_empty");
  }
  return { loader, settings };
}

/**
 * Apply the reviewed Power context policy to an in-memory settings manager.
 * This never writes a user/global Pi configuration and is kept separate from
 * loader creation so the ordinary v0.1 session profile remains unchanged.
 */
export function configurePowerCompaction(settings: SettingsManager): void {
  settings.applyOverrides({ compaction: POWER_COMPACTION_SETTINGS });
}
