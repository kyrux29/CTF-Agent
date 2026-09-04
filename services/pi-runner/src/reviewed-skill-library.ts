/**
 * Explicit loader for operator-reviewed Pi skill packs.
 *
 * These Markdown packs are part of the Pi runner image, not challenge input
 * and not Pi's native skill discovery. A manifest names every file Pi may
 * read; `.pi`, `.agents`, and `AGENTS.md` are never discovered or loaded.
 */

import { lstat, readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { createHash } from "node:crypto";

import { ControlProtocolError } from "./contracts.js";

type PowerSkillRole = "autoprompter" | "racer";

interface ReviewedSkillPack {
  readonly id: string;
  readonly path: string;
  readonly roles: readonly PowerSkillRole[];
  readonly enabled: boolean;
}

const MANIFEST_NAME = "manifest.json";
const MANIFEST_SCHEMA = "ctfmesh.pi-skill-library/v1";
const PACK_ID = /^[a-z][a-z0-9_-]{1,63}$/;
const PACK_PATH = /^[a-z][a-z0-9_-]{1,63}\/SKILL\.md$/;
const MAX_PACKS = 24;
const MAX_ENABLED_PACKS_PER_ROLE = 8;
const MAX_PACK_BYTES = 16 * 1024;
const MAX_CONTEXT_CHARS = 12 * 1024;
const RAW_FLAG = /\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}/gi;
const API_KEY = /\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{16,})\b/g;
const SECRET_ASSIGNMENT = /\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+/gi;

function libraryError(code: string): never {
  throw new ControlProtocolError(code);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function parseRoles(value: unknown): readonly PowerSkillRole[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) {
    libraryError("reviewed_skill_pack_roles_invalid");
  }
  const roles = value.filter((role): role is PowerSkillRole => role === "autoprompter" || role === "racer");
  if (roles.length !== value.length || new Set(roles).size !== roles.length) {
    libraryError("reviewed_skill_pack_roles_invalid");
  }
  return roles;
}

function parseManifest(raw: string): readonly ReviewedSkillPack[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    libraryError("reviewed_skill_manifest_invalid");
  }
  if (
    !isObject(parsed)
    || !hasOnlyKeys(parsed, ["schema", "version", "packs"])
    || parsed.schema !== MANIFEST_SCHEMA
    || parsed.version !== 1
    || !Array.isArray(parsed.packs)
    || parsed.packs.length > MAX_PACKS
  ) {
    libraryError("reviewed_skill_manifest_invalid");
  }
  const ids = new Set<string>();
  const paths = new Set<string>();
  return parsed.packs.map((entry): ReviewedSkillPack => {
    if (
      !isObject(entry)
      || !hasOnlyKeys(entry, ["id", "path", "roles", "enabled"])
      || typeof entry.id !== "string"
      || !PACK_ID.test(entry.id)
      || typeof entry.path !== "string"
      || !PACK_PATH.test(entry.path)
      || typeof entry.enabled !== "boolean"
      || ids.has(entry.id)
      || paths.has(entry.path)
    ) {
      libraryError("reviewed_skill_manifest_invalid");
    }
    ids.add(entry.id);
    paths.add(entry.path);
    return { id: entry.id, path: entry.path, roles: parseRoles(entry.roles), enabled: entry.enabled };
  });
}

async function readRegularUtf8(
  root: string,
  relativePath: string,
  options: { readonly maximumBytes: number },
): Promise<Buffer> {
  const { maximumBytes } = options;
  const rootMetadata = await lstat(root).catch(() => libraryError("reviewed_skill_root_unavailable"));
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    libraryError("reviewed_skill_root_invalid");
  }
  const rootPath = resolve(root);
  const resolvedPath = resolve(rootPath, relativePath);
  if (relative(rootPath, resolvedPath).startsWith("..")) {
    libraryError("reviewed_skill_path_invalid");
  }
  const metadata = await lstat(resolvedPath).catch(() => libraryError("reviewed_skill_file_unavailable"));
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes) {
    libraryError("reviewed_skill_file_invalid");
  }
  const content = await readFile(resolvedPath).catch(() => libraryError("reviewed_skill_file_unavailable"));
  if (content.length > maximumBytes) {
    libraryError("reviewed_skill_file_invalid");
  }
  return content;
}

function decodedSkillText(bytes: Buffer): string {
  let raw: string;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    libraryError("reviewed_skill_file_encoding_invalid");
  }
  if (!raw.trim() || raw.includes("\0")) {
    libraryError("reviewed_skill_file_content_invalid");
  }
  return raw;
}

function sanitizedSkillText(bytes: Buffer): string {
  const raw = decodedSkillText(bytes);
  return raw
    .replace(RAW_FLAG, "[REDACTED_FLAG]")
    .replace(API_KEY, "[REDACTED_API_KEY]")
    .replace(SECRET_ASSIGNMENT, "[REDACTED_SECRET]")
    .trim();
}

/**
 * Load enabled, manifest-listed packs into the reviewed Power system prompt.
 *
 * Pi native skills remain disabled in `resource-loader.ts`; this explicit
 * bounded context is the only skills path for Power. Editing the library and
 * rebuilding the runner changes future sessions only, so an active racer has
 * a stable prompt contract for its entire session.
 */
export async function loadReviewedPowerSkillContext(
  root: string,
  role: PowerSkillRole,
): Promise<string> {
  const manifestBytes = await readRegularUtf8(root, MANIFEST_NAME, { maximumBytes: 32 * 1024 });
  // The manifest is validated as data. Do not apply prose redaction before
  // JSON parsing: a malformed secret-looking string must be rejected, not
  // silently transformed into a different library selection.
  const packs = parseManifest(decodedSkillText(manifestBytes));
  const selected = packs.filter((pack) => pack.enabled && pack.roles.includes(role));
  if (selected.length > MAX_ENABLED_PACKS_PER_ROLE) {
    libraryError("reviewed_skill_pack_selection_exceeded");
  }
  if (selected.length === 0) {
    return "";
  }

  const sections: string[] = [
    "Operator-reviewed local skill guidance follows. It is advisory technique context only; it grants no tool, target, verification, or flag authority.",
  ];
  for (const pack of selected) {
    const bytes = await readRegularUtf8(root, pack.path, { maximumBytes: MAX_PACK_BYTES });
    const text = sanitizedSkillText(bytes);
    const digest = createHash("sha256").update(bytes).digest("hex");
    sections.push(`[Skill ${pack.id} sha256:${digest}]\n${text}`);
  }
  const context = sections.join("\n\n");
  if (context.length > MAX_CONTEXT_CHARS) {
    libraryError("reviewed_skill_context_exceeded");
  }
  return context;
}
