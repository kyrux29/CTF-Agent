/**
 * Ephemeral, authenticated model-credential leases for the live Pi runner.
 *
 * The control API deposits a credential for one run over the private control
 * network.  This module intentionally has no file, database, event, or log
 * output path: an API key exists only in this process until the lease expires
 * or its owning session is disposed.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { Socket } from "node:net";

import { ControlProtocolError } from "./contracts.js";

export const LIVE_MODEL_PROVIDERS = ["openai", "google", "deepseek"] as const;

export type LiveModelProvider = (typeof LIVE_MODEL_PROVIDERS)[number];

export interface CredentialLeaseInput {
  readonly runId: string;
  /**
   * Power owns four concurrent models, so its credential is scoped to a
   * durable Pi session. Older v0.1 work remains safely keyed by runId.
   */
  readonly sessionId?: string;
  readonly provider: LiveModelProvider;
  readonly model: string;
  readonly apiKey: string;
  readonly ttlSeconds: number;
}

/** The runner-internal view deliberately never crosses an HTTP response. */
export interface ActiveCredentialLease {
  readonly runId: string;
  readonly sessionId?: string;
  readonly provider: LiveModelProvider;
  readonly model: string;
  readonly apiKey: string;
  readonly expiresAtMs: number;
  readonly revision: number;
}

export interface CredentialLeaseReceipt {
  readonly accepted: true;
  readonly expires_at: string;
}

export interface CredentialLeaseBrokerOptions {
  readonly controlToken: string;
  readonly bindHost: string;
  readonly bindPort: number;
}

type LeaseRevoker = () => void | Promise<void>;

interface LeaseEntry extends ActiveCredentialLease {
  readonly timer: ReturnType<typeof setTimeout>;
  readonly revokers: Set<LeaseRevoker>;
}

const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}$/;
const API_KEY_MAX_LENGTH = 4_096;
const MIN_TTL_SECONDS = 30;
const MAX_REQUEST_BYTES = 8 * 1024;
const CREDENTIAL_BROKER_HOSTS = new Set(["0.0.0.0", "127.0.0.1", "::", "::1"]);
const MAX_ACTIVE_LEASES = 64;

function leaseError(code: string): never {
  throw new ControlProtocolError(code);
}

function isLiveModelProvider(value: unknown): value is LiveModelProvider {
  return typeof value === "string" && (LIVE_MODEL_PROVIDERS as readonly string[]).includes(value);
}

function validateLeaseInput(input: CredentialLeaseInput, maxTtlSeconds: number): void {
  if (!RUN_ID.test(input.runId)) {
    leaseError("credential_lease_run_id_invalid");
  }
  if (input.sessionId !== undefined && !RUN_ID.test(input.sessionId)) {
    leaseError("credential_lease_session_id_invalid");
  }
  if (!isLiveModelProvider(input.provider)) {
    leaseError("credential_lease_provider_invalid");
  }
  if (!MODEL_ID.test(input.model)) {
    leaseError("credential_lease_model_invalid");
  }
  // Keep the key opaque.  We only reject unsafe transport/control characters
  // and accidental whitespace; no provider-specific key format is assumed.
  if (
    input.apiKey.length < 8
    || input.apiKey.length > API_KEY_MAX_LENGTH
    || input.apiKey.trim() !== input.apiKey
    || /[\u0000-\u001F\u007F]/u.test(input.apiKey)
  ) {
    leaseError("credential_lease_api_key_invalid");
  }
  if (
    !Number.isSafeInteger(input.ttlSeconds)
    || input.ttlSeconds < MIN_TTL_SECONDS
    || input.ttlSeconds > maxTtlSeconds
  ) {
    leaseError("credential_lease_ttl_invalid");
  }
}

function noOp(): void {
  // Deliberately empty: a best-effort revoker must never surface an SDK error
  // whose message could contain a provider or credential-derived value.
}

/**
 * Process-local lease registry. `setTimeout` evicts expired material even
 * when no later request touches the run.  A revision prevents an old timer
 * from deleting a replacement lease for the same run.
 */
export class CredentialLeaseStore {
  private readonly entries = new Map<string, LeaseEntry>();
  private readonly waiters = new Map<string, Set<(lease: ActiveCredentialLease | undefined) => void>>();
  private nextRevision = 1;

  public constructor(
    private readonly maxTtlSeconds: number,
    private readonly now: () => number = Date.now,
  ) {
    if (!Number.isSafeInteger(maxTtlSeconds) || maxTtlSeconds < MIN_TTL_SECONDS || maxTtlSeconds > 3_600) {
      leaseError("credential_lease_max_ttl_invalid");
    }
  }

  public put(input: CredentialLeaseInput): CredentialLeaseReceipt {
    validateLeaseInput(input, this.maxTtlSeconds);
    const leaseId = input.sessionId ?? input.runId;
    if (!this.entries.has(leaseId) && this.entries.size >= MAX_ACTIVE_LEASES) {
      leaseError("credential_lease_capacity_exceeded");
    }
    this.revoke(leaseId);

    const expiresAtMs = this.now() + input.ttlSeconds * 1_000;
    const revision = this.nextRevision;
    this.nextRevision += 1;
    const timer = setTimeout(() => this.revoke(leaseId, revision), input.ttlSeconds * 1_000);
    // Lease expiry must not keep a test process or a shutting-down container
    // alive solely because it holds a credential.
    timer.unref();
    const lease: LeaseEntry = {
      ...input,
      expiresAtMs,
      revision,
      timer,
      revokers: new Set(),
    };
    this.entries.set(leaseId, lease);
    this.resolveWaiters(leaseId, lease);
    return { accepted: true, expires_at: new Date(expiresAtMs).toISOString() };
  }

  /** Read a still-valid lease for the Pi session factory; never serialize it. */
  public get(leaseId: string): ActiveCredentialLease | undefined {
    const entry = this.entries.get(leaseId);
    if (entry === undefined) {
      return undefined;
    }
    if (entry.expiresAtMs <= this.now()) {
      this.revoke(leaseId, entry.revision);
      return undefined;
    }
    return {
      runId: entry.runId,
      ...(entry.sessionId === undefined ? {} : { sessionId: entry.sessionId }),
      provider: entry.provider,
      model: entry.model,
      apiKey: entry.apiKey,
      expiresAtMs: entry.expiresAtMs,
      revision: entry.revision,
    };
  }

  /**
   * Wait briefly for the API's deposit when a start job races its HTTP call.
   * The timeout has no side effects and cannot manufacture a credential.
   */
  public async waitFor(leaseId: string, timeoutMs: number): Promise<ActiveCredentialLease | undefined> {
    if (!RUN_ID.test(leaseId) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 30_000) {
      leaseError("credential_lease_wait_invalid");
    }
    const active = this.get(leaseId);
    if (active !== undefined || timeoutMs === 0) {
      return active;
    }
    return new Promise((resolve) => {
      const waiter = (lease: ActiveCredentialLease | undefined): void => {
        clearTimeout(timer);
        resolve(lease);
      };
      const current = this.waiters.get(leaseId) ?? new Set<(lease: ActiveCredentialLease | undefined) => void>();
      current.add(waiter);
      this.waiters.set(leaseId, current);
      const timer = setTimeout(() => {
        const pending = this.waiters.get(leaseId);
        pending?.delete(waiter);
        if (pending?.size === 0) {
          this.waiters.delete(leaseId);
        }
        resolve(undefined);
      }, timeoutMs);
      timer.unref();
    });
  }

  /**
   * Register a runtime-key remover against this exact lease revision.  A
   * replacement or expiry invokes it, so a long-lived Pi session cannot keep
   * using an expired browser-supplied key.
   */
  public subscribe(lease: ActiveCredentialLease, revoker: LeaseRevoker): (() => void) | undefined {
    const leaseId = lease.sessionId ?? lease.runId;
    const active = this.get(leaseId);
    if (active === undefined || active.revision !== lease.revision) {
      return undefined;
    }
    const entry = this.entries.get(leaseId);
    if (entry === undefined) {
      return undefined;
    }
    entry.revokers.add(revoker);
    return () => entry.revokers.delete(revoker);
  }

  /** Remove every secret and notify dependent Pi runtimes during shutdown. */
  public close(): void {
    for (const runId of [...this.entries.keys()]) {
      this.revoke(runId);
    }
    for (const [runId, pending] of this.waiters) {
      this.waiters.delete(runId);
      for (const resolve of pending) {
        resolve(undefined);
      }
    }
  }

  private revoke(runId: string, expectedRevision?: number): void {
    const entry = this.entries.get(runId);
    if (entry === undefined || (expectedRevision !== undefined && entry.revision !== expectedRevision)) {
      return;
    }
    clearTimeout(entry.timer);
    this.entries.delete(runId);
    for (const revoker of entry.revokers) {
      void Promise.resolve(revoker()).catch(noOp);
    }
    entry.revokers.clear();
  }

  private resolveWaiters(runId: string, lease: ActiveCredentialLease): void {
    const pending = this.waiters.get(runId);
    if (pending === undefined) {
      return;
    }
    this.waiters.delete(runId);
    for (const resolve of pending) {
      resolve(lease);
    }
  }
}

function sameToken(received: string | string[] | undefined, expected: string): boolean {
  if (typeof received !== "string") {
    return false;
  }
  const receivedBytes = Buffer.from(received, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  return receivedBytes.length === expectedBytes.length && timingSafeEqual(receivedBytes, expectedBytes);
}

function sendJson(response: ServerResponse, statusCode: number, body: Record<string, unknown>): void {
  const encoded = JSON.stringify(body);
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(encoded),
  });
  response.end(encoded);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of request) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > MAX_REQUEST_BYTES) {
        request.resume();
        leaseError("credential_lease_request_too_large");
      }
      chunks.push(bytes);
    }
  } catch (error) {
    if (error instanceof ControlProtocolError) {
      throw error;
    }
    leaseError("credential_lease_request_unreadable");
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    leaseError("credential_lease_request_not_json");
  }
}

function parseInput(value: unknown): CredentialLeaseInput {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    leaseError("credential_lease_request_invalid");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set(["run_id", "session_id", "provider", "model", "api_key", "ttl_seconds"]);
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    leaseError("credential_lease_request_unknown_field");
  }
  const runId = record.run_id;
  const sessionId = record.session_id;
  const provider = record.provider;
  const model = record.model;
  const apiKey = record.api_key;
  const ttlSeconds = record.ttl_seconds;
  if (
    typeof runId !== "string"
    || (sessionId !== undefined && typeof sessionId !== "string")
    || !isLiveModelProvider(provider)
    || typeof model !== "string"
    || typeof apiKey !== "string"
    || typeof ttlSeconds !== "number"
  ) {
    leaseError("credential_lease_request_invalid");
  }
  return { runId, ...(sessionId === undefined ? {} : { sessionId }), provider, model, apiKey, ttlSeconds };
}

function requestPath(request: IncomingMessage): string | undefined {
  if (request.url === undefined) {
    return undefined;
  }
  let parsed: URL;
  try {
    parsed = new URL(request.url, "http://credential-broker.invalid");
  } catch {
    return undefined;
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    return undefined;
  }
  return parsed.pathname;
}

/**
 * Tiny private HTTP ingress for API-to-runner key handoff.  It deliberately
 * exposes no lookup endpoint: the only HTTP operation stores a lease and
 * returns non-secret receipt metadata.
 */
export class CredentialLeaseBroker {
  private readonly sockets = new Set<Socket>();
  private server: Server | undefined;

  public constructor(
    private readonly options: CredentialLeaseBrokerOptions,
    private readonly leases: CredentialLeaseStore,
  ) {
    if (options.controlToken.length < 16 || !options.controlToken.trim()) {
      leaseError("credential_broker_token_invalid");
    }
    if (!Number.isSafeInteger(options.bindPort) || options.bindPort < 0 || options.bindPort > 65_535) {
      leaseError("credential_broker_port_invalid");
    }
    if (!CREDENTIAL_BROKER_HOSTS.has(options.bindHost)) {
      leaseError("credential_broker_bind_host_invalid");
    }
  }

  public async start(): Promise<void> {
    if (this.server !== undefined) {
      leaseError("credential_broker_already_started");
    }
    const server = createServer((request, response) => {
      void this.handle(request, response).catch(noOp);
    });
    server.requestTimeout = 5_000;
    server.headersTimeout = 5_000;
    server.keepAliveTimeout = 1_000;
    server.on("connection", (socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        server.off("listening", onListening);
        reject(error);
      };
      const onListening = (): void => {
        server.off("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen({ host: this.options.bindHost, port: this.options.bindPort });
    });
    this.server = server;
  }

  public address(): { readonly host: string; readonly port: number } | undefined {
    const address = this.server?.address();
    if (address === null || address === undefined || typeof address === "string") {
      return undefined;
    }
    return { host: address.address, port: address.port };
  }

  public async close(): Promise<void> {
    this.leases.close();
    const server = this.server;
    this.server = undefined;
    for (const socket of this.sockets) {
      socket.destroy();
    }
    this.sockets.clear();
    if (server === undefined) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      if (!sameToken(request.headers["x-ctfmesh-runner-token"], this.options.controlToken)) {
        sendJson(response, 401, { accepted: false, code: "credential_lease_unauthorized" });
        return;
      }
      if (request.method !== "POST" || requestPath(request) !== "/internal/credential-leases") {
        sendJson(response, 404, { accepted: false, code: "credential_lease_route_not_found" });
        return;
      }
      const contentType = request.headers["content-type"];
      if (typeof contentType !== "string" || !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(contentType)) {
        sendJson(response, 415, { accepted: false, code: "credential_lease_content_type_invalid" });
        return;
      }
      const receipt = this.leases.put(parseInput(await readJsonBody(request)));
      sendJson(response, 200, { accepted: receipt.accepted, expires_at: receipt.expires_at });
    } catch (error) {
      const code = error instanceof ControlProtocolError ? error.code : "credential_lease_request_rejected";
      // Do not surface parser/SDK error strings: request bodies contain API
      // keys and Node error messages can echo malformed input.
      sendJson(response, 400, { accepted: false, code });
    }
  }
}
