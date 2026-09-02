/**
 * Configure the one reviewed egress path used by Pi's provider SDK.
 *
 * Node's built-in ``--use-env-proxy`` dispatcher and Pi's bundled Undici can
 * be different implementations.  The latter is what Pi uses for model
 * requests, so install the matching Undici dispatcher before any session is
 * created.  This retains the Compose-only HTTP(S) proxy route and honours
 * ``NO_PROXY`` for the internal control API.
 */

import { EventEmitter } from "node:events";

import * as undici from "undici";

const PROVIDER_IDLE_TIMEOUT_MS = 300_000;
const PROVIDER_CONNECT_FAMILY_TIMEOUT_MS = 2_000;

function ignoreDispatcherError(): void {
  // The request body owns its observable failure.  This listener prevents an
  // internal dispatcher EventEmitter error from terminating the Pi process.
}

function withDispatcherErrorListener<T>(dispatcher: T): T {
  if (dispatcher instanceof EventEmitter) {
    EventEmitter.prototype.on.call(dispatcher, "error", ignoreDispatcherError);
  }
  return dispatcher;
}

function createClient(origin: string | URL, options: undici.Client.Options): undici.Client {
  return withDispatcherErrorListener(new undici.Client(origin, options));
}

function createOriginDispatcher(
  origin: string | URL,
  options: undici.Pool.Options,
): undici.Dispatcher {
  if (options.connections === 1) {
    return createClient(origin, options);
  }
  return withDispatcherErrorListener(new undici.Pool(origin, {
    ...options,
    factory: createClient,
  }));
}

/**
 * Make Pi model traffic use the same reviewed proxy-aware Undici dispatcher
 * that Pi's CLI installs.  This function never opens a connection; it only
 * installs transport policy before live sessions begin.
 */
export function configureReviewedProviderEgress(): void {
  const dispatcher = withDispatcherErrorListener(new undici.EnvHttpProxyAgent({
    allowH2: false,
    bodyTimeout: PROVIDER_IDLE_TIMEOUT_MS,
    connect: { autoSelectFamilyAttemptTimeout: PROVIDER_CONNECT_FAMILY_TIMEOUT_MS },
    headersTimeout: PROVIDER_IDLE_TIMEOUT_MS,
    clientFactory: createClient,
    factory: createOriginDispatcher,
  }));
  undici.setGlobalDispatcher(dispatcher);
  // Use this Undici's ``fetch`` with its dispatcher. This is required when
  // Pi's SDK and Node's global fetch are backed by different Undici versions.
  undici.install?.();
}
