// The transport session actions travel over.
//
// It must NOT be the app's `ConvexReactClient`. Convex stops the WebSocket
// *before* asking for a fresh token:
//
//   await this.stopSocket();
//   const token = await this.fetchTokenAndGuardAgainstRace(fetchToken, {
//     forceRefreshToken: true,
//   });
//   ...
//   this.tryRestartSocket();
//
// (convex/browser/sync/authentication_manager.js, `tryToReauthenticate`.)
//
// Our `fetchAccessToken` answers that call by running the `refresh` action. On
// a stopped socket `sendMessage` returns false and the action parks as
// `"NotSent"` in a promise that never settles, so nothing ever reaches
// `tryRestartSocket()`, and it is the only caller of `tryRestart()`. The app
// wedges until a reload: queries stop updating, mutations queue silently, and
// every later refresh merges into the dead promise. A backgrounded tab or a
// suspended native app reaches that path routinely.
//
// Session actions carry their own credential in their arguments and never use
// Convex auth, so a plain HTTP client is all they need.

import { ConvexHttpClient } from "convex/browser";
import type { ConvexReactClient } from "convex/react";
import type { SessionTransport } from "./session-client";

/**
 * A session transport that reaches the deployment over HTTP, independent of the
 * app's WebSocket.
 *
 * The URL already passed `ConvexReactClient`'s own validation, so revalidating
 * it here could only reject a deployment the app is otherwise talking to
 * happily (a proxied origin, a self-hosted backend).
 */
export function createDeploymentSessionTransport(
  url: string,
): SessionTransport {
  const client = new ConvexHttpClient(url, {
    skipConvexDeploymentUrlCheck: true,
    // `ConvexHttpClient` calls `fetch` with no signal of its own. A request
    // that never answers would park `inflightRefresh` forever, since every
    // later token fetch merges into that promise and the recovery loop waits on
    // it. That is the same wedge this module exists to avoid, moved from a
    // stopped socket to a stalled request.
    fetch: timeoutFetch,
  });
  return {
    // Belt and braces. `fetch` is a newer constructor option than this
    // package's `convex` floor, so an older client would ignore it. The race
    // settles the caller either way.
    action: (reference, args) => withDeadline(client.action(reference, args)),
  };
}

/** Same ceiling the cookie transport applies to its own routes. */
const SESSION_ACTION_TIMEOUT_MS = 10 * 1000;

function timeoutError(): Error {
  return new Error("convex-logto: the session request timed out.");
}

const timeoutFetch: typeof globalThis.fetch = (input, init) => {
  const controller = new AbortController();
  const error = timeoutError();
  const timer = setTimeout(
    () => controller.abort(error),
    SESSION_ACTION_TIMEOUT_MS,
  );
  return globalThis
    .fetch(input, { ...init, signal: controller.signal })
    .finally(() => clearTimeout(timer));
};

async function withDeadline<T>(operation: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(timeoutError()), SESSION_ACTION_TIMEOUT_MS);
  });
  try {
    return await Promise.race([operation, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * The default transport for a provider. HTTP when the client exposes its URL,
 * otherwise the client itself.
 *
 * `ConvexReactClient.url` exists on every version this package supports; the
 * fallback only keeps a client-shaped stub working rather than throwing at
 * mount.
 */
export function defaultSessionTransport(
  client: ConvexReactClient,
): SessionTransport {
  const url = (client as { url?: unknown }).url;
  return typeof url === "string" && url !== ""
    ? createDeploymentSessionTransport(url)
    : client;
}
