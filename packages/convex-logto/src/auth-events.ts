// Opt-in phase timings for the auth bootstrap, shared by both modes.
//
// The question this answers is "how long did the user actually wait before the
// first authenticated query, and which phase regressed?". Without it the only
// view is a devtools waterfall on someone else's machine. It is deliberately
// small: phase names, a monotonic elapsed time, and the little context that
// distinguishes a fast path from a slow one. No tokens, no user identity, no
// URLs — an event is safe to forward to an analytics backend as-is.

/**
 * `bootstrap_start` is emitted once per provider mount; every other phase's
 * `elapsedMs` is measured from it.
 *
 * - `config_loaded` — bridge mode only: `configQuery` resolved, so the Logto SDK
 *   can mount. Session mode has no such fetch.
 * - `session_restored` / `unauthenticated` — the mount state machine settled.
 * - `convex_authenticated` — Convex accepted the token. This is the one that
 *   marks "the first authenticated query can run"; everything before it is
 *   setup.
 * - the `refresh_*` phases bracket a token refresh, including the silent ones
 *   that happen long after mount.
 */
export type LogtoAuthPhase =
  | "bootstrap_start"
  | "config_loaded"
  | "session_restored"
  | "unauthenticated"
  | "convex_authenticated"
  | "refresh_started"
  | "refresh_succeeded"
  | "refresh_failed"
  | "revoked"
  | "signed_out";

/** Where a restored credential came from — the difference between a fast and a slow mount. */
export type LogtoAuthEventSource =
  | "cache"
  | "refresh"
  | "callback"
  | "ssr"
  | "cross-tab";

export type LogtoAuthEvent = {
  phase: LogtoAuthPhase;
  /** Milliseconds since `bootstrap_start`, from a monotonic clock where available. */
  elapsedMs: number;
  source?: LogtoAuthEventSource;
  /** For `refresh_failed`: whether the session is gone or the attempt is retryable. */
  errorKind?: "terminal" | "transient";
};

export type LogtoAuthEventHandler = (event: LogtoAuthEvent) => void;

export type AuthEventEmitter = (
  phase: LogtoAuthPhase,
  detail?: Omit<LogtoAuthEvent, "phase" | "elapsedMs">,
) => void;

/** No handler: a no-op the engine can call unconditionally. */
export const NO_AUTH_EVENTS: AuthEventEmitter = () => {};

function monotonicNow(): number {
  return typeof performance === "undefined" ? Date.now() : performance.now();
}

/**
 * Build an emitter whose `elapsedMs` counts from the moment it is created.
 * A throwing handler is contained here: telemetry must never be able to fail an
 * authentication, so it is reported to the console and otherwise ignored.
 */
export function createAuthEventEmitter(
  handler: LogtoAuthEventHandler | undefined,
  now: () => number = monotonicNow,
): AuthEventEmitter {
  if (handler === undefined) return NO_AUTH_EVENTS;
  const start = now();
  return (phase, detail) => {
    try {
      handler({ phase, elapsedMs: now() - start, ...detail });
    } catch (error) {
      console.error("convex-logto: an onAuthEvent handler threw.", error);
    }
  };
}
