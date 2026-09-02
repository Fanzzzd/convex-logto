// Opt-in phase timings for the auth bootstrap, shared by both modes.
//
// The question this answers is "how long did the user wait before the first
// authenticated query, and which phase regressed?". Without it the only view
// is a devtools waterfall on someone else's machine. It is deliberately small:
// phase names, a monotonic elapsed time, and the little context that
// distinguishes a fast path from a slow one. No tokens, no user identity, no
// URLs. An event is safe to forward to an analytics backend as-is.

/**
 * The emitter sends `bootstrap_start` once per provider mount and measures
 * every other phase's `elapsedMs` from it.
 *
 * - `config_loaded` is bridge mode only. `configQuery` resolved, so the Logto
 *   SDK can mount. Session mode has no such fetch.
 * - `session_restored` / `unauthenticated` mean the mount state machine
 *   settled.
 * - `convex_authenticated` means Convex accepted the token. This is the one
 *   that marks "the first authenticated query can run"; everything before it
 *   is setup.
 * - The `refresh_*` phases bracket a token refresh, including the silent ones
 *   that happen long after mount. Exactly one of `refresh_succeeded`,
 *   `refresh_failed`, or `refresh_abandoned` follows every `refresh_started`,
 *   so a consumer pairing them never records a span that stays open.
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
  /**
   * A sign-out or revocation landed mid-refresh, so the engine discarded its
   * result.
   */
  | "refresh_abandoned"
  | "revoked"
  | "signed_out";

/**
 * Where a restored credential came from. The difference between a fast and a
 * slow mount.
 */
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
  /**
   * For `refresh_failed`, whether the session is gone or the attempt is
   * retryable.
   */
  errorKind?: "terminal" | "transient";
};

export type LogtoAuthEventHandler = (event: LogtoAuthEvent) => void;

/**
 * A live handler slot, shaped like a React ref on purpose, so a provider can
 * hand one straight to the engine.
 *
 * A provider cannot pass the handler itself. An inline arrow changes identity
 * every render, and rebuilding the engine mid-session would drop the auth
 * state. Reading through a slot keeps the engine stable while still honouring
 * `onAuthEvent` appearing, changing, or going away on a later render. While
 * the slot holds `undefined`, the emitter measures nothing.
 */
export type LogtoAuthEventHandlerSlot = {
  readonly current: LogtoAuthEventHandler | undefined;
};

export type LogtoAuthEventSink =
  | LogtoAuthEventHandler
  | LogtoAuthEventHandlerSlot;

export type AuthEventEmitter = (
  phase: LogtoAuthPhase,
  detail?: Omit<LogtoAuthEvent, "phase" | "elapsedMs">,
) => void;

/** No handler. A no-op the engine can call unconditionally. */
export const NO_AUTH_EVENTS: AuthEventEmitter = () => {};

function monotonicNow(): number {
  return typeof performance === "undefined" ? Date.now() : performance.now();
}

/**
 * Build an emitter whose `elapsedMs` counts from the `bootstrap_start` event,
 * not from the construction of the emitter, which can happen an arbitrary
 * React commit earlier.
 *
 * Opting out costs nothing. With no handler in the sink, an emit returns before
 * it reads the clock or allocates an event. The emitter contains a throwing
 * handler here, because telemetry must never be able to fail an
 * authentication, so it reports the error to the console and otherwise
 * ignores it.
 */
export function createAuthEventEmitter(
  sink: LogtoAuthEventSink | undefined,
  now: () => number = monotonicNow,
): AuthEventEmitter {
  if (sink === undefined) return NO_AUTH_EVENTS;
  const resolve: () => LogtoAuthEventHandler | undefined =
    typeof sink === "function" ? () => sink : () => sink.current;
  let start: number | undefined;
  return (phase, detail) => {
    const handler = resolve();
    if (handler === undefined) return;
    const at = now();
    // A handler attached after the bootstrap counts from the first event it
    // sees. That is the only baseline it can honestly have.
    if (phase === "bootstrap_start" || start === undefined) start = at;
    try {
      handler({ phase, elapsedMs: at - start, ...detail });
    } catch (error) {
      console.error("convex-logto: an onAuthEvent handler threw.", error);
    }
  };
}
