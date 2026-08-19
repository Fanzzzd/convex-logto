// The `convex-logto/react-session` entry: session mode's React provider. No
// Logto SDK import — the server-side component owns all OIDC traffic, so this
// entry works without installing `@logto/react`.

import {
  ConvexProviderWithAuth,
  type ConvexReactClient,
  useConvexAuth,
  useQueries,
  type RequestForQueries,
} from "convex/react";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useSyncExternalStore,
} from "react";
import {
  SessionAuthEngine,
  SessionStorageArea,
  type TokenStorageKind,
} from "./session-client";
import { defaultSessionTransport } from "./session-transport";
import type { LogtoAuthEventHandler } from "./auth-events";
import { createSessionDeviceBinding } from "./session-device";
import {
  createCookieSessionMarker,
  createLogtoSessionCookieTransport,
  type LogtoSessionCookieTransportOptions,
} from "./session-cookie";
import type {
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";

const DEFAULT_CALLBACK_PATH = "/callback";

const SessionContext = createContext<{
  engine: SessionAuthEngine;
  sessionApi: LogtoSessionApi;
} | null>(null);

function useSessionContext(caller: string) {
  const context = useContext(SessionContext);
  if (context === null) {
    throw new Error(
      `convex-logto: ${caller} must be used inside <ConvexLogtoSessionProvider>.`,
    );
  }
  return context;
}

export type ConvexLogtoSessionProviderProps = {
  /** Your `ConvexReactClient`. */
  client: ConvexReactClient;
  /**
   * The module re-exporting `logtoSessionApi(...)`'s functions, e.g. `api.auth`.
   * The provider expects the exact names `signIn` / `callback` / `refresh` /
   * `signOut` / `signOutEverywhere` / `listSessions` / `renameSession` /
   * `revokeSession` / `sessionValid`. Everything after `signOut` is
   * feature-detected: omitting one disables that call with a message naming
   * the export to add, so a rolling upgrade never breaks sign-in.
   */
  sessionApi: LogtoSessionApi;
  /**
   * The route that finishes the OIDC redirect. Default `/callback`. Must match
   * the path of a **Redirect URI** registered on the Logto Traditional Web app;
   * only that exact path runs callback handling.
   */
  callbackPath?: string;
  /** Where to go once sign-in completes. Default `/`. `signIn({ returnTo })` overrides it. */
  afterSignIn?: string;
  /**
   * Soft navigation (e.g. your router's navigate). Prefer a replace-style
   * navigate so the spent callback URL doesn't stay in history. Falls back to a
   * hard `location.replace`.
   */
  navigate?: (to: string) => void;
  /**
   * Where the short-lived ID token persists. `"session"` (default): per-tab
   * sessionStorage — an unexpired token can restore without refresh while its
   * paired component-session marker remains. `"memory"`: strictest, every
   * reload refreshes. `"local"`: shared across tabs and restarts. By default
   * the rotating session token lives in localStorage; `cookieTransport` moves
   * it into an HttpOnly cookie.
   */
  tokenStorage?: TokenStorageKind;
  /**
   * Bind refresh and revocation operations to a non-extractable ECDSA key
   * persisted in IndexedDB. Default `false`. Cannot be combined with
   * `cookieTransport`.
   */
  deviceBinding?: boolean;
  /**
   * Move the rotating session token into the same-site handler's HttpOnly
   * cookie. The browser keeps only a non-secret session marker in localStorage;
   * each rotation renews the persistent cookie's 190-day idle lifetime.
   */
  cookieTransport?: LogtoSessionCookieTransportOptions;
  /**
   * Self-reported description of this client ("Chrome", "macOS", ...), stamped
   * on the session at sign-in so `listSessions()` can show the user something
   * recognisable. The app supplies it — the library never sniffs a User-Agent or
   * IP — and it is advisory display data, never authenticated. Safe to pass as
   * an inline object: only the three field values affect the engine.
   */
  clientDescriptor?: LogtoSessionClientDescriptor;
  /** Fresh ID token returned by `handler.getInitialToken(request)` during SSR. */
  initialToken?: string | null;
  /** Stable session id returned alongside `initialToken`. */
  initialSessionId?: string | null;
  /**
   * Subscribe to server-side session liveness and drop auth the moment the
   * session is revoked (sign-out elsewhere, reuse detection, webhook
   * revocation). Default `true`.
   */
  reactiveRevocation?: boolean;
  /**
   * Called when starting or finishing sign-in fails recoverably (a failed
   * action, stale/replayed/forged callback, or Logto unreachable), or opted-in
   * device-key storage fails. This makes `void signIn()` safe for event
   * handlers; errors are also logged to the console.
   */
  onAuthError?: (error: Error) => void;
  /**
   * Opt-in phase timings for the auth bootstrap — `bootstrap_start` through
   * `convex_authenticated`, plus refresh, revocation and sign-out. Absent means
   * nothing is measured or emitted. See [`LogtoAuthEvent`](./auth-events).
   */
  onAuthEvent?: LogtoAuthEventHandler;
  children: ReactNode;
};

/**
 * Session mode: Convex holds the Logto refresh token server-side (Traditional
 * Web app); the browser holds only a short-lived ID token and a rotating
 * application session token. Requires the session component
 * (`app.use(logto)` in `convex/convex.config.ts`) and `logtoSessionApi(...)`
 * re-exported from your Convex functions.
 *
 * @example
 * <ConvexLogtoSessionProvider client={convex} sessionApi={api.auth}>
 *   <App />
 * </ConvexLogtoSessionProvider>
 */
export function ConvexLogtoSessionProvider({
  client,
  sessionApi,
  callbackPath = DEFAULT_CALLBACK_PATH,
  afterSignIn = "/",
  navigate,
  tokenStorage = "session",
  deviceBinding = false,
  cookieTransport,
  clientDescriptor,
  initialToken,
  initialSessionId,
  reactiveRevocation = true,
  onAuthError,
  onAuthEvent,
  children,
}: ConvexLogtoSessionProviderProps) {
  const usesCookieTransport = cookieTransport !== undefined;
  const hasInitialToken = initialToken != null;
  const hasInitialSessionId = initialSessionId != null;
  if (hasInitialToken !== hasInitialSessionId) {
    throw new Error(
      "convex-logto: initialToken and initialSessionId must be provided together.",
    );
  }
  if (hasInitialToken && !usesCookieTransport) {
    throw new Error(
      "convex-logto: SSR initialToken seeding requires cookieTransport.",
    );
  }

  const cookieEndpoint = cookieTransport?.endpoint;
  const cookieFetch = cookieTransport?.fetch;
  const cookieDeviceBinding = cookieTransport?.deviceBinding;

  // The engine must survive re-renders, but `navigate`/`onAuthError` are often
  // inline arrows with a fresh identity each render — route them through refs
  // so the engine stays stable and still always calls the latest one. The
  // client descriptor rides along for a stronger reason: apps usually learn it
  // asynchronously, and rebuilding the engine to deliver it would restart the
  // mount state machine — abandoning an in-flight callback exchange and leaving
  // the tree signed out with a live session on the server.
  const navigateRef = useRef(navigate);
  const onAuthErrorRef = useRef(onAuthError);
  const clientDescriptorRef = useRef(clientDescriptor);
  const onAuthEventRef = useRef(onAuthEvent);
  useEffect(() => {
    navigateRef.current = navigate;
    onAuthErrorRef.current = onAuthError;
    clientDescriptorRef.current = clientDescriptor;
  });
  // Assigned during render, not in an effect: child effects run before the
  // parent's, so the `convex_authenticated` watcher below would emit into a
  // ref that still held the previous render's handler.
  onAuthEventRef.current = onAuthEvent;

  const engine = useMemo(() => {
    // Namespace storage by deployment so two dev apps on the same origin
    // (localhost) don't cross-read each other's sessions.
    const namespace = clientNamespace(client);
    const storage = new SessionStorageArea(namespace, tokenStorage);
    const transport = usesCookieTransport
      ? createLogtoSessionCookieTransport(sessionApi, {
          endpoint: cookieEndpoint,
          fetch: cookieFetch,
          deviceBinding: deviceBinding || cookieDeviceBinding,
        })
      : defaultSessionTransport(client);
    return new SessionAuthEngine({
      transport,
      api: sessionApi,
      storage,
      callbackPath,
      afterSignIn,
      initialToken: initialToken ?? undefined,
      // Cookie mode always writes a non-secret marker. That both overwrites a
      // legacy localStorage credential and makes reload attempt the /token
      // route even though JavaScript cannot inspect the HttpOnly cookie.
      initialSession: usesCookieTransport
        ? createCookieSessionMarker(storage.readSession(), initialSessionId)
        : undefined,
      // The credential is an HttpOnly cookie only the server can expire, so a
      // failed revoke is a failed sign-out — not something to swallow.
      serverHeldCredential: usesCookieTransport,
      deviceBinding: deviceBinding
        ? createSessionDeviceBinding(namespace)
        : undefined,
      clientDescriptor: () => clientDescriptorRef.current,
      navigate: (to) => {
        const soft = navigateRef.current;
        if (soft) soft(to);
        else window.location.replace(to);
      },
      onAuthError: (error) => onAuthErrorRef.current?.(error),
      // Always wired, always through the ref: making this conditional would put
      // the handler's presence in the memo's dependencies, and an app that
      // enables telemetry from an effect would rebuild the engine mid-mount.
      // The cost when no handler is set is one ref read per phase.
      onAuthEvent: onAuthEventRef,
    });
  }, [
    client,
    sessionApi,
    callbackPath,
    tokenStorage,
    afterSignIn,
    usesCookieTransport,
    cookieEndpoint,
    cookieFetch,
    cookieDeviceBinding,
    deviceBinding,
    initialToken,
    initialSessionId,
  ]);

  useEffect(() => {
    engine.start();
    const onStorage = (event: StorageEvent) => {
      // Another tab signed out: its localStorage removal lands here.
      if (event.key === engine.sessionEventKey && event.newValue === null) {
        engine.handleExternalSignOut();
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [engine]);

  const contextValue = useMemo(
    () => ({ engine, sessionApi }),
    [engine, sessionApi],
  );

  return (
    <SessionContext.Provider value={contextValue}>
      <ConvexProviderWithAuth client={client} useAuth={useAuthFromSession}>
        {reactiveRevocation ? <RevocationWatcher /> : null}
        <ConvexAuthPhaseWatcher engine={engine} />
        {children}
      </ConvexProviderWithAuth>
    </SessionContext.Provider>
  );
}

function clientNamespace(client: ConvexReactClient): string {
  // `ConvexReactClient.url` exists on every version this package supports, but
  // stay defensive: an empty namespace only costs cross-app isolation on the
  // same origin.
  const url = (client as { url?: unknown }).url;
  return typeof url === "string" ? url : "";
}

/** Bridges the session engine into the `useAuth` shape `ConvexProviderWithAuth` expects. */
function useAuthFromSession() {
  const { engine } = useSessionContext(
    "ConvexLogtoSessionProvider's auth bridge",
  );
  const snapshot = useSyncExternalStore(
    engine.subscribe,
    engine.getSnapshot,
    engine.getServerSnapshot,
  );
  const fetchAccessToken = useCallback(
    ({ forceRefreshToken }: { forceRefreshToken: boolean }) =>
      engine.fetchAccessToken(forceRefreshToken),
    [engine],
  );
  return useMemo(
    () => ({
      isLoading: snapshot.status === "restoring",
      isAuthenticated: snapshot.status === "authenticated",
      fetchAccessToken,
    }),
    [snapshot, fetchAccessToken],
  );
}

/**
 * `convex_authenticated` is the phase an app actually cares about — the first
 * moment an authenticated query can run — and only Convex knows when it
 * happens. Always mounted: whether anything is measured is decided per event by
 * the handler slot, so an `onAuthEvent` passed on a later render still works.
 */
function ConvexAuthPhaseWatcher({ engine }: { engine: SessionAuthEngine }) {
  const { isAuthenticated } = useConvexAuth();
  const reported = useRef(false);
  useEffect(() => {
    if (!isAuthenticated || reported.current) return;
    reported.current = true;
    engine.reportConvexAuthenticated();
  }, [engine, isAuthenticated]);
  return null;
}

/**
 * Reactive revocation: subscribe to the session's liveness; the moment the
 * server deletes the session row (sign-out elsewhere, reuse detection, a
 * webhook revocation), Convex pushes `false` and auth drops in real time.
 */
function RevocationWatcher() {
  const { engine, sessionApi } = useSessionContext("RevocationWatcher");
  const snapshot = useSyncExternalStore(
    engine.subscribe,
    engine.getSnapshot,
    engine.getServerSnapshot,
  );
  const sessionId = snapshot.sessionId;
  const hasSessionId = sessionId !== null && sessionId.length > 0;
  // `useQueries`, not `useQuery`, because `useQuery` rethrows a query error
  // during render and this component is a sibling of `{children}` — above every
  // error boundary the app can install. A frontend deployed ahead of its Convex
  // functions would otherwise blank the page for every signed-in user instead of
  // merely losing reactive revocation. Here the error arrives as a value.
  const queries = useMemo(() => {
    const request: RequestForQueries = {};
    if (hasSessionId) {
      request.valid = { query: sessionApi.sessionValid, args: { sessionId } };
    }
    return request;
  }, [hasSessionId, sessionApi, sessionId]);
  const valid: unknown = useQueries(queries).valid;
  useEffect(() => {
    if (valid instanceof Error) {
      engine.reportWatchFailure(
        new Error(
          "convex-logto: reactive revocation is off — the sessionValid query failed. " +
            "Sessions still expire on their own schedule.",
          { cause: valid },
        ),
      );
      return;
    }
    if (hasSessionId && valid === false) engine.handleRevoked();
  }, [engine, hasSessionId, valid]);
  return null;
}

export type LogtoSessionAuth = {
  isAuthenticated: boolean;
  isLoading: boolean;
  /** Decoded ID token claims (sub, email, name, ...), once authenticated. Display only. */
  user: Record<string, unknown> | undefined;
  /**
   * Start sign-in: one round-trip to mint the sign-in URL, then a full-page
   * redirect to Logto and back to the provider's `callbackPath`. `returnTo`
   * (a same-origin path starting with `/`) is where the user lands after
   * sign-in completes; it overrides the provider's `afterSignIn`. Initiation
   * failures reach `onAuthError` before this promise rejects.
   */
  signIn: (options?: { returnTo?: string }) => Promise<void>;
  /**
   * Sign out: deletes the component Session and its server-held refresh token,
   * clears this browser's storage (other tabs follow via the storage event), then —
   * unless `federated: false` — ends Logto's SSO session and returns to
   * `postLogoutRedirectUri` (default `window.location.origin`, which you must
   * register as a **Post sign-out redirect URI**).
   */
  signOut: (options?: {
    postLogoutRedirectUri?: string;
    federated?: boolean;
  }) => Promise<void>;
  /**
   * Delete every component session for the current subject, then end this
   * browser's Logto SSO session. Other live devices drop through the existing
   * reactive revocation subscription.
   */
  signOutEverywhere: (options?: {
    postLogoutRedirectUri?: string;
  }) => Promise<void>;
  /**
   * The caller's own sessions, for a "where am I signed in" screen. A snapshot,
   * not a subscription — the session token it authenticates with rotates — so
   * call it again after `renameSession` / `revokeSession`. `truncated` means the
   * subject has more sessions than the page returned.
   */
  listSessions: () => Promise<{
    sessions: LogtoSessionSummary[];
    truncated: boolean;
  }>;
  /**
   * Name one of the caller's own sessions (pass `undefined` to clear it).
   * Rejects with a terminal `session_not_found` when the id is not the caller's
   * or is already revoked — the component refuses to confirm that another
   * subject's session exists.
   */
  renameSession: (
    targetSessionId: string,
    label: string | undefined,
  ) => Promise<void>;
  /**
   * Revoke one of the caller's own sessions; that device drops on its next
   * reactive revocation tick, and an unknown id rejects like `renameSession`.
   * Revoking the current session does not clear this browser's credentials —
   * call `signOut` for that, and note that a device which still holds a live
   * Logto SSO cookie can start a new sign-in.
   */
  revokeSession: (targetSessionId: string) => Promise<void>;
};

/**
 * Auth state and actions from one import. `isAuthenticated` / `isLoading` come
 * from Convex, so they're true only once Convex has accepted the token.
 *
 * @example
 * const { isAuthenticated, user, signIn, signOut, signOutEverywhere } =
 *   useLogtoAuth();
 */
export function useLogtoAuth(): LogtoSessionAuth {
  const { engine } = useSessionContext("useLogtoAuth");
  const { isAuthenticated, isLoading } = useConvexAuth();
  const snapshot = useSyncExternalStore(
    engine.subscribe,
    engine.getSnapshot,
    engine.getServerSnapshot,
  );
  const signIn = useCallback(
    (options?: { returnTo?: string }) => engine.signIn(options),
    [engine],
  );
  const signOut = useCallback(
    (options?: { postLogoutRedirectUri?: string; federated?: boolean }) =>
      engine.signOut(options),
    [engine],
  );
  const signOutEverywhere = useCallback(
    (options?: { postLogoutRedirectUri?: string }) =>
      engine.signOutEverywhere(options),
    [engine],
  );
  const listSessions = useCallback(() => engine.listSessions(), [engine]);
  const renameSession = useCallback(
    (targetSessionId: string, label: string | undefined) =>
      engine.renameSession(targetSessionId, label),
    [engine],
  );
  const revokeSession = useCallback(
    (targetSessionId: string) => engine.revokeSession(targetSessionId),
    [engine],
  );
  return useMemo(
    () => ({
      isAuthenticated,
      isLoading,
      user: isAuthenticated ? snapshot.user : undefined,
      signIn,
      signOut,
      signOutEverywhere,
      listSessions,
      renameSession,
      revokeSession,
    }),
    [
      isAuthenticated,
      isLoading,
      snapshot.user,
      signIn,
      signOut,
      signOutEverywhere,
      listSessions,
      renameSession,
      revokeSession,
    ],
  );
}

export type {
  LogtoAuthEvent,
  LogtoAuthEventHandler,
  LogtoAuthEventSource,
  LogtoAuthPhase,
} from "./auth-events";
export type {
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";
export type { TokenStorageKind } from "./session-client";
export type { LogtoSessionCookieTransportOptions } from "./session-cookie";
