// The `convex-logto/react-session` entry: session mode's React provider. No
// Logto SDK import — the server-side component owns all OIDC traffic, so this
// entry works without installing `@logto/react`.

import {
  ConvexProviderWithAuth,
  type ConvexReactClient,
  useConvexAuth,
  useQuery,
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
  type SessionTransport,
  type TokenStorageKind,
} from "./session-client";
import {
  createCookieSessionMarker,
  createLogtoSessionCookieTransport,
  type LogtoSessionCookieTransportOptions,
} from "./session-cookie";
import type { LogtoSessionApi } from "./session";

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
   * `signOut` / `sessionValid`.
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
   * sessionStorage — an unexpired token makes reload a zero-round-trip
   * authenticate. `"memory"`: strictest, every reload refreshes. `"local"`:
   * shared across tabs and restarts. By default the one-time session token
   * lives in localStorage; `cookieTransport` moves it into an HttpOnly cookie.
   */
  tokenStorage?: TokenStorageKind;
  /**
   * Move the rotating session token into the same-site handler's HttpOnly
   * cookie. The browser keeps only a non-secret session marker in localStorage.
   */
  cookieTransport?: LogtoSessionCookieTransportOptions;
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
   * Called when finishing a sign-in fails recoverably (a stale/replayed/forged
   * callback, Logto unreachable). The user is returned to the app logged out
   * either way; use this to toast/telemetry the failure. Errors are also logged
   * to the console.
   */
  onAuthError?: (error: Error) => void;
  children: ReactNode;
};

/**
 * Session mode: Convex holds the Logto refresh token server-side (Traditional
 * Web app); the browser holds only a short-lived ID token and a one-time
 * rotating session token. Requires the session component
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
  cookieTransport,
  initialToken,
  initialSessionId,
  reactiveRevocation = true,
  onAuthError,
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
  // so the engine stays stable and still always calls the latest one.
  const navigateRef = useRef(navigate);
  const onAuthErrorRef = useRef(onAuthError);
  useEffect(() => {
    navigateRef.current = navigate;
    onAuthErrorRef.current = onAuthError;
  });

  const engine = useMemo(() => {
    // Namespace storage by deployment so two dev apps on the same origin
    // (localhost) don't cross-read each other's sessions.
    const namespace = clientNamespace(client);
    const storage = new SessionStorageArea(namespace, tokenStorage);
    const transport = usesCookieTransport
      ? createLogtoSessionCookieTransport(sessionApi, {
          endpoint: cookieEndpoint,
          fetch: cookieFetch,
          deviceBinding: cookieDeviceBinding,
        })
      : (client as SessionTransport);
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
      navigate: (to) => {
        const soft = navigateRef.current;
        if (soft) soft(to);
        else window.location.replace(to);
      },
      onAuthError: (error) => onAuthErrorRef.current?.(error),
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
  const valid = useQuery(
    sessionApi.sessionValid,
    sessionId !== null ? { sessionId } : "skip",
  );
  useEffect(() => {
    if (sessionId !== null && valid === false) engine.handleRevoked();
  }, [engine, sessionId, valid]);
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
   * sign-in completes; it overrides the provider's `afterSignIn`.
   */
  signIn: (options?: { returnTo?: string }) => Promise<void>;
  /**
   * Sign out: kills the session server-side (revoking Logto's grant), clears
   * this browser's storage (other tabs follow via the storage event), then —
   * unless `federated: false` — ends Logto's SSO session and returns to
   * `postLogoutRedirectUri` (default `window.location.origin`, which you must
   * register as a **Post sign-out redirect URI**).
   */
  signOut: (options?: {
    postLogoutRedirectUri?: string;
    federated?: boolean;
  }) => Promise<void>;
};

/**
 * Auth state and actions from one import. `isAuthenticated` / `isLoading` come
 * from Convex, so they're true only once Convex has accepted the token.
 *
 * @example
 * const { isAuthenticated, user, signIn, signOut } = useLogtoAuth();
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
  return useMemo(
    () => ({
      isAuthenticated,
      isLoading,
      user: isAuthenticated ? snapshot.user : undefined,
      signIn,
      signOut,
    }),
    [isAuthenticated, isLoading, snapshot.user, signIn, signOut],
  );
}

export type { LogtoSessionApi } from "./session";
export type { TokenStorageKind } from "./session-client";
export type { LogtoSessionCookieTransportOptions } from "./session-cookie";
