// The `convex-logto/native-session` entry: the web session state machine with
// Expo SecureStore and system-browser adapters. It intentionally does not
// import @logto/rn; the Convex component owns every OIDC token exchange.

import * as SecureStore from "expo-secure-store";
import * as WebBrowser from "expo-web-browser";
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
  createNativeSessionAuthFlow,
  NativeSessionStorageArea,
} from "./native-session-client";
import type { LogtoUserClaims } from "./claims";
import type { LogtoAuthEventHandler } from "./auth-events";
import { SessionAuthEngine } from "./session-client";
import { defaultSessionTransport } from "./session-transport";
import type {
  LogtoResourceTokenClaims,
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";

const SessionContext = createContext<{
  engine: SessionAuthEngine;
  sessionApi: LogtoSessionApi;
  redirectUri: string;
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
  /** The module re-exporting `logtoSessionApi(...)`, e.g. `api.auth`. */
  sessionApi: LogtoSessionApi;
  /** Custom-scheme/universal-link callback registered in Logto. */
  redirectUri: string;
  /**
   * Self-reported description of this device ("ios", "iPhone 15", ...), stamped
   * on the session at sign-in so `listSessions()` can show the user something
   * recognisable. Advisory display data, never authenticated. Safe to pass as an
   * inline object: only the three field values affect the engine.
   */
  clientDescriptor?: LogtoSessionClientDescriptor;
  /** Subscribe to `sessionValid` and drop auth immediately on revocation. Default true. */
  reactiveRevocation?: boolean;
  /** Sign-in initiation plus recoverable OAuth, SecureStore, and system-browser failures. */
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
 * Session mode for React Native / Expo. The rotating session token, short-lived
 * ID token, and single-use OAuth state are all encrypted by SecureStore. Sign-in
 * and federated sign-out use expo-web-browser; there is no callback route.
 *
 * Device binding is intentionally absent: native credential persistence is
 * already bound to the OS keystore, and this surface never exposes that option.
 */
export function ConvexLogtoSessionProvider({
  client,
  sessionApi,
  redirectUri,
  clientDescriptor,
  reactiveRevocation = true,
  onAuthError,
  onAuthEvent,
  children,
}: ConvexLogtoSessionProviderProps) {
  // Refs, not `useMemo` dependencies: apps usually learn the device description
  // asynchronously, and rebuilding the engine to deliver it would restart the
  // mount state machine mid-sign-in.
  const onAuthErrorRef = useRef(onAuthError);
  const clientDescriptorRef = useRef(clientDescriptor);
  const onAuthEventRef = useRef(onAuthEvent);
  useEffect(() => {
    onAuthErrorRef.current = onAuthError;
    clientDescriptorRef.current = clientDescriptor;
  });
  // Assigned during render, not in an effect: child effects run before the
  // parent's, so the `convex_authenticated` watcher below would emit into a
  // ref that still held the previous render's handler.
  onAuthEventRef.current = onAuthEvent;

  const engine = useMemo(() => {
    const storage = new NativeSessionStorageArea(
      clientNamespace(client),
      SecureStore,
    );
    return new SessionAuthEngine({
      transport: defaultSessionTransport(client),
      api: sessionApi,
      storage,
      callbackPath: "",
      afterSignIn: "",
      authFlow: createNativeSessionAuthFlow(redirectUri, WebBrowser),
      clientDescriptor: () => clientDescriptorRef.current,
      // Native returns to the same mounted tree; callback completion has no
      // route cleanup or post-sign-in navigation to perform.
      navigate: () => {},
      onAuthError: (error) => onAuthErrorRef.current?.(error),
      // Always wired, always through the ref: making this conditional would put
      // the handler's presence in the memo's dependencies, and an app that
      // enables telemetry from an effect would rebuild the engine mid-mount.
      // The cost when no handler is set is one ref read per phase.
      onAuthEvent: onAuthEventRef,
    });
  }, [client, sessionApi, redirectUri]);

  useEffect(() => {
    engine.start();
  }, [engine]);

  const contextValue = useMemo(
    () => ({ engine, sessionApi, redirectUri }),
    [engine, sessionApi, redirectUri],
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
  const url = (client as { url?: unknown }).url;
  return typeof url === "string" ? url : "";
}

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
  // Keyed by engine, not a bare boolean: a replaced engine emits its own
  // `bootstrap_start`, and a `reported` that survived it would leave that span
  // open forever.
  const reportedFor = useRef<SessionAuthEngine | null>(null);
  useEffect(() => {
    if (!isAuthenticated || reportedFor.current === engine) return;
    reportedFor.current = engine;
    engine.reportConvexAuthenticated();
  }, [engine, isAuthenticated]);
  return null;
}

/**
 * Reactive revocation: subscribe to the session's liveness; the moment the
 * server deletes the session row (sign-out elsewhere, reuse detection, a
 * webhook revocation), Convex pushes `false`, SecureStore is cleared, and auth
 * drops in real time.
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
  /** Decoded ID token claims, for display only. */
  user: LogtoUserClaims | undefined;
  /**
   * Open Logto in the system browser and complete the deep-link return in
   * place. Concurrent calls share the one in-progress native browser flow.
   * Initiation failures reach `onAuthError` before this promise rejects.
   */
  signIn: () => Promise<void>;
  /**
   * Finish a sign-in whose deep link came back outside the system-browser
   * promise — the OS reclaimed the app while Logto had it, so the app
   * cold-started on the redirect instead of resuming.
   *
   * Web needs no equivalent: the callback lives in the URL and the provider
   * re-reads it on the next mount. Native's flow otherwise lives entirely in one
   * in-memory promise, so without this the user returns signed in at Logto and
   * signed out in the app, with no error.
   *
   * Wire it to both Expo `Linking` entry points and pass the URL through
   * unchanged; anything that is not this app's `redirectUri` is ignored:
   *
   * ```tsx
   * useEffect(() => {
   *   void Linking.getInitialURL().then((url) => url && completeSignIn(url));
   *   const sub = Linking.addEventListener("url", ({ url }) => {
   *     void completeSignIn(url);
   *   });
   *   return () => sub.remove();
   * }, [completeSignIn]);
   * ```
   *
   * Safe to call with any link: one that is not this app's `redirectUri`, or
   * that carries no OIDC response, is ignored without disturbing a sign-in in
   * progress, and a duplicate delivery of the same URL waits for the first.
   *
   * A user who cancelled in the browser is not recoverable this way, by design:
   * cancelling discards the OIDC state so a later deep link cannot replay it.
   */
  completeSignIn: (url: string) => Promise<void>;
  /**
   * Revoke the session, clear SecureStore, and end browser SSO by default.
   * Rejects with `SessionSignOutError` when durable cleanup fails twice; its
   * `serverSessionStatus` distinguishes a successful revocation from a dual failure.
   */
  signOut: (options?: {
    postLogoutRedirectUri?: string;
    federated?: boolean;
  }) => Promise<void>;
  /**
   * Delete every component session for the current subject, then end this
   * device's Logto browser SSO session.
   */
  signOutEverywhere: (options?: {
    postLogoutRedirectUri?: string;
  }) => Promise<void>;
  /**
   * The caller's own sessions, for a "where am I signed in" screen. A snapshot,
   * not a subscription — the session token it authenticates with rotates — so
   * call it again after `renameSession` / `revokeSession`.
   */
  listSessions: () => Promise<{
    sessions: LogtoSessionSummary[];
    truncated: boolean;
  }>;
  /**
   * Name one of the caller's own sessions (`undefined` clears it). Rejects with
   * a terminal `session_not_found` for an id that is not the caller's.
   */
  renameSession: (
    targetSessionId: string,
    label: string | undefined,
  ) => Promise<void>;
  /**
   * Revoke one of the caller's own sessions, rejecting like `renameSession` for
   * an unknown id. Revoking the current one does not clear this device's
   * credentials — call `signOut` for that.
   */
  revokeSession: (targetSessionId: string) => Promise<void>;
  /**
   * The current ID token — the Short bearer Convex validates. `null` when
   * signed out, when the stored one has aged out, or while the engine is still
   * restoring — so read it under `isAuthenticated`, which is false until the
   * restore finishes.
   */
  getIdToken: () => string | null;
  /**
   * What an Organization token authorizes, without the token itself.
   *
   * Membership and organization *roles* need none of this: Logto puts them in
   * the ID token, so `user.organizations` and `user.organization_roles` are
   * already here for free. This is for fine-grained organization
   * **permissions**, which Logto issues nowhere but an Organization token.
   */
  getOrganizationTokenClaims: (
    organizationId: string,
    scopes?: string[],
  ) => Promise<LogtoResourceTokenClaims>;
  /**
   * What a Resource token authorizes. The resource must be listed in
   * `resources` on `logtoSessionApi()` — Logto will not issue a token for a
   * resource the grant never named.
   */
  getAccessTokenClaims: (
    resource: string,
    scopes?: string[],
  ) => Promise<LogtoResourceTokenClaims>;
  /**
   * The Organization token *string*, for a caller that must reach a non-Convex
   * API from the browser. Rejects unless the deployment passed
   * `exposeAccessTokens: true`.
   */
  getOrganizationToken: (
    organizationId: string,
    scopes?: string[],
  ) => Promise<string>;
  /** The Resource token *string*, under the same `exposeAccessTokens` gate. */
  getAccessToken: (resource: string, scopes?: string[]) => Promise<string>;
  /**
   * Logto's live profile (`/oidc/me`), fetched by the component. A round trip,
   * unlike `user`, which is the copy the last ID token froze.
   */
  fetchUserInfo: () => Promise<unknown>;
};

export function useLogtoAuth(): LogtoSessionAuth {
  const { engine, redirectUri } = useSessionContext("useLogtoAuth");
  const { isAuthenticated, isLoading } = useConvexAuth();
  const snapshot = useSyncExternalStore(
    engine.subscribe,
    engine.getSnapshot,
    engine.getServerSnapshot,
  );
  const signIn = useCallback(() => engine.signIn(), [engine]);
  const completeSignIn = useCallback(
    async (url: string) => {
      // Apps hand over every deep link they receive, most of which are their
      // own routes. Only this flow's redirect can carry an OIDC response.
      if (!url.startsWith(redirectUri)) return;
      await engine.completeSignIn(url, redirectUri);
    },
    [engine, redirectUri],
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
  const getIdToken = useCallback(() => engine.getIdToken(), [engine]);
  const getOrganizationTokenClaims = useCallback(
    (organizationId: string, scopes?: string[]) =>
      engine.getOrganizationTokenClaims(organizationId, scopes),
    [engine],
  );
  const getAccessTokenClaims = useCallback(
    (resource: string, scopes?: string[]) =>
      engine.getAccessTokenClaims(resource, scopes),
    [engine],
  );
  const getOrganizationToken = useCallback(
    (organizationId: string, scopes?: string[]) =>
      engine.getOrganizationToken(organizationId, scopes),
    [engine],
  );
  const getAccessToken = useCallback(
    (resource: string, scopes?: string[]) =>
      engine.getAccessToken(resource, scopes),
    [engine],
  );
  const fetchUserInfo = useCallback(() => engine.fetchUserInfo(), [engine]);
  return useMemo(
    () => ({
      isAuthenticated,
      isLoading,
      user: isAuthenticated ? snapshot.user : undefined,
      signIn,
      completeSignIn,
      signOut,
      signOutEverywhere,
      listSessions,
      renameSession,
      revokeSession,
      getIdToken,
      getOrganizationTokenClaims,
      getAccessTokenClaims,
      getOrganizationToken,
      getAccessToken,
      fetchUserInfo,
    }),
    [
      isAuthenticated,
      isLoading,
      snapshot.user,
      signIn,
      completeSignIn,
      signOut,
      signOutEverywhere,
      listSessions,
      renameSession,
      revokeSession,
      getIdToken,
      getOrganizationTokenClaims,
      getAccessTokenClaims,
      getOrganizationToken,
      getAccessToken,
      fetchUserInfo,
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
  LogtoResourceTokenClaims,
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";
export type { SessionSignOutServerStatus } from "./session-client";
export { SessionSignOutError } from "./session-client";
