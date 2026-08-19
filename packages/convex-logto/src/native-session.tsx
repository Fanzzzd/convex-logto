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
import type { LogtoAuthEventHandler } from "./auth-events";
import { SessionAuthEngine } from "./session-client";
import { defaultSessionTransport } from "./session-transport";
import type {
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";

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
  user: Record<string, unknown> | undefined;
  /**
   * Open Logto in the system browser and complete the deep-link return in
   * place. Concurrent calls share the one in-progress native browser flow.
   * Initiation failures reach `onAuthError` before this promise rejects.
   */
  signIn: () => Promise<void>;
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
};

export function useLogtoAuth(): LogtoSessionAuth {
  const { engine } = useSessionContext("useLogtoAuth");
  const { isAuthenticated, isLoading } = useConvexAuth();
  const snapshot = useSyncExternalStore(
    engine.subscribe,
    engine.getSnapshot,
    engine.getServerSnapshot,
  );
  const signIn = useCallback(() => engine.signIn(), [engine]);
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
export type { SessionSignOutServerStatus } from "./session-client";
export { SessionSignOutError } from "./session-client";
