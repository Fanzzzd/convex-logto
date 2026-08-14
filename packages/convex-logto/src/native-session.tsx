// The `convex-logto/native-session` entry: the web session state machine with
// Expo SecureStore and system-browser adapters. It intentionally does not
// import @logto/rn; the Convex component owns every OIDC token exchange.

import * as SecureStore from "expo-secure-store";
import * as WebBrowser from "expo-web-browser";
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
  createNativeSessionAuthFlow,
  NativeSessionStorageArea,
} from "./native-session-client";
import { SessionAuthEngine, type SessionTransport } from "./session-client";
import type { LogtoSessionApi } from "./session";

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
  /** Subscribe to `sessionValid` and drop auth immediately on revocation. Default true. */
  reactiveRevocation?: boolean;
  /** Recoverable OAuth, SecureStore, and system-browser failures. */
  onAuthError?: (error: Error) => void;
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
  reactiveRevocation = true,
  onAuthError,
  children,
}: ConvexLogtoSessionProviderProps) {
  const onAuthErrorRef = useRef(onAuthError);
  useEffect(() => {
    onAuthErrorRef.current = onAuthError;
  });

  const engine = useMemo(() => {
    const storage = new NativeSessionStorageArea(
      clientNamespace(client),
      SecureStore,
    );
    return new SessionAuthEngine({
      transport: client as SessionTransport,
      api: sessionApi,
      storage,
      callbackPath: "",
      afterSignIn: "",
      authFlow: createNativeSessionAuthFlow(redirectUri, WebBrowser),
      // Native returns to the same mounted tree; callback completion has no
      // route cleanup or post-sign-in navigation to perform.
      navigate: () => {},
      onAuthError: (error) => onAuthErrorRef.current?.(error),
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

function RevocationWatcher() {
  const { engine, sessionApi } = useSessionContext("RevocationWatcher");
  const snapshot = useSyncExternalStore(
    engine.subscribe,
    engine.getSnapshot,
    engine.getServerSnapshot,
  );
  const sessionId = snapshot.sessionId;
  const hasSessionId = sessionId !== null && sessionId.length > 0;
  const valid = useQuery(
    sessionApi.sessionValid,
    hasSessionId ? { sessionId } : "skip",
  );
  useEffect(() => {
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
  return useMemo(
    () => ({
      isAuthenticated,
      isLoading,
      user: isAuthenticated ? snapshot.user : undefined,
      signIn,
      signOut,
      signOutEverywhere,
    }),
    [
      isAuthenticated,
      isLoading,
      snapshot.user,
      signIn,
      signOut,
      signOutEverywhere,
    ],
  );
}

export type { LogtoSessionApi } from "./session";
export type { SessionSignOutServerStatus } from "./session-client";
export { SessionSignOutError } from "./session-client";
