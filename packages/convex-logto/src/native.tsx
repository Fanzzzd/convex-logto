import {
  type IdTokenClaims,
  type LogtoConfig,
  LogtoProvider,
  UserScope,
  useLogto,
} from "@logto/rn";
import {
  ConvexProviderWithAuth,
  type ConvexReactClient,
  useConvexAuth,
} from "convex/react";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { LogtoConfigQueryRef, LogtoPublicConfig } from "./config";

/**
 * Bridges Logto's ID token into the `useAuth` shape `ConvexProviderWithAuth`
 * expects — the React Native counterpart of `useAuthFromLogto` in `react.tsx`.
 *
 * `@logto/rn` exposes `getIdToken()` (the raw JWT Convex validates) just like the
 * web SDK, but differs in two ways the bridge accounts for:
 *   - it has no `isLoading`; `isInitialized` is a one-way false→true latch, so we
 *     map `isLoading: !isInitialized` directly (no "settle latch" needed on web);
 *   - it has no top-level `clearAccessToken`, so the force-refresh path reaches it
 *     through the underlying `client` (`@logto/client`'s `LogtoClient`).
 */
function useAuthFromLogto() {
  const { isAuthenticated, isInitialized, getIdToken, getAccessToken, client } =
    useLogto();

  const fetchAccessToken = useCallback(
    async ({ forceRefreshToken }: { forceRefreshToken: boolean }) => {
      try {
        if (forceRefreshToken) {
          // Clearing the access token forces a token-endpoint round-trip that also
          // rotates the ID token; bail if it fails rather than return a stale token.
          await client.clearAccessToken();
          if (!(await getAccessToken())) return null;
        }
        return (await getIdToken()) ?? null;
      } catch {
        // The refresh token expired or Logto is unreachable: report "no token" so
        // Convex transitions cleanly to unauthenticated instead of surfacing a
        // rejection (which is how a returning user's stale session should resolve).
        return null;
      }
    },
    [client, getIdToken, getAccessToken],
  );

  return useMemo(
    () => ({ isLoading: !isInitialized, isAuthenticated, fetchAccessToken }),
    [isInitialized, isAuthenticated, fetchAccessToken],
  );
}

type ConfigState =
  | { status: "loading" }
  | { status: "ready"; config: LogtoPublicConfig }
  | { status: "error"; error: unknown };

// The native callback URI (your `app.json` scheme, registered in Logto), so
// `useLogtoAuth().signIn()` can default to it without every caller repeating it.
const RedirectUriContext = createContext<string | undefined>(undefined);

export type ConvexLogtoProviderProps = {
  /** Your `ConvexReactClient`. */
  client: ConvexReactClient;
  /** Reference to the query exported from `logtoConfigQuery()`, e.g. `api.logto.config`. */
  configQuery: LogtoConfigQueryRef;
  /**
   * Native sign-in callback URI — your `app.json` `scheme` plus a path, e.g.
   * `io.logto://callback`. Must be registered as a Redirect URI on the Logto app.
   * Used as the default for `useLogtoAuth().signIn()`.
   */
  redirectUri?: string;
  /** Extra scopes. `openid`, `profile`, `offline_access`, and `email` are always included. */
  scopes?: string[];
  /** API resource indicators to request, if any. */
  resources?: string[];
  /**
   * Rendered during the one-time backend config fetch. Unlike the web provider,
   * native has no inert-client trick, so children mount only once `{ endpoint,
   * appId }` arrives. Default `null`. Use Convex's `<AuthLoading>` inside for the
   * subsequent auth handshake.
   */
  fallback?: ReactNode;
  children: ReactNode;
};

/**
 * Wires Logto to Convex on React Native / Expo: pulls `{ endpoint, appId }` from
 * the backend (`configQuery`), mounts `@logto/rn`, and bridges the ID token into
 * Convex. No hand-rolled `useAuth`, no JWT template, no JWKS URL.
 *
 * Unlike the web provider there is **no callback route to add** — `@logto/rn`'s
 * `signIn` opens the system browser and resolves when the deep link returns.
 *
 * @example
 * <ConvexLogtoProvider
 *   client={convex}
 *   configQuery={api.logto.config}
 *   redirectUri="io.logto://callback"
 * >
 *   <App />
 * </ConvexLogtoProvider>
 */
export function ConvexLogtoProvider({
  client,
  configQuery,
  redirectUri,
  scopes,
  resources,
  fallback = null,
  children,
}: ConvexLogtoProviderProps) {
  // One-shot fetch (config is per-deployment, fixed at runtime).
  const [state, setState] = useState<ConfigState>({ status: "loading" });

  useEffect(() => {
    let active = true;
    client
      .query(configQuery)
      .then((config) => {
        if (active) setState({ status: "ready", config });
      })
      .catch((error: unknown) => {
        if (active) setState({ status: "error", error });
      });
    return () => {
      active = false;
    };
  }, [client, configQuery]);

  // Key the memo on array contents, not identity, so a fresh `scopes`/`resources`
  // array each render doesn't rebuild the LogtoClient.
  const scopesKey = scopes?.join(" ") ?? "";
  const resourcesKey = resources?.join(" ") ?? "";
  const endpoint = state.status === "ready" ? state.config.endpoint : "";
  const appId = state.status === "ready" ? state.config.appId : "";
  const logtoConfig = useMemo<LogtoConfig>(
    () => ({
      endpoint,
      appId,
      // Logto adds openid, offline_access, and profile by default; we add email.
      scopes: [UserScope.Email, ...(scopesKey ? scopesKey.split(" ") : [])],
      ...(resourcesKey ? { resources: resourcesKey.split(" ") } : {}),
    }),
    [endpoint, appId, scopesKey, resourcesKey],
  );

  if (state.status === "error") {
    // Throw so an error boundary / dev overlay shows it, instead of a blank screen.
    throw new Error(
      "convex-logto: could not load Logto config from configQuery. Check the query " +
        "is deployed and LOGTO_ENDPOINT / LOGTO_APP_ID are set on the Convex deployment.",
      { cause: state.error },
    );
  }

  // No inert-client trick on native (LogtoProvider takes no LogtoClientClass), so
  // hold the fallback until the real config arrives, then mount the tree once.
  if (state.status !== "ready") return <>{fallback}</>;

  return (
    <RedirectUriContext.Provider value={redirectUri}>
      <LogtoProvider config={logtoConfig}>
        <ConvexProviderWithAuth client={client} useAuth={useAuthFromLogto}>
          {children}
        </ConvexProviderWithAuth>
      </LogtoProvider>
    </RedirectUriContext.Provider>
  );
}

export type LogtoAuth = {
  isAuthenticated: boolean;
  isLoading: boolean;
  /** Decoded ID token claims (sub, email, name, ...), once authenticated. */
  user: IdTokenClaims | undefined;
  /**
   * Start sign-in. Opens the system browser and resolves when the deep link
   * returns. Defaults the redirect to the provider's `redirectUri`; pass one
   * explicitly to override (must be registered on the Logto app).
   */
  signIn: (redirectUri?: string) => Promise<void>;
  /**
   * Sign out. On native this clears the local session by default (it does not
   * open the browser); pass a registered post-sign-out URI to end the Logto
   * session in the browser too.
   */
  signOut: (postLogoutRedirectUri?: string) => Promise<void>;
};

/**
 * Auth state and actions from one import. `isAuthenticated` / `isLoading` come
 * from Convex, so they're true only once Convex has accepted the token.
 *
 * @example
 * const { isAuthenticated, user, signIn, signOut } = useLogtoAuth();
 */
export function useLogtoAuth(): LogtoAuth {
  const { isAuthenticated, isLoading } = useConvexAuth();
  const { signIn, signOut, getIdTokenClaims } = useLogto();
  const defaultRedirectUri = useContext(RedirectUriContext);
  const [user, setUser] = useState<IdTokenClaims>();

  useEffect(() => {
    let active = true;
    if (isAuthenticated) {
      getIdTokenClaims()
        .then((claims) => {
          if (active) setUser(claims);
        })
        // Native's getIdTokenClaims rejects if the token is gone; treat as no user.
        .catch(() => {
          if (active) setUser(undefined);
        });
    } else {
      setUser(undefined);
    }
    return () => {
      active = false;
    };
  }, [isAuthenticated, getIdTokenClaims]);

  const doSignIn = useCallback(
    (redirectUri?: string) => {
      const uri = redirectUri ?? defaultRedirectUri;
      if (!uri) {
        throw new Error(
          "convex-logto: signIn needs a redirect URI on native — pass one to " +
            "signIn() or set `redirectUri` on <ConvexLogtoProvider> (e.g. " +
            '"io.logto://callback").',
        );
      }
      return signIn(uri);
    },
    [signIn, defaultRedirectUri],
  );
  const doSignOut = useCallback(
    (postLogoutRedirectUri?: string) => signOut(postLogoutRedirectUri),
    [signOut],
  );

  return useMemo(
    () => ({
      isAuthenticated,
      isLoading,
      user,
      signIn: doSignIn,
      signOut: doSignOut,
    }),
    [isAuthenticated, isLoading, user, doSignIn, doSignOut],
  );
}
