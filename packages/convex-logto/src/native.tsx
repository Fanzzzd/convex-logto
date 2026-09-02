import {
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
  useInsertionEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  createAuthEventEmitter,
  type AuthEventEmitter,
  type LogtoAuthEventHandler,
} from "./auth-events";
import { asUserClaims, type LogtoUserClaims } from "./claims";
import { useNativeAuthState } from "./auth-loading";
import type { LogtoConfigQueryRef, LogtoPublicConfig } from "./config";
import { normalizeLogtoPublicConfig } from "./component/endpoint";

/**
 * Bridges Logto's ID token into the `useAuth` shape `ConvexProviderWithAuth`
 * expects. The React Native counterpart of `useAuthFromLogto` in `react.tsx`.
 *
 * `@logto/rn` exposes `getIdToken()` (the raw JWT Convex validates) just like the
 * web SDK, but differs in ways the bridge accounts for:
 *   - it has no `isLoading` churn; `isInitialized` is a one-way false→true latch;
 *   - it flips `isAuthenticated` true the instant `signIn()` resolves, so we feed a
 *     one-render loading pulse on that transition via `useNativeAuthState` (#11);
 *   - it has no top-level `clearAccessToken`, so the force-refresh path reaches it
 *     through the underlying `client` (`@logto/client`'s `LogtoClient`).
 */
function useAuthFromLogto() {
  const { isAuthenticated, isInitialized, getIdToken, getAccessToken, client } =
    useLogto();
  const tokenFailure = useContext(TokenFailureContext);

  // One loading frame on the render Logto first authenticates, reported as
  // not-yet-authenticated, so Convex resets cleanly instead of surfacing the
  // logged-out tick (issue #11; see `useNativeAuthState`).
  const { isLoading, isAuthenticated: reportedAuthenticated } =
    useNativeAuthState(isInitialized, isAuthenticated);

  const fetchAccessToken = useCallback(
    async ({ forceRefreshToken }: { forceRefreshToken: boolean }) => {
      try {
        if (forceRefreshToken) {
          // Clearing the access token forces a token-endpoint round-trip that also
          // rotates the ID token; bail if it fails rather than return a stale token.
          await client.clearAccessToken();
          if (!(await getAccessToken())) {
            tokenFailure?.onFailed();
            return null;
          }
        }
        const idToken = (await getIdToken()) ?? null;
        if (idToken === null) tokenFailure?.onFailed();
        return idToken;
      } catch {
        // The refresh token expired or Logto is unreachable. Report "no token"
        // so Convex moves to unauthenticated instead of seeing a rejection,
        // which is how a returning user's stale session should resolve.
        tokenFailure?.onFailed();
        return null;
      }
    },
    [client, getIdToken, getAccessToken, tokenFailure],
  );

  // Convex stops asking for a token after one `null`, and re-arms only when the
  // `isAuthenticated` we report goes false→true. `@logto/rn` latches its own
  // flag true and never moves it, so without folding the failure in here the
  // provider stays disarmed for the life of the process and Sign in cannot
  // recover it. The token never fails *again*, so nothing re-triggers.
  const failed = tokenFailure?.failed ?? false;

  // The SDK going unauthenticated and back (a sign-out, then a fresh sign-in)
  // is a recovery too, and it happens without anyone calling `onRetry`.
  const previouslyAuthenticated = useRef(isAuthenticated);
  useEffect(() => {
    const recovered = !previouslyAuthenticated.current && isAuthenticated;
    previouslyAuthenticated.current = isAuthenticated;
    if (recovered) tokenFailure?.onRetry();
  }, [isAuthenticated, tokenFailure]);

  return useMemo(
    () => ({
      isLoading,
      isAuthenticated: reportedAuthenticated && !failed,
      fetchAccessToken,
    }),
    [isLoading, reportedAuthenticated, failed, fetchAccessToken],
  );
}

/**
 * Whether the last token fetch failed, and the two ways out of it.
 *
 * Lives above `<ConvexProviderWithAuth>` so `useAuthFromLogto` (which runs
 * inside it) can fold the failure into what it reports, and `useLogtoAuth`
 * (which runs inside the app) can clear it when the user signs in again.
 */
type TokenFailureState = {
  failed: boolean;
  onFailed: () => void;
  onRetry: () => void;
};
const TokenFailureContext = createContext<TokenFailureState | undefined>(
  undefined,
);

function useTokenFailureState(): TokenFailureState {
  const [failed, setFailed] = useState(false);
  return useMemo(
    () => ({
      failed,
      onFailed: () => setFailed(true),
      onRetry: () => setFailed(false),
    }),
    [failed],
  );
}

type ConfigState =
  | { status: "loading" }
  | { status: "ready"; config: LogtoPublicConfig }
  | { status: "error"; error: unknown };

// The native callback URI (your `app.json` scheme, registered in Logto), so
// `useLogtoAuth().signIn()` can default to it without every caller repeating it.
const RedirectUriContext = createContext<string | undefined>(undefined);

// `@logto/rn` does not proxy its errors the way the web SDK does: `signIn` and
// `signOut` reject. The shipped pattern is `void signIn()` in an onPress, so
// without somewhere to report them a dismissed browser sheet or an offline
// sign-out becomes an unhandled rejection and nothing else.
const AuthErrorContext = createContext<((error: Error) => void) | undefined>(
  undefined,
);

/** Reports a recoverable auth error to the console and to `onAuthError`. */
function reportAuthError(
  onAuthError: ((error: Error) => void) | undefined,
  error: Error,
): void {
  console.error(`convex-logto: ${error.message}`, error);
  try {
    onAuthError?.(error);
  } catch {
    // An app's own handler must not break sign-in or sign-out.
  }
}

function asAuthError(caught: unknown, fallbackMessage: string): Error {
  if (caught instanceof Error) return caught;
  return new Error(fallbackMessage, { cause: caught });
}

export type ConvexLogtoProviderProps = {
  /** Your `ConvexReactClient`. */
  client: ConvexReactClient;
  /**
   * Native sign-in callback URI: your `app.json` `scheme` plus a path, e.g.
   * `io.logto://callback`. Register it as a Redirect URI on the Logto app.
   * `useLogtoAuth().signIn()` uses this; pass an argument to `signIn` to
   * override.
   */
  redirectUri: string;
  /** Extra scopes. `openid`, `profile`, `offline_access`, and `email` are always included. */
  scopes?: string[];
  /** API resource indicators to request, if any. */
  resources?: string[];
  /**
   * A splash rendered while `configQuery` loads (that mode only; with static
   * `config` there is no loading phase). Children, and the Convex provider,
   * mount only once `{ endpoint, appId }` is known. Default `null`. Convex's
   * `<AuthLoading>` then covers the sign-in handshake from inside your app, not
   * from `fallback` (which renders before Convex is mounted).
   */
  fallback?: ReactNode;
  /**
   * Opt-in phase timings for the auth bootstrap. Absent (the default), nothing
   * is measured or emitted. See [`LogtoAuthEvent`](./auth-events).
   *
   * Native bridge mode emits `bootstrap_start`, `convex_authenticated`, and,
   * only with `configQuery`, `config_loaded`. `@logto/rn` owns the credential
   * lifecycle, so the settle and refresh phases belong to session mode.
   */
  onAuthEvent?: LogtoAuthEventHandler;
  /**
   * Called when sign-in or sign-out fails recoverably (Logto unreachable, the
   * user dismissing the system browser, an expired session). `@logto/rn`
   * rejects rather than storing the error, so without this a `void signIn()` in
   * an `onPress`, the documented pattern, is an unhandled rejection and nothing
   * else. A failed sign-out matters as much. The SDK reaches Logto before
   * clearing tokens, so the user stays signed in.
   */
  onAuthError?: (error: Error) => void;
  children: ReactNode;
} & (
  | {
      /**
       * Your Logto public config, statically: `{ endpoint, appId,
       * allowInsecureHttp? }`. Both OAuth values are public (the client id is
       * not a secret). Non-loopback HTTP requires that explicit opt-in; HTTPS
       * is the default. This is the fastest path, with no config round-trip.
       */
      config: LogtoPublicConfig;
      configQuery?: never;
    }
  | {
      config?: never;
      /**
       * Reference to the query exported from `logtoConfigQuery()`, e.g.
       * `api.logto.config`. Fetches `{ endpoint, appId }` from the Convex
       * deployment at runtime. Prefer static `config` unless you need
       * runtime-resolved config.
       */
      configQuery: LogtoConfigQueryRef;
    }
);

/**
 * Wires Logto to Convex on React Native / Expo. Pulls `{ endpoint, appId }`
 * from the backend (`configQuery`), mounts `@logto/rn`, and bridges the ID
 * token into Convex. No hand-rolled `useAuth`, no JWT template, no JWKS URL.
 *
 * Unlike the web provider there is **no callback route to add**. `@logto/rn`'s
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
export function ConvexLogtoProvider(props: ConvexLogtoProviderProps) {
  const {
    client,
    redirectUri,
    scopes,
    resources,
    fallback = null,
    onAuthEvent,
    onAuthError,
    children,
  } = props;
  const staticConfig = props.config;
  const configQuery = props.configQuery;
  if (!staticConfig && !configQuery) {
    // TypeScript enforces the union, but plain-JS callers can miss both.
    throw new Error(
      "convex-logto: pass either `config` (static { endpoint, appId }) or `configQuery` to ConvexLogtoProvider.",
    );
  }

  // Opt-in phase timings. The emitter is built once per mount and reads the
  // handler through a ref, so an inline arrow never rebuilds anything, and
  // while the ref is empty (no `onAuthEvent`) an emit costs nothing.
  const onAuthEventRef = useRef(onAuthEvent);
  // An insertion effect, because React runs every insertion effect of a
  // commit before any passive effect. The `convex_authenticated` watcher below
  // is a child, and a child's passive effect runs before this component's, so
  // a passive effect here would hand it the previous render's handler.
  useInsertionEffect(() => {
    onAuthEventRef.current = onAuthEvent;
  });
  // oxlint-disable-next-line react/refs -- the emitter reads the ref at emit time, from effects and handlers, never during render
  const events = useMemo(() => createAuthEventEmitter(onAuthEventRef), []);
  useEffect(() => {
    events("bootstrap_start");
  }, [events]);

  // One-shot fetch (config is per-deployment, fixed at runtime), used only in
  // configQuery mode.
  const [fetched, setFetched] = useState<ConfigState>({ status: "loading" });

  const tokenFailure = useTokenFailureState();

  useEffect(() => {
    if (!configQuery) return undefined;
    let active = true;
    client
      .query(configQuery)
      .then((config) => {
        if (!active) return;
        events("config_loaded");
        setFetched({ status: "ready", config });
      })
      .catch((error: unknown) => {
        if (active) setFetched({ status: "error", error });
      });
    return () => {
      active = false;
    };
  }, [client, configQuery, events]);

  const unresolved: LogtoPublicConfig | undefined =
    staticConfig ?? (fetched.status === "ready" ? fetched.config : undefined);
  const resolved =
    unresolved === undefined
      ? undefined
      : normalizeLogtoPublicConfig(unresolved);

  // Key the memo on array contents, not identity, so a fresh `scopes`/`resources`
  // array each render doesn't rebuild the LogtoClient.
  const scopesKey = scopes?.join(" ") ?? "";
  const resourcesKey = resources?.join(" ") ?? "";
  const endpoint = resolved?.endpoint ?? "";
  const appId = resolved?.appId ?? "";
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

  if (configQuery && fetched.status === "error") {
    // Throw so an error boundary / dev overlay shows it, instead of a blank screen.
    throw new Error(
      "convex-logto: could not load Logto config from configQuery. Check the query " +
        "is deployed and LOGTO_ENDPOINT / LOGTO_APP_ID are set on the Convex deployment.",
      { cause: fetched.error },
    );
  }

  // Hold the fallback until the config is known, then mount the tree once (with
  // static `config` this is immediate; there is no loading phase at all).
  if (!resolved) return <>{fallback}</>;

  return (
    <RedirectUriContext.Provider value={redirectUri}>
      <AuthErrorContext.Provider value={onAuthError}>
        <TokenFailureContext.Provider value={tokenFailure}>
          <LogtoProvider config={logtoConfig}>
            {/* oxlint-disable-next-line react/hooks -- `useAuth` is a prop that takes a hook; that is Convex's API. */}
            <ConvexProviderWithAuth client={client} useAuth={useAuthFromLogto}>
              <ConvexAuthPhaseWatcher events={events} />
              {children}
            </ConvexProviderWithAuth>
          </LogtoProvider>
        </TokenFailureContext.Provider>
      </AuthErrorContext.Provider>
    </RedirectUriContext.Provider>
  );
}

/**
 * `convex_authenticated` is the phase that matters to an app, the first moment
 * an authenticated query can run, and only Convex knows when it arrives.
 */
function ConvexAuthPhaseWatcher({ events }: { events: AuthEventEmitter }) {
  const { isAuthenticated } = useConvexAuth();
  const reported = useRef(false);
  useEffect(() => {
    if (!isAuthenticated || reported.current) return;
    reported.current = true;
    events("convex_authenticated");
  }, [events, isAuthenticated]);
  return null;
}

export type LogtoAuth = {
  isAuthenticated: boolean;
  isLoading: boolean;
  /**
   * Decoded ID token claims (sub, email, name, ...), once authenticated.
   * Display only. A Convex function reads the same claims through
   * `ctx.auth.getUserIdentity()`, which is where they are trustworthy.
   */
  user: LogtoUserClaims | undefined;
  /**
   * Start sign-in. Opens the system browser and resolves when the deep link
   * returns. Defaults the redirect to the provider's `redirectUri`; pass one
   * explicitly to override (must be registered on the Logto app).
   *
   * Takes an options object like every other entry. The native override is a
   * redirect URI rather than the web's `returnTo`, because there is no in-app
   * route to come back to until the deep link lands.
   */
  signIn: (options?: { redirectUri?: string }) => Promise<void>;
  /**
   * Sign out. Revokes the tokens and clears local storage. Unlike the web, it
   * does not open the browser, because `@logto/rn` skips the federated sign-out
   * flow by default, so the Logto SSO session in the system browser may persist
   * and a later sign-in can skip the prompt.
   */
  signOut: (options?: { postLogoutRedirectUri?: string }) => Promise<void>;
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
  const onAuthError = useContext(AuthErrorContext);
  const tokenFailure = useContext(TokenFailureContext);
  const [user, setUser] = useState<LogtoUserClaims>();

  useEffect(() => {
    let active = true;
    if (isAuthenticated) {
      getIdTokenClaims()
        // Narrowed through the same gate session mode uses, so both modes hand
        // back one type. The SDK's `IdTokenClaims` is an interface with no
        // index signature, which is what makes a custom claim unreachable here.
        .then((claims) => {
          if (active) setUser(asUserClaims(claims));
        })
        // Native's getIdTokenClaims rejects if the token is gone; treat as no user.
        .catch(() => {
          if (active) setUser(undefined);
        });
    } else {
      // Deriving `user` from `isAuthenticated` instead would show the previous
      // user's claims for a frame on the next sign-in, until the fetch above
      // replaces them. Clearing them costs one render, at sign-out.
      // oxlint-disable-next-line react/set-state-in-effect -- see above
      setUser(undefined);
    }
    return () => {
      active = false;
    };
  }, [isAuthenticated, getIdTokenClaims]);

  const doSignIn = useCallback(
    async (options?: { redirectUri?: string }) => {
      const uri = options?.redirectUri ?? defaultRedirectUri;
      try {
        if (!uri) {
          throw new Error(
            "convex-logto: signIn needs a redirect URI on native. Pass one to " +
              "signIn() or set `redirectUri` on <ConvexLogtoProvider> (e.g. " +
              '"io.logto://callback").',
          );
        }
        await signIn(uri);
        // After, never before. A background fetch racing the browser sheet could
        // re-arm Convex against a token that is still broken, and setting it back
        // to failed would then be the *stale* write. Once `signIn` resolves the
        // SDK holds fresh tokens, so this is the point where retrying is honest.
        tokenFailure?.onRetry();
      } catch (caught) {
        // Dismissing the system browser rejects with `auth_session_failed`.
        // Report it so an app's "signing in…" state has something to clear on.
        const failure = asAuthError(
          caught,
          "convex-logto: starting Logto sign-in failed.",
        );
        reportAuthError(onAuthError, failure);
        throw failure;
      }
    },
    [signIn, defaultRedirectUri, onAuthError, tokenFailure],
  );
  const doSignOut = useCallback(
    async (options?: { postLogoutRedirectUri?: string }) => {
      try {
        await signOut(options?.postLogoutRedirectUri);
      } catch (caught) {
        // `@logto/client` reaches OIDC discovery before it clears tokens, so an
        // unreachable Logto leaves the user signed in with a live ID token while
        // the button looks like it worked.
        const failure = asAuthError(
          caught,
          "convex-logto: Logto sign-out failed.",
        );
        reportAuthError(onAuthError, failure);
        throw failure;
      }
    },
    [signOut, onAuthError],
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

export type {
  LogtoAuthEvent,
  LogtoAuthEventHandler,
  LogtoAuthEventSource,
  LogtoAuthPhase,
} from "./auth-events";
