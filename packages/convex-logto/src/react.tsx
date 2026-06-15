import {
  type IdTokenClaims,
  type LogtoConfig,
  LogtoProvider,
  type LogtoProviderProps,
  UserScope,
  useHandleSignInCallback,
  useLogto,
} from "@logto/react";
import {
  ConvexProviderWithAuth,
  type ConvexReactClient,
  useConvexAuth,
} from "convex/react";
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { type SignInOutcome, classifySignInSearch } from "./callback";
import type { LogtoConfigQueryRef, LogtoPublicConfig } from "./config";

const CALLBACK_PATH = "/callback";

/** Bridges Logto's ID token into the `useAuth` shape `ConvexProviderWithAuth` expects. */
function useAuthFromLogto() {
  const {
    isAuthenticated,
    isLoading,
    getIdToken,
    getAccessToken,
    clearAccessToken,
  } = useLogto();

  // `@logto/react` toggles `isLoading` around every SDK call; forwarding that to
  // Convex creates a token-fetch ↔ loading feedback loop that flickers the
  // identity. Latch on the first settle and ignore the churn after.
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    if (!isLoading) setSettled(true);
  }, [isLoading]);

  const fetchAccessToken = useCallback(
    async ({ forceRefreshToken }: { forceRefreshToken: boolean }) => {
      try {
        if (forceRefreshToken) {
          // Clearing the access token forces a token-endpoint round-trip that also
          // rotates the ID token; bail if it fails rather than return a stale token.
          await clearAccessToken();
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
    [getIdToken, getAccessToken, clearAccessToken],
  );

  return useMemo(
    () => ({ isLoading: !settled, isAuthenticated, fetchAccessToken }),
    [settled, isAuthenticated, fetchAccessToken],
  );
}

// An inert Logto client mounted only while the backend config loads. Its
// `isAuthenticated()` never resolves, so @logto/react's loadingCount stays > 0 —
// `isLoading` holds true and there's no signed-out flash — until the real client
// swaps in once config arrives. A Proxy covers every method @logto/react binds,
// and it touches no `window`, so the whole provider tree is safe to render on the
// server (SSR) and during the first client paint.
type LogtoClientClass = NonNullable<LogtoProviderProps["LogtoClientClass"]>;
const pendingForever = new Promise<never>(() => {});
const LoadingLogtoClient = function () {
  return new Proxy(
    {},
    {
      get: (_t, key) =>
        key === "isAuthenticated"
          ? () => pendingForever
          : async () => undefined,
    },
  );
} as unknown as LogtoClientClass;
const LOADING_LOGTO_CONFIG: LogtoConfig = {
  endpoint: "https://convex-logto-loading.invalid",
  appId: "__convex_logto_loading__",
};

/** Finishes the OIDC redirect then navigates to `afterSignIn`; surfaces setup errors loudly. */
function LogtoCallback({
  afterSignIn,
  navigate,
}: {
  afterSignIn: string;
  navigate?: (to: string) => void;
}) {
  const goAfterSignIn = useCallback(() => {
    if (navigate) navigate(afterSignIn);
    else window.location.replace(afterSignIn);
  }, [navigate, afterSignIn]);

  // Classified once from the landing URL; only a real OIDC redirect carries `state`.
  // A real callback always arrives via a full-page redirect, so mount == landing.
  const outcome = useMemo<SignInOutcome>(
    () =>
      typeof window === "undefined"
        ? { kind: "none" }
        : classifySignInSearch(window.location.search),
    [],
  );
  // This component renders on every route, so once the exchange succeeds we latch
  // it finished and unmount <CodeExchange> — otherwise it lingers off `/callback`,
  // keeping the SDK's callback hook alive over an already-consumed code.
  const [exchanged, setExchanged] = useState(false);

  useEffect(() => {
    // The user cancelled / there was no session — just return to the app.
    if (outcome.kind === "benign") goAfterSignIn();
  }, [outcome, goAfterSignIn]);

  if (outcome.kind === "error")
    throw new Error(`convex-logto: ${outcome.message}`);
  // Only a real `?code=` callback runs the token exchange; benign/error redirects
  // never touch the SDK, so a cancelled sign-in can't poison the next one.
  if (outcome.kind === "pending" && !exchanged)
    return (
      <CodeExchange
        onExchanged={() => setExchanged(true)}
        goAfterSignIn={goAfterSignIn}
      />
    );
  return null;
}

/** Runs the code→token exchange for a real `/callback?code=…` landing. */
function CodeExchange({
  onExchanged,
  goAfterSignIn,
}: {
  onExchanged: () => void;
  goAfterSignIn: () => void;
}) {
  // Fires once when the code→token exchange succeeds: stop rendering this handler
  // (so the spent code is never re-submitted), then continue into the app.
  useHandleSignInCallback(() => {
    onExchanged();
    goAfterSignIn();
  });
  const { error } = useLogto();
  // Surface a failed exchange instead of hanging the page on "finishing sign in".
  if (error) {
    throw new Error(
      `convex-logto: completing Logto sign-in failed (${error.message}). ` +
        `The callback URL was likely stale or the sign-in session was lost — ` +
        `start sign-in again.`,
      { cause: error },
    );
  }
  return null;
}

type ConfigState =
  | { status: "loading" }
  | { status: "ready"; config: LogtoPublicConfig }
  | { status: "error"; error: unknown };

export type ConvexLogtoProviderProps = {
  /** Your `ConvexReactClient`. */
  client: ConvexReactClient;
  /** Reference to the query exported from `logtoConfigQuery()`, e.g. `api.logto.config`. */
  configQuery: LogtoConfigQueryRef;
  /** Extra scopes. `openid`, `profile`, `offline_access`, and `email` are always included. */
  scopes?: string[];
  /** API resource indicators to request, if any. */
  resources?: string[];
  /** Where to go once sign-in completes. Default `/`. */
  afterSignIn?: string;
  /** Soft navigation (e.g. your router's navigate). Falls back to a hard redirect. */
  navigate?: (to: string) => void;
  children: ReactNode;
};

/**
 * Wires Logto to Convex: pulls `{ endpoint, appId }` from the backend (`configQuery`),
 * mounts Logto, bridges the ID token into Convex, and finishes the sign-in redirect.
 * No hand-rolled `useAuth`, no JWT template, no JWKS URL.
 *
 * Safe to render on the server: children mount immediately (under Convex's
 * `<AuthLoading>`) while config loads and nothing touches `window`, so SSR
 * frameworks need no stub or mount-gate. The redirect lands on `/callback` — add a
 * route there that just renders; pass `signIn(`${origin}/your-path`)` for another path.
 *
 * @example
 * <ConvexLogtoProvider client={convex} configQuery={api.logto.config}>
 *   <App />
 * </ConvexLogtoProvider>
 */
export function ConvexLogtoProvider({
  client,
  configQuery,
  scopes,
  resources,
  afterSignIn = "/",
  navigate,
  children,
}: ConvexLogtoProviderProps) {
  // One-shot fetch (config is per-deployment, fixed at runtime). Until it lands we
  // mount the same tree with an inert client, so there's no remount when it does.
  const [state, setState] = useState<ConfigState>({ status: "loading" });

  useEffect(() => {
    let active = true;
    // Don't reset to "loading" on re-run: once resolved, demoting back would swap
    // the live Logto client for the inert one mid-session and drop the identity.
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
  const logtoConfig = useMemo<LogtoConfig>(() => {
    if (state.status !== "ready") return LOADING_LOGTO_CONFIG;
    return {
      endpoint: state.config.endpoint,
      appId: state.config.appId,
      // Logto adds openid, offline_access, and profile by default; we add email.
      scopes: [UserScope.Email, ...(scopesKey ? scopesKey.split(" ") : [])],
      ...(resourcesKey ? { resources: resourcesKey.split(" ") } : {}),
    };
  }, [state, scopesKey, resourcesKey]);

  if (state.status === "error") {
    // Throw so an error boundary / dev overlay shows it, instead of a blank screen.
    throw new Error(
      "convex-logto: could not load Logto config from configQuery. Check the query " +
        "is deployed and LOGTO_ENDPOINT / LOGTO_APP_ID are set on the Convex deployment.",
      { cause: state.error },
    );
  }

  const ready = state.status === "ready";
  return (
    <LogtoProvider
      config={logtoConfig}
      {...(ready ? {} : { LogtoClientClass: LoadingLogtoClient })}
    >
      {/* Only meaningful once the real client is up; a no-op until the callback URL. */}
      {ready ? (
        <LogtoCallback afterSignIn={afterSignIn} navigate={navigate} />
      ) : null}
      <ConvexProviderWithAuth client={client} useAuth={useAuthFromLogto}>
        {children}
      </ConvexProviderWithAuth>
    </LogtoProvider>
  );
}

export type LogtoAuth = {
  isAuthenticated: boolean;
  isLoading: boolean;
  /** Decoded ID token claims (sub, email, name, ...), once authenticated. */
  user: IdTokenClaims | undefined;
  /** Start sign-in. Defaults the redirect to `${origin}/callback`. */
  signIn: (redirectUri?: string) => Promise<void>;
  /**
   * Sign out: ends the Logto session, then returns to `window.location.origin`,
   * which you must register as a **Post sign-out redirect URI** (exact match, no
   * trailing slash). Pass another registered URI to land elsewhere.
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
  const [user, setUser] = useState<IdTokenClaims>();

  useEffect(() => {
    let active = true;
    if (isAuthenticated) {
      // Resolves undefined on failure (never rejects).
      getIdTokenClaims().then((claims) => {
        if (active) setUser(claims);
      });
    } else {
      setUser(undefined);
    }
    return () => {
      active = false;
    };
  }, [isAuthenticated, getIdTokenClaims]);

  const doSignIn = useCallback(
    (redirectUri?: string) =>
      signIn(redirectUri ?? `${window.location.origin}${CALLBACK_PATH}`),
    [signIn],
  );
  // Federated sign-out: ends the SSO session (so the next sign-in isn't silent),
  // then returns to origin — which must be a registered Post sign-out redirect URI.
  const doSignOut = useCallback(
    (postLogoutRedirectUri?: string) =>
      signOut(postLogoutRedirectUri ?? window.location.origin),
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
