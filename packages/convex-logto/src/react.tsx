import {
  type IdTokenClaims,
  type LogtoConfig,
  LogtoProvider,
  ReservedScope,
  UserScope,
  useHandleSignInCallback,
  useLogto,
} from "@logto/react";
import { ConvexProviderWithAuth, type ConvexReactClient } from "convex/react";
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

const CallbackPathContext = createContext("/callback");

/**
 * Bridges Logto's `useLogto()` into the `useAuth` shape `ConvexProviderWithAuth`
 * expects, returning the Logto **ID token** (not the `at+jwt` access token).
 * `@logto/react` wraps these methods so they resolve `undefined` on failure
 * rather than throwing, so no try/catch is needed here.
 */
function useAuthFromLogto() {
  const {
    isAuthenticated,
    isLoading,
    getIdToken,
    getAccessToken,
    clearAccessToken,
  } = useLogto();

  const fetchAccessToken = useCallback(
    async ({ forceRefreshToken }: { forceRefreshToken: boolean }) => {
      if (forceRefreshToken) {
        // Force a refresh-token exchange: dropping the cached access token makes
        // getAccessToken() hit the token endpoint, which also rotates the cached
        // ID token. If the refresh fails, getAccessToken() resolves undefined, so
        // bail out rather than return the now-stale ID token; Convex then drives
        // re-authentication.
        await clearAccessToken();
        const refreshed = await getAccessToken();
        if (!refreshed) return null;
      }
      return (await getIdToken()) ?? null;
    },
    [getIdToken, getAccessToken, clearAccessToken],
  );

  return useMemo(
    () => ({ isLoading, isAuthenticated, fetchAccessToken }),
    [isLoading, isAuthenticated, fetchAccessToken],
  );
}

/**
 * Drives Logto's `useHandleSignInCallback`, which only acts when the current URL
 * matches a stored sign-in session (so it's a no-op off the redirect), then
 * navigates to `afterSignIn` once the OIDC exchange completes.
 */
function LogtoCallback({
  afterSignIn,
  navigate,
}: {
  afterSignIn: string;
  navigate?: (to: string) => void;
}) {
  useHandleSignInCallback(() => {
    if (navigate) navigate(afterSignIn);
    else window.location.replace(afterSignIn);
  });
  return null;
}

type InnerProviderProps = {
  client: ConvexReactClient;
  endpoint: string;
  appId: string;
  scopes?: string[];
  resources?: string[];
  callbackPath: string;
  afterSignIn: string;
  navigate?: (to: string) => void;
  children: ReactNode;
};

/** Mounts Logto + the Convex bridge once concrete config is available. */
function InnerProvider({
  client,
  endpoint,
  appId,
  scopes,
  resources,
  callbackPath,
  afterSignIn,
  navigate,
  children,
}: InnerProviderProps) {
  // Inline `scopes`/`resources` arrays get a fresh identity each render, which
  // would rebuild `logtoConfig` (and the underlying LogtoClient) every time.
  // Key on the content instead, and reconstruct the arrays inside the memo.
  const scopesKey = scopes?.join(" ") ?? "";
  const resourcesKey = resources?.join(" ") ?? "";
  const logtoConfig = useMemo<LogtoConfig>(
    () => ({
      endpoint,
      appId,
      scopes: [
        UserScope.Email,
        UserScope.Profile,
        ReservedScope.OfflineAccess,
        ...(scopesKey ? scopesKey.split(" ") : []),
      ],
      ...(resourcesKey ? { resources: resourcesKey.split(" ") } : {}),
    }),
    [endpoint, appId, scopesKey, resourcesKey],
  );

  return (
    <LogtoProvider config={logtoConfig}>
      <CallbackPathContext.Provider value={callbackPath}>
        {/*
         * Mount the callback handler unconditionally: `useHandleSignInCallback`
         * is a no-op unless Logto's stored sign-in session matches the current
         * URL (it checks `isSignInRedirected`), so it correctly finishes `?code=`
         * exchanges *and* `?error=`/custom-redirect landings, and does nothing
         * on ordinary navigation.
         */}
        <LogtoCallback afterSignIn={afterSignIn} navigate={navigate} />
        <ConvexProviderWithAuth client={client} useAuth={useAuthFromLogto}>
          {children}
        </ConvexProviderWithAuth>
      </CallbackPathContext.Provider>
    </LogtoProvider>
  );
}

type ConfigState =
  | { status: "loading" }
  | { status: "ready"; config: LogtoPublicConfig }
  | { status: "error"; error: unknown };

/** Fetches `{ endpoint, appId }` from the backend, then mounts InnerProvider. */
function BackendConfiguredProvider({
  client,
  configQuery,
  fallback,
  ...rest
}: Omit<InnerProviderProps, "endpoint" | "appId"> & {
  configQuery: LogtoConfigQueryRef;
  fallback?: ReactNode;
}) {
  const [state, setState] = useState<ConfigState>({ status: "loading" });

  useEffect(() => {
    let active = true;
    setState({ status: "loading" });
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

  if (state.status === "error") {
    // Surface loudly instead of hanging on a blank screen: an error boundary
    // (or the dev overlay) shows exactly what went wrong.
    throw new Error(
      "convex-logto: could not load Logto config from configQuery. Check that " +
        "the query is deployed and LOGTO_ENDPOINT / LOGTO_APP_ID are set on the " +
        "Convex deployment.",
      { cause: state.error },
    );
  }
  if (state.status === "loading") return <>{fallback ?? null}</>;
  return (
    <InnerProvider
      client={client}
      endpoint={state.config.endpoint}
      appId={state.config.appId}
      {...rest}
    />
  );
}

type CommonProps = {
  /** Your `ConvexReactClient`. */
  client: ConvexReactClient;
  /** Extra scopes. `email`, `profile`, and `offline_access` are always included. */
  scopes?: string[];
  /** API resource indicators to request, if any. */
  resources?: string[];
  /**
   * Path that receives the OIDC redirect. Default `/callback`. The provider
   * auto-finishes the sign-in redirect (both `?code=` success and `?error=`
   * cases) once Logto recognizes the landing URL as its callback.
   */
  callbackPath?: string;
  /** Where to go once sign-in completes. Default `/`. */
  afterSignIn?: string;
  /** Soft navigation (e.g. your router's navigate). Falls back to a hard redirect. */
  navigate?: (to: string) => void;
  children: ReactNode;
};

/** Configure Logto directly with literal values (or `import.meta.env`). */
export type ConvexLogtoLiteralProps = CommonProps & {
  endpoint: string;
  appId: string;
  configQuery?: never;
  fallback?: never;
};

/** Single source of truth: pull `{ endpoint, appId }` from your backend. */
export type ConvexLogtoBackendProps = CommonProps & {
  /** Reference to the query exported from `logtoConfigQuery()`, e.g. `api.logto.config`. */
  configQuery: LogtoConfigQueryRef;
  /** Rendered while the config is being fetched. Default: nothing. */
  fallback?: ReactNode;
  endpoint?: never;
  appId?: never;
};

export type ConvexLogtoProviderProps =
  | ConvexLogtoLiteralProps
  | ConvexLogtoBackendProps;

/**
 * One provider that wires Logto to Convex: it renders `<LogtoProvider>`, bridges
 * the Logto ID token into `<ConvexProviderWithAuth>`, and finishes the sign-in
 * redirect automatically. No hand-rolled `useAuth`, no JWT template, no JWKS URL.
 *
 * Provide either literal `endpoint`/`appId`, or a `configQuery` so the frontend
 * pulls them from the backend (configure Logto in one place per environment).
 *
 * @example
 * <ConvexLogtoProvider client={convex} configQuery={api.logto.config}>
 *   <App />
 * </ConvexLogtoProvider>
 */
export function ConvexLogtoProvider(props: ConvexLogtoProviderProps) {
  const {
    client,
    scopes,
    resources,
    callbackPath = "/callback",
    afterSignIn = "/",
    navigate,
    children,
  } = props;

  const shared = {
    client,
    scopes,
    resources,
    callbackPath,
    afterSignIn,
    navigate,
  };

  if (props.configQuery) {
    return (
      <BackendConfiguredProvider
        {...shared}
        configQuery={props.configQuery}
        fallback={props.fallback}
      >
        {children}
      </BackendConfiguredProvider>
    );
  }

  return (
    <InnerProvider {...shared} endpoint={props.endpoint} appId={props.appId}>
      {children}
    </InnerProvider>
  );
}

export type LogtoAuth = {
  isAuthenticated: boolean;
  isLoading: boolean;
  /** Decoded ID token claims (sub, email, name, ...), once authenticated. */
  user: IdTokenClaims | undefined;
  /** Start sign-in. Defaults the redirect to `${origin}${callbackPath}`. */
  signIn: (redirectUri?: string) => Promise<void>;
  /** Sign out. Defaults the post-logout redirect to the current origin. */
  signOut: (postLogoutRedirectUri?: string) => Promise<void>;
};

/**
 * Everything a component needs for auth, from one import — no need to also pull
 * in `@logto/react`. `signIn`/`signOut` come pre-filled with sensible redirects
 * that respect the provider's `callbackPath`.
 *
 * @example
 * const { isAuthenticated, user, signIn, signOut } = useLogtoAuth();
 */
export function useLogtoAuth(): LogtoAuth {
  const { isAuthenticated, isLoading, signIn, signOut, getIdTokenClaims } =
    useLogto();
  const callbackPath = useContext(CallbackPathContext);
  const [user, setUser] = useState<IdTokenClaims>();

  useEffect(() => {
    let active = true;
    if (isAuthenticated) {
      // getIdTokenClaims() resolves undefined on failure (never rejects).
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
      signIn(redirectUri ?? `${window.location.origin}${callbackPath}`),
    [signIn, callbackPath],
  );
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
