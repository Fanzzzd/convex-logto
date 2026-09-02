import {
  type LogtoConfig,
  LogtoProvider,
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
import { nextAuthLoading } from "./auth-loading";
import {
  type SignInOutcome,
  callbackResolved,
  classifySignInSearch,
  isSafeReturnTo,
} from "./callback";
import type { LogtoConfigQueryRef, LogtoPublicConfig } from "./config";
import { normalizeLogtoPublicConfig } from "./component/endpoint";

const DEFAULT_CALLBACK_PATH = "/callback";

// Safety net for a `/callback` URL that will never exchange and never error (the
// sign-in session was lost): after this long, give up waiting and return to the
// app rather than spinning forever. A real exchange resolves in well under this
// (the SDK flips `isAuthenticated` as it finishes), so this only bites the rare
// stuck case. See {@link callbackResolved} and #14.
const STALE_CALLBACK_TIMEOUT_MS = 10_000;

// Provider-level settings the bridge hooks need but can't take as props, since
// `ConvexProviderWithAuth` owns the `useAuth` call site.
/**
 * One `signIn()`/`signOut()` call, tracked so the failure `@logto/react`
 * swallows into its own state can still be reported exactly once.
 */
type BridgeAuthAttempt = {
  baselineError: Error | undefined;
  handled: boolean;
};

type BridgeAuthErrors = {
  begin: (baselineError: Error | undefined) => BridgeAuthAttempt;
  fail: (attempt: BridgeAuthAttempt, error: Error) => void;
  observe: (error: Error | undefined) => void;
};

const NOOP_AUTH_ERRORS: BridgeAuthErrors = {
  begin: (baselineError) => ({ baselineError, handled: false }),
  fail: () => {},
  observe: () => {},
};

const BridgeContext = createContext<{
  callbackPath: string;
  authErrors: BridgeAuthErrors;
  /**
   * Is this document still finishing an OIDC redirect? React state, not a read
   * of `window.location`: the location is not a reactive source, and a provider
   * mounted *above* the router — the layout every SPA example ships — never
   * re-renders when the callback soft-navigates away. A value derived from the
   * URL during render would then stay frozen at "still on /callback" for the
   * rest of the page session.
   */
  callbackActive: boolean;
}>({
  callbackPath: DEFAULT_CALLBACK_PATH,
  authErrors: NOOP_AUTH_ERRORS,
  callbackActive: false,
});

/** True only when the current document is on the provider's callback route. */
function onCallbackRoute(callbackPath: string): boolean {
  return (
    typeof window !== "undefined" && window.location.pathname === callbackPath
  );
}

// `signIn({ returnTo })` stashes the post-sign-in destination here; the callback
// resolution consumes it. Our own stash (not the SDK's `postRedirectUri`) because
// the SDK navigates to `postRedirectUri` itself with a hard redirect, which would
// bypass the `navigate` prop and race our own resolution flow. sessionStorage is
// same-tab, which is exactly the OIDC redirect's scope.
const RETURN_TO_KEY = "convex-logto:returnTo";
function stashReturnTo(returnTo: string): void {
  try {
    sessionStorage.setItem(RETURN_TO_KEY, returnTo);
  } catch {
    // Storage unavailable (private mode quota, sandbox): fall back to afterSignIn.
  }
}
function takeReturnTo(): string | undefined {
  try {
    const value = sessionStorage.getItem(RETURN_TO_KEY);
    sessionStorage.removeItem(RETURN_TO_KEY);
    // Re-validate on read: the stash is same-origin storage, but a hostile or
    // buggy write must still never turn the redirect into an open redirect.
    return value !== null && isSafeReturnTo(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** Bridges Logto's ID token into the `useAuth` shape `ConvexProviderWithAuth` expects. */
function useAuthFromLogto() {
  const { callbackActive } = useContext(BridgeContext);
  const {
    isAuthenticated,
    isLoading,
    getIdToken,
    getAccessToken,
    clearAccessToken,
  } = useLogto();

  // A `/callback?code=` exchange is in flight: the SDK has the code but hasn't
  // authenticated yet. Hold `isLoading` true through it so Convex never sees a
  // transient logged-out tick that route guards mistake for a sign-out (#11).
  // Gated to the exact callback route: a stray `?code=&state=` on any other page
  // is not a sign-in transaction and must not pin the app into a loading state.
  //
  // `callbackActive` ends when the callback resolves — including when it
  // resolves *without* authenticating (spent code, lost sign-in session, the
  // stale-callback timeout). It has veto over `isLoading`, so reading it from
  // the URL instead would leave an app whose provider never re-renders pinned
  // at `isLoading: true` forever, with no way back short of a page reload.
  const authFlowPending =
    !isAuthenticated &&
    callbackActive &&
    classifySignInSearch(window.location.search).kind === "pending";

  // `@logto/react` toggles `isLoading` around every SDK call; forwarding that to
  // Convex flickers the identity. Latch on the first settle and ignore the churn.
  const [settled, setSettled] = useState(false);
  const { settled: shouldSettle, isLoading: reportedLoading } = nextAuthLoading(
    settled,
    isLoading,
    authFlowPending,
  );
  // Latched during render, the way React documents for remembering a fact
  // from an earlier render: it re-runs this component before committing, so
  // the settled frame commits once instead of once plus an effect re-render.
  if (shouldSettle && !settled) setSettled(true);

  // Merge concurrent fetches of the same kind into one in-flight promise, so
  // StrictMode double-invokes and overlapping WS auth attempts can't stack
  // token-endpoint round-trips (a forced refresh is never satisfied by a plain
  // in-flight fetch, so the two kinds don't merge with each other).
  const inflight = useRef<{
    forced?: Promise<string | null>;
    plain?: Promise<string | null>;
  }>({});
  const fetchAccessToken = useCallback(
    async ({ forceRefreshToken }: { forceRefreshToken: boolean }) => {
      const kind = forceRefreshToken ? "forced" : "plain";
      const existing = inflight.current[kind];
      if (existing) return existing;
      const request = (async () => {
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
        } finally {
          inflight.current[kind] = undefined;
        }
      })();
      inflight.current[kind] = request;
      return request;
    },
    [getIdToken, getAccessToken, clearAccessToken],
  );

  return useMemo(
    () => ({ isLoading: reportedLoading, isAuthenticated, fetchAccessToken }),
    [reportedLoading, isAuthenticated, fetchAccessToken],
  );
}

/** Reports a recoverable auth error: loud in the console, surfaced to `onAuthError`. */
function reportAuthError(
  onAuthError: ((error: Error) => void) | undefined,
  error: Error,
): void {
  console.error(`convex-logto: ${error.message}`, error);
  try {
    onAuthError?.(error);
  } catch {
    // A throwing observer must not replace the auth failure or break recovery.
  }
}

function asAuthError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback, { cause: error });
}

/**
 * `convex_authenticated` is the phase that matters to an app — the first moment
 * an authenticated query can run — and only Convex knows when it arrives.
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

/** Observes the failures @logto/react catches into its error state instead of rejecting. */
function LogtoAuthErrorObserver({
  authErrors,
}: {
  authErrors: BridgeAuthErrors;
}) {
  const { error } = useLogto();
  useEffect(() => {
    authErrors.observe(error);
  }, [error, authErrors]);
  return null;
}

/** Finishes the OIDC redirect then navigates to `returnTo`/`afterSignIn`; errors are recoverable. */
function LogtoCallback({
  afterSignIn,
  navigate,
  onAuthError,
  onResolved,
}: {
  afterSignIn: string;
  navigate?: (to: string) => void;
  onAuthError?: (error: Error) => void;
  /** Ends the provider's callback flow, whatever the outcome. */
  onResolved: () => void;
}) {
  const goAfterSignIn = useCallback(() => {
    // `returnTo` (validated same-origin path) wins over the static default.
    const to = takeReturnTo() ?? afterSignIn;
    // Prefer a soft nav (pass a replace-style navigate for history hygiene);
    // the hard fallback uses replace so the spent code never stays in history.
    if (navigate) navigate(to);
    else window.location.replace(to);
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
  // `outcome` is frozen at mount, so once the callback resolves we latch it done
  // and unmount <CodeExchange> — otherwise it would keep the SDK's callback hook
  // alive over a spent code if this component re-renders before navigation.
  const [done, setDone] = useState(false);

  // Resolve at most once. StrictMode double-invokes this effect, and in
  // production it re-runs whenever an inline `navigate`/`onAuthError` arrow —
  // the documented pattern — changes identity. `takeReturnTo()` is destructive,
  // so a second pass finds the stash empty and sends the user to `afterSignIn`
  // instead of where they were headed; an error would also be reported twice.
  const resolved = useRef(false);
  useEffect(() => {
    if (resolved.current) return;
    // On the callback route with no sign-in result to finish. Nothing to do,
    // but the flow still has to end or it would gate the provider forever.
    if (outcome.kind === "none") {
      resolved.current = true;
      onResolved();
      return;
    }
    // The user cancelled / there was no session: just return to the app.
    // `done` is not set here; it only gates <CodeExchange>, which a benign or
    // error outcome never mounts.
    if (outcome.kind === "benign") {
      resolved.current = true;
      onResolved();
      goAfterSignIn();
      return;
    }
    // A setup error (e.g. invalid_scope): recoverable, not fatal. Report and
    // return to the app logged out, instead of throwing during render. A throw
    // would blank any tree without an error boundary above the provider.
    if (outcome.kind === "error") {
      resolved.current = true;
      reportAuthError(onAuthError, new Error(outcome.message));
      onResolved();
      goAfterSignIn();
    }
  }, [outcome, goAfterSignIn, onAuthError, onResolved]);

  // Only a real `?code=` callback runs the token exchange; benign/error redirects
  // never touch the SDK, so a cancelled sign-in can't poison the next one.
  if (outcome.kind === "pending" && !done)
    return (
      <CodeExchange
        onDone={() => {
          setDone(true);
          onResolved();
        }}
        goAfterSignIn={goAfterSignIn}
        onAuthError={onAuthError}
      />
    );
  return null;
}

/** Runs the code→token exchange for a real `/callback?code=…` landing. */
function CodeExchange({
  onDone,
  goAfterSignIn,
  onAuthError,
}: {
  onDone: () => void;
  goAfterSignIn: () => void;
  onAuthError?: (error: Error) => void;
}) {
  const { isAuthenticated, isLoading, error } = useLogto();
  // Rendering the hook is what makes @logto/react run the code→token exchange. We
  // deliberately do NOT navigate from its callback: on a stale/replayed callback URL
  // the SDK won't exchange (already authenticated, or the sign-in session is gone),
  // so that callback never fires (#14). We resolve from observable state instead.
  useHandleSignInCallback(() => {});

  // Safety net for a callback that resolves on its own (lost session: no exchange,
  // no error, never authenticated). Arm the countdown ONLY while the SDK is idle and
  // unauthenticated — an in-flight exchange holds `isLoading` true, which cancels and
  // re-arms the timer, so a slow-but-legit sign-in is never abandoned mid-exchange.
  const [timedOut, setTimedOut] = useState(false);
  useEffect(() => {
    if (isAuthenticated || isLoading) return undefined;
    const timer = setTimeout(
      () => setTimedOut(true),
      STALE_CALLBACK_TIMEOUT_MS,
    );
    return () => clearTimeout(timer);
  }, [isAuthenticated, isLoading]);

  // Resolve once. Success flips `isAuthenticated`; an already-authenticated replay is
  // true on entry; the timeout covers a silent lost session; and a failed exchange
  // (`error`) is recoverable, not fatal. The popular auto-callback providers
  // (react-oidc-context, @auth0/auth0-react) put a callback failure into state and
  // never throw during render, so a stale/replayed `/callback` — state mismatch, spent
  // code, lost sign-in session — can't crash the app. We mirror that: report it and
  // return to the app (the user lands logged-out and can start sign-in again).
  // Idempotent via the ref so overlapping signals don't double-fire.
  const resolved = useRef(false);
  useEffect(() => {
    if (resolved.current) return;
    if (
      callbackResolved({ isAuthenticated, timedOut, errored: error != null })
    ) {
      if (error) {
        reportAuthError(
          onAuthError,
          new Error(
            `completing Logto sign-in failed (${error.message}). The callback URL ` +
              `was likely stale or the sign-in session was lost — start sign-in again.`,
            { cause: error },
          ),
        );
      }
      resolved.current = true;
      onDone();
      goAfterSignIn();
    }
  }, [error, isAuthenticated, timedOut, onDone, goAfterSignIn, onAuthError]);

  return null;
}

type ConfigState =
  | { status: "loading" }
  | { status: "ready"; config: LogtoPublicConfig }
  | { status: "error"; error: unknown };

type CommonProviderProps = {
  /** Your `ConvexReactClient`. */
  client: ConvexReactClient;
  /** Extra scopes. `openid`, `profile`, `offline_access`, and `email` are always included. */
  scopes?: string[];
  /** API resource indicators to request, if any. */
  resources?: string[];
  /** Where to go once sign-in completes. Default `/`. `signIn({ returnTo })` overrides it. */
  afterSignIn?: string;
  /**
   * Soft navigation (e.g. your router's navigate). Optional for plain Vite;
   * recommended for any router (TanStack/Next) so post-sign-in is a soft nav,
   * not a full reload that drops router state. Prefer a replace-style navigate
   * so the spent callback URL doesn't stay in history. Falls back to a hard
   * `location.replace`.
   */
  navigate?: (to: string) => void;
  /**
   * The route that finishes the OIDC redirect. Default `/callback`. Must match
   * the path of a **Redirect URI** registered on the Logto app; sign-in
   * redirects there, and only that exact path runs callback handling.
   */
  callbackPath?: string;
  /**
   * Called when starting or finishing sign-in — or signing out — fails
   * recoverably (Logto unreachable, blocked storage, a stale/replayed callback,
   * or a setup error like `invalid_scope`). Failures are reported here and
   * logged to the console; the ones `@logto/react` swallows into its own state
   * would otherwise be invisible, and the ones it doesn't are reported *before*
   * the promise rejects, so a fire-and-forget caller still wants a
   * `.catch(() => {})` to avoid an unhandled rejection. A failed sign-out
   * matters as much as a failed sign-in — the SDK leaves the tokens in place,
   * so the user is still signed in.
   */
  onAuthError?: (error: Error) => void;
  /**
   * Cache Logto's OIDC discovery + JWKS responses in sessionStorage (via
   * `@logto/react`'s `unstable_enableCache`), so the sign-in page and the
   * callback page don't each pay a discovery round-trip. Default `true`.
   */
  discoveryCache?: boolean;
  /**
   * Rendered while `configQuery` loads (that mode only — with static `config`
   * there is no loading phase). Children mount once, when config is ready.
   * Default `null`.
   */
  fallback?: ReactNode;
  /**
   * Opt-in phase timings for the auth bootstrap: `bootstrap_start`,
   * `convex_authenticated` — the point where the first authenticated query can
   * run — and, in `configQuery` mode only, `config_loaded` for that one fetch.
   * Absent means nothing is measured. Events carry no token and no user
   * identity.
   */
  onAuthEvent?: LogtoAuthEventHandler;
  children: ReactNode;
};

export type ConvexLogtoProviderProps = CommonProviderProps &
  (
    | {
        /**
         * Your Logto public config, statically: `{ endpoint, appId,
         * allowInsecureHttp? }`. Both OAuth values are public (the client id is
         * not a secret). Non-loopback HTTP requires that explicit opt-in; HTTPS
         * is the default. This is the fastest path: no config round-trip.
         */
        config: LogtoPublicConfig;
        configQuery?: never;
      }
    | {
        config?: never;
        /**
         * Reference to the query exported from `logtoConfigQuery()`, e.g.
         * `api.logto.config` — fetches `{ endpoint, appId }` from the Convex
         * deployment at runtime. Prefer static `config` unless you need
         * runtime-resolved config (multi-tenant, shared frontend artifacts).
         */
        configQuery: LogtoConfigQueryRef;
      }
  );

/**
 * Wires Logto to Convex: mounts Logto with your public config, bridges the ID
 * token into Convex, and finishes the sign-in redirect on `callbackPath`.
 * No hand-rolled `useAuth`, no JWT template, no JWKS URL.
 *
 * Safe to render on the server: nothing touches `window` during render, so SSR
 * frameworks need no stub or mount-gate. The redirect lands on `/callback` — add
 * a route there that just renders; set `callbackPath` to use another path.
 *
 * @example
 * <ConvexLogtoProvider
 *   client={convex}
 *   config={{
 *     endpoint: import.meta.env.VITE_LOGTO_ENDPOINT,
 *     appId: import.meta.env.VITE_LOGTO_APP_ID,
 *   }}
 * >
 *   <App />
 * </ConvexLogtoProvider>
 */
export function ConvexLogtoProvider(props: ConvexLogtoProviderProps) {
  const {
    client,
    scopes,
    resources,
    afterSignIn = "/",
    navigate,
    callbackPath = DEFAULT_CALLBACK_PATH,
    onAuthError,
    discoveryCache = true,
    fallback = null,
    onAuthEvent,
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
  // configQuery mode. Until it lands we render `fallback`; children mount once.
  const [fetched, setFetched] = useState<ConfigState>({ status: "loading" });

  useEffect(() => {
    if (!configQuery) return undefined;
    let active = true;
    // Don't reset to "loading" on re-run: once resolved, demoting back would
    // unmount the live Logto tree mid-session and drop the identity.
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

  // Key the memo on scalar contents, not object identity, so a fresh `config`/
  // `scopes`/`resources` value each render doesn't rebuild the LogtoClient.
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
  const onAuthErrorRef = useRef(onAuthError);
  useEffect(() => {
    onAuthErrorRef.current = onAuthError;
  }, [onAuthError]);
  const signInErrorState = useRef<{
    latestAttempt: BridgeAuthAttempt | undefined;
  }>({ latestAttempt: undefined });
  const authErrors = useMemo<BridgeAuthErrors>(() => {
    return {
      begin: (baselineError) => {
        const attempt = { baselineError, handled: false };
        signInErrorState.current.latestAttempt = attempt;
        return attempt;
      },
      fail: (attempt, error) => {
        if (attempt.handled) return;
        attempt.handled = true;
        reportAuthError(onAuthErrorRef.current, error);
      },
      observe: (error) => {
        const attempt = signInErrorState.current.latestAttempt;
        if (
          attempt === undefined ||
          attempt.handled ||
          error === undefined ||
          error === attempt.baselineError
        ) {
          return;
        }
        attempt.handled = true;
        reportAuthError(onAuthErrorRef.current, error);
      },
    };
  }, []);
  // Captured once, at mount: a real OIDC redirect always lands as a full-page
  // load, so mount == landing. Ending it is a state change, which is what makes
  // both the loading veto and the error observer below react to the callback
  // finishing even in an app whose provider never re-renders on navigation.
  const [callbackActive, setCallbackActive] = useState(() =>
    onCallbackRoute(callbackPath),
  );
  const endCallbackFlow = useCallback(() => setCallbackActive(false), []);
  const bridgeValue = useMemo(
    () => ({ callbackPath, authErrors, callbackActive }),
    [callbackPath, authErrors, callbackActive],
  );

  if (configQuery && fetched.status === "error") {
    // A missing/broken config query is a setup error: throw so an error
    // boundary / dev overlay shows it, instead of a blank screen.
    throw new Error(
      "convex-logto: could not load Logto config from configQuery. Check the query " +
        "is deployed and LOGTO_ENDPOINT / LOGTO_APP_ID are set on the Convex deployment.",
      { cause: fetched.error },
    );
  }

  if (!resolved) return <>{fallback}</>;

  return (
    <BridgeContext.Provider value={bridgeValue}>
      <LogtoProvider config={logtoConfig} unstable_enableCache={discoveryCache}>
        {/* @logto/react catches signIn failures into context and resolves its
            public promise. Observe that state only on the initiating page;
            callback errors are already handled by LogtoCallback below. */}
        {!callbackActive ? (
          <LogtoAuthErrorObserver authErrors={authErrors} />
        ) : null}
        {/* Callback handling is gated to the exact callback route: a real OIDC
            redirect always lands as a full-page load, so mount == landing. */}
        {callbackActive ? (
          <LogtoCallback
            afterSignIn={afterSignIn}
            navigate={navigate}
            onAuthError={onAuthError}
            onResolved={endCallbackFlow}
          />
        ) : null}
        {/* oxlint-disable-next-line react/hooks -- `useAuth` is a prop that takes a hook; that is Convex's API. */}
        <ConvexProviderWithAuth client={client} useAuth={useAuthFromLogto}>
          <ConvexAuthPhaseWatcher events={events} />
          {children}
        </ConvexProviderWithAuth>
      </LogtoProvider>
    </BridgeContext.Provider>
  );
}

export type LogtoAuth = {
  isAuthenticated: boolean;
  isLoading: boolean;
  /**
   * Decoded ID token claims (sub, email, name, ...), once authenticated.
   * Display only — a Convex function reads the same claims through
   * `ctx.auth.getUserIdentity()`, which is where they are trustworthy.
   */
  user: LogtoUserClaims | undefined;
  /**
   * Start sign-in. Redirects to Logto and back to the provider's `callbackPath`.
   * `returnTo` (a same-origin path starting with `/`) is where the user lands
   * after sign-in completes; it overrides the provider's `afterSignIn`.
   * Initiation failures are always sent to the provider's `onAuthError`, even
   * when the caller deliberately discards this promise with `void signIn()`.
   */
  signIn: (options?: { returnTo?: string }) => Promise<void>;
  /**
   * Sign out: ends the Logto session, then returns to `window.location.origin`,
   * which you must register as a **Post sign-out redirect URI** (exact match, no
   * trailing slash). Pass another registered URI to land elsewhere.
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
  const { signIn, signOut, getIdTokenClaims, error } = useLogto();
  const { callbackPath, authErrors } = useContext(BridgeContext);
  const [user, setUser] = useState<LogtoUserClaims>();

  useEffect(() => {
    let active = true;
    if (isAuthenticated) {
      // The SDK documents undefined on failure; still contain an unexpected
      // rejection so a third-party regression cannot become unhandled.
      void getIdTokenClaims()
        // Narrowed through the same gate session mode uses, so both modes hand
        // back one type: the SDK's `IdTokenClaims` is an interface and carries
        // no index signature, which is exactly what makes a custom claim
        // unreachable in bridge mode today.
        .then((claims) => {
          if (active) setUser(asUserClaims(claims));
        })
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
    async (options?: { returnTo?: string }) => {
      const attempt = authErrors.begin(error);
      try {
        const returnTo = options?.returnTo;
        if (returnTo !== undefined) {
          if (!isSafeReturnTo(returnTo)) {
            throw new Error(
              `convex-logto: signIn returnTo must be a same-origin path starting with "/" ` +
                `(got "${returnTo}") — full URLs and protocol-relative paths are rejected ` +
                `to prevent open redirects.`,
            );
          }
          stashReturnTo(returnTo);
        }
        await signIn(`${window.location.origin}${callbackPath}`);
      } catch (caught) {
        const failure = asAuthError(
          caught,
          "convex-logto: starting Logto sign-in failed.",
        );
        authErrors.fail(attempt, failure);
        throw failure;
      }
    },
    [signIn, callbackPath, error, authErrors],
  );
  // Federated sign-out: ends the SSO session (so the next sign-in isn't silent),
  // then returns to origin — which must be a registered Post sign-out redirect URI.
  const doSignOut = useCallback(
    async (options?: { postLogoutRedirectUri?: string }) => {
      // Sign-out is swallowed the same way sign-in is: `@logto/react` catches
      // the failure into its own state and resolves this promise. Worse, the
      // SDK reaches OIDC discovery *before* clearing tokens, so an unreachable
      // Logto leaves the user signed in with a live token while the button
      // appears to have worked. Register the attempt so the observer reports
      // whatever the SDK stored.
      const attempt = authErrors.begin(error);
      try {
        await signOut(options?.postLogoutRedirectUri ?? window.location.origin);
      } catch (caught) {
        const failure = asAuthError(
          caught,
          "convex-logto: Logto sign-out failed.",
        );
        authErrors.fail(attempt, failure);
        throw failure;
      }
    },
    [signOut, error, authErrors],
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
