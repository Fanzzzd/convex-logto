// The framework-free half of session mode's client: storage, the auth state
// machine, and the refresh pipeline. `react-session.tsx` is thin React glue
// over this. No Logto SDK — the server (component) owns all OIDC traffic.

import type { FunctionReference } from "convex/server";
import { ConvexError } from "convex/values";
import { classifySignInSearch, isSafeReturnTo } from "./callback";
import {
  SessionDeviceBindingError,
  type SessionDeviceBinding,
} from "./session-device";
import type { LogtoSessionApi } from "./session";

/** Where the short-lived ID token persists. The session token is always localStorage. */
export type TokenStorageKind = "session" | "memory" | "local";

/** Serve a cached ID token only if it has at least this much life left. */
const ID_TOKEN_SKEW_MS = 30 * 1000;

/** Backoff between retries of a transiently-failing action call. */
const RETRY_DELAYS_MS = [500, 2000];

export type SessionSnapshot = {
  status: "restoring" | "authenticated" | "unauthenticated";
  sessionId: string | null;
  /** Decoded ID token claims (display only — verification is Convex's job). */
  user: Record<string, unknown> | undefined;
};

/** Structural slice of `ConvexReactClient` the engine needs — stubbed in tests. */
export type SessionTransport = {
  action<Action extends FunctionReference<"action">>(
    action: Action,
    args: Action["_args"],
  ): Promise<Action["_returnType"]>;
};

/** Storage contract used by the shared web/native session state machine. */
export type SessionStorageAdapter = {
  /** Async stores hydrate their synchronous cache here before the engine reads it. */
  prepare?(): Promise<void>;
  /** Wait for queued durable writes; browser storage writes synchronously. */
  flush?(): Promise<void>;
  readonly sessionEventKey: string;
  readSession(): StoredSession | null;
  writeSession(session: StoredSession): void;
  readIdToken(): string | null;
  writeIdToken(idToken: string): void;
  stashTransaction(transaction: StoredTransaction): void;
  takeTransaction(): StoredTransaction | null;
  clearAll(): void;
  clearIdToken(): void;
};

/** Native system-browser seam. Absent means the existing browser redirect flow. */
export type SessionAuthFlow = {
  redirectUri: string;
  /** Return the successful deep-link URL, or null when the user cancels. */
  openAuthorization(url: string): Promise<string | null>;
  /** Best-effort federated sign-out in the system browser. */
  openEndSession(url: string, returnUrl: string): Promise<void>;
};

export type SessionSignOutServerStatus =
  | "revoked"
  | "revocation_failed"
  | "not_present";

/** Durable credential cleanup failed twice during an explicit sign-out. */
export class SessionSignOutError extends Error {
  readonly code:
    | "local_cleanup_failed"
    | "local_cleanup_and_server_revocation_failed";

  constructor(
    readonly serverSessionStatus: SessionSignOutServerStatus,
    cause?: unknown,
  ) {
    const revocationAlsoFailed = serverSessionStatus === "revocation_failed";
    super(
      revocationAlsoFailed
        ? "convex-logto: sign-out did not complete because SecureStore cleanup and server revocation both failed."
        : serverSessionStatus === "revoked"
          ? "convex-logto: the server session was revoked, but local credentials could not be wiped from SecureStore."
          : "convex-logto: local credentials could not be wiped from SecureStore.",
      cause === undefined ? undefined : { cause },
    );
    this.name = "SessionSignOutError";
    this.code = revocationAlsoFailed
      ? "local_cleanup_and_server_revocation_failed"
      : "local_cleanup_failed";
  }
}

export function decodeJwtPayload(
  token: string,
): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function idTokenExpMs(token: string): number {
  const exp = decodeJwtPayload(token)?.exp;
  return typeof exp === "number" ? exp * 1000 : 0;
}

/** Terminal ends the session on the client; anything else is retried and never treated as a sign-out. */
export function sessionErrorKind(error: unknown): "terminal" | "transient" {
  if (error instanceof ConvexError) {
    const kind = (error.data as { kind?: unknown } | undefined | null)?.kind;
    if (kind === "terminal") return "terminal";
  }
  return "transient";
}

// --- storage -----------------------------------------------------------------

export type StoredSession = { token: string; sessionId: string };
type StoredTransaction = { state: string };

/**
 * Namespaced browser storage for the three session-mode artifacts:
 *
 * - session token + id (**localStorage**, fixed): shared across tabs and
 *   restarts. Safe there because it's one-time — every use rotates it, the
 *   server stores only its hash, and reuse outside the window kills the session.
 * - ID token (sessionStorage by default): per-tab short bearer; an unexpired
 *   one makes reload a zero-round-trip authenticate.
 * - sign-in transaction stash (sessionStorage, fixed): binds the OIDC `state`
 *   to the tab that started sign-in, so a foreign callback (login CSRF) is
 *   refused client-side.
 *
 * Falls back to per-instance memory when storage throws (private mode, quota),
 * keeping the flow alive within the tab.
 */
export class SessionStorageArea {
  private memory = new Map<string, string>();

  constructor(
    private namespace: string,
    private tokenStorage: TokenStorageKind,
  ) {}

  private key(name: string): string {
    return `convex-logto:${this.namespace}:${name}`;
  }

  private area(
    kind: "local" | "session" | "memory",
  ): Pick<Storage, "getItem" | "setItem" | "removeItem"> {
    if (kind !== "memory" && typeof window !== "undefined") {
      try {
        const area =
          kind === "local" ? window.localStorage : window.sessionStorage;
        // Accessing the getter can itself throw (sandboxed iframes).
        area.getItem(this.key("probe"));
        return area;
      } catch {
        // fall through to memory
      }
    }
    const memory = this.memory;
    return {
      getItem: (k) => memory.get(k) ?? null,
      setItem: (k, value) => void memory.set(k, value),
      removeItem: (k) => void memory.delete(k),
    };
  }

  private read<T>(
    kind: "local" | "session" | "memory",
    name: string,
  ): T | null {
    try {
      const raw = this.area(kind).getItem(this.key(name));
      return raw === null ? null : (JSON.parse(raw) as T);
    } catch {
      return null;
    }
  }

  private write(
    kind: "local" | "session" | "memory",
    name: string,
    value: unknown,
  ): void {
    try {
      this.area(kind).setItem(this.key(name), JSON.stringify(value));
    } catch {
      // Quota/private mode: memory fallback handled by area(); a throwing set is dropped.
    }
  }

  private remove(kind: "local" | "session" | "memory", name: string): void {
    try {
      this.area(kind).removeItem(this.key(name));
    } catch {
      // ignore
    }
  }

  /** The localStorage key session writes land on — for `storage` event filtering. */
  get sessionEventKey(): string {
    return this.key("session");
  }

  readSession(): StoredSession | null {
    const value = this.read<StoredSession>("local", "session");
    return value &&
      typeof value.token === "string" &&
      typeof value.sessionId === "string"
      ? value
      : null;
  }

  writeSession(session: StoredSession): void {
    this.write("local", "session", session);
  }

  readIdToken(): string | null {
    return this.read<string>(this.tokenStorage, "idToken");
  }

  writeIdToken(idToken: string): void {
    this.write(this.tokenStorage, "idToken", idToken);
  }

  stashTransaction(transaction: StoredTransaction): void {
    this.write("session", "txn", transaction);
  }

  takeTransaction(): StoredTransaction | null {
    const value = this.read<StoredTransaction>("session", "txn");
    this.remove("session", "txn");
    return value && typeof value.state === "string" ? value : null;
  }

  clearAll(): void {
    this.remove("local", "session");
    this.remove(this.tokenStorage, "idToken");
    this.remove("session", "txn");
  }

  /** Clear only this tab's bearer — for reacting to a sign-out from another tab. */
  clearIdToken(): void {
    this.remove(this.tokenStorage, "idToken");
  }
}

// --- the engine --------------------------------------------------------------

export type SessionEngineOptions = {
  transport: SessionTransport;
  api: LogtoSessionApi;
  storage: SessionStorageAdapter;
  callbackPath: string;
  afterSignIn: string;
  /** Fresh SSR-seeded ID token. */
  initialToken?: string;
  /** Session marker paired with `initialToken` (cookie transport uses a sentinel). */
  initialSession?: StoredSession;
  /** Opt-in proof-of-possession key; absent keeps the legacy unbound flow. */
  deviceBinding?: SessionDeviceBinding;
  /** Replace-style navigation; falls back to `location.replace`. */
  navigate?: (to: string) => void;
  /** Native system-browser/deep-link flow; absent preserves the web flow. */
  authFlow?: SessionAuthFlow;
  onAuthError?: (error: Error) => void;
  /** Injectable for tests. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
};

const SERVER_SNAPSHOT: SessionSnapshot = {
  status: "restoring",
  sessionId: null,
  user: undefined,
};

/**
 * The session-mode auth state machine. One instance per provider mount; framework-free.
 *
 * ```
 * mount
 *  ├─ on callbackPath with ?code&state → restoring: exchange → authenticated
 *  ├─ stored ID token still fresh      → authenticated (zero round-trips)
 *  ├─ stored session token             → restoring: refresh → authenticated | unauthenticated
 *  └─ nothing                          → unauthenticated
 * ```
 *
 * Transitions are one-way per mount — no isLoading churn by construction.
 */
export class SessionAuthEngine {
  private snapshot: SessionSnapshot;
  private serverSnapshot: SessionSnapshot;
  private listeners = new Set<() => void>();
  private started = false;
  private inflightSignIn: Promise<void> | null = null;
  private inflightRefresh: Promise<string | null> | null = null;
  private storagePreparation: Promise<void> | null = null;
  /** The last ID token handed to Convex — a forced fetch must never re-serve it. */
  private lastServed: string | null = null;
  private now: () => number;
  private sleep: (ms: number) => Promise<void>;

  constructor(private options: SessionEngineOptions) {
    this.now = options.now ?? (() => Date.now());
    this.sleep =
      options.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    if (options.initialSession) {
      options.storage.writeSession(options.initialSession);
    }
    if (options.initialToken) {
      options.storage.writeIdToken(options.initialToken);
      this.snapshot = {
        status: "authenticated",
        sessionId: options.initialSession?.sessionId ?? null,
        user: decodeJwtPayload(options.initialToken) ?? undefined,
      };
    } else {
      this.snapshot = SERVER_SNAPSHOT;
    }
    // React's hydration snapshot must match what the server rendered even if
    // the live client state changes before hydration finishes.
    this.serverSnapshot = this.snapshot;
  }

  /** The localStorage key cross-tab sign-outs land on — for `storage` event filtering. */
  get sessionEventKey(): string {
    return this.options.storage.sessionEventKey;
  }

  // -- external-store surface --

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getSnapshot = (): SessionSnapshot => this.snapshot;

  getServerSnapshot = (): SessionSnapshot => this.serverSnapshot;

  private setSnapshot(next: SessionSnapshot): void {
    this.snapshot = next;
    for (const listener of [...this.listeners]) listener();
  }

  private setAuthenticated(idToken: string): void {
    this.setSnapshot({
      status: "authenticated",
      sessionId: this.options.storage.readSession()?.sessionId ?? null,
      user: decodeJwtPayload(idToken) ?? undefined,
    });
  }

  private setUnauthenticated(): void {
    this.setSnapshot({
      status: "unauthenticated",
      sessionId: null,
      user: undefined,
    });
  }

  // -- mount --

  /** Run the mount state machine. Idempotent (StrictMode double-effects). */
  start(): void {
    if (
      this.started ||
      (this.options.authFlow === undefined && typeof window === "undefined")
    )
      return;
    this.started = true;
    void this.startInner();
  }

  private async startInner(): Promise<void> {
    try {
      await this.prepareStorage();
      await this.options.deviceBinding?.prepare();
    } catch (error) {
      this.reportError(this.asError(error));
      this.setUnauthenticated();
      return;
    }
    if (this.options.authFlow !== undefined) {
      await this.restore();
      return;
    }
    const onCallback = window.location.pathname === this.options.callbackPath;
    const outcome = onCallback
      ? classifySignInSearch(window.location.search)
      : ({ kind: "none" } as const);
    if (outcome.kind === "pending") {
      await this.completeCallback(
        new URLSearchParams(window.location.search),
        `${window.location.origin}${this.options.callbackPath}`,
      );
      return;
    }
    if (outcome.kind === "error") {
      this.reportError(new Error(outcome.message));
    }
    await this.restore();
    // A benign/errored callback landing still needs to leave the callback URL.
    if (outcome.kind === "benign" || outcome.kind === "error") {
      this.navigateReplace(this.options.afterSignIn);
    }
  }

  private async completeCallback(
    params: URLSearchParams,
    redirectUri: string,
  ): Promise<void> {
    const code = params.get("code") ?? "";
    const state = params.get("state") ?? "";
    // Login-CSRF binding: only the browser tab that started this sign-in holds
    // the matching stash. A foreign (attacker-initiated) or replayed callback
    // is refused without ever calling the exchange.
    const transaction = this.options.storage.takeTransaction();
    await this.flushStorageReporting();
    if (!transaction || transaction.state !== state) {
      this.reportError(
        new Error(
          "convex-logto: this sign-in callback doesn't match a sign-in started in this " +
            "browser tab — refusing to complete it. (A replayed/forged callback URL, or " +
            "sessionStorage was cleared mid-sign-in.)",
        ),
      );
      await this.restore();
      this.navigateReplace(this.options.afterSignIn);
      return;
    }
    try {
      const devicePublicKey = await this.options.deviceBinding?.getPublicKey();
      const result = await this.retrying(() =>
        this.options.transport.action(this.options.api.callback, {
          code,
          state,
          redirectUri,
          ...(devicePublicKey === undefined ? {} : { devicePublicKey }),
        }),
      );
      this.options.storage.writeSession({
        token: result.sessionToken,
        sessionId: result.sessionId,
      });
      this.options.storage.writeIdToken(result.idToken);
      await this.flushStorage();
      this.lastServed = null;
      this.setAuthenticated(result.idToken);
      const destination =
        result.returnTo !== undefined && isSafeReturnTo(result.returnTo)
          ? result.returnTo
          : this.options.afterSignIn;
      this.navigateReplace(destination);
    } catch (error) {
      this.reportError(
        error instanceof Error
          ? error
          : new Error("convex-logto: completing sign-in failed.", {
              cause: error,
            }),
      );
      // The transaction is spent or Logto is down; land back in the app. If a
      // previous session survives in storage, restore() picks it up.
      await this.restore();
      this.navigateReplace(this.options.afterSignIn);
    }
  }

  private async restore(): Promise<void> {
    const cached = this.options.storage.readIdToken();
    if (cached !== null && this.isFresh(cached)) {
      const session = this.options.storage.readSession();
      if (session?.sessionId !== "") {
        this.setAuthenticated(cached);
        return;
      }
      // Cookie mode can know that a session exists before SSR or a rotation has
      // supplied its stable id. Recover it now instead of authenticating with
      // reactive revocation silently disabled. Mark the cached token
      // unacceptable so refreshIdToken actually presents the cookie.
      const recovered = await this.refreshIdToken(cached);
      if (recovered !== null) {
        this.setAuthenticated(recovered);
        return;
      }
      // A transient refresh keeps storage intact: use the still-fresh cached
      // token as a degraded fallback. Terminal failures already cleared it.
      if (this.options.storage.readSession() !== null) {
        this.setAuthenticated(cached);
        return;
      }
    }
    if (this.options.storage.readSession() !== null) {
      const idToken = await this.refreshIdToken(null);
      if (idToken !== null) {
        this.setAuthenticated(idToken);
        return;
      }
    }
    // refreshIdToken already flipped state on terminal; make the transient/no-session
    // paths land unauthenticated too.
    if (this.snapshot.status !== "authenticated") this.setUnauthenticated();
  }

  // -- Convex auth bridge --

  /** The `fetchAccessToken` half of `ConvexProviderWithAuth`'s `useAuth` contract. */
  async fetchAccessToken(forceRefreshToken: boolean): Promise<string | null> {
    try {
      await this.prepareStorage();
    } catch (error) {
      this.reportError(this.asError(error));
      this.setUnauthenticated();
      return null;
    }
    const cached = this.options.storage.readIdToken();
    if (!forceRefreshToken && cached !== null && this.isFresh(cached)) {
      this.lastServed = cached;
      return cached;
    }
    // Forced means Convex found the current token expiring/rejected — a token
    // another tab just rotated in satisfies it, the one we last served can't.
    const token = await this.refreshIdToken(
      forceRefreshToken ? this.lastServed : null,
    );
    if (token !== null) {
      this.lastServed = token;
      if (this.snapshot.status !== "authenticated")
        this.setAuthenticated(token);
    }
    return token;
  }

  /**
   * Rotate: session token → fresh ID token (+ next session token). Single-flight
   * per tab (in-flight merge) and per browser (Web Locks): concurrent refreshes
   * at Logto's ≥70%-TTL rotation boundary would replay the refresh token and
   * destroy the grant. `unacceptable` is an ID token that must NOT be served
   * from cache (the one Convex just rejected).
   */
  private refreshIdToken(unacceptable: string | null): Promise<string | null> {
    if (this.inflightRefresh) return this.inflightRefresh;
    const run = async (): Promise<string | null> => {
      // Re-read inside the lock: another tab may have rotated while we queued.
      const cached = this.options.storage.readIdToken();
      if (cached !== null && this.isFresh(cached) && cached !== unacceptable) {
        return cached;
      }
      const session = this.options.storage.readSession();
      if (session === null) {
        if (this.snapshot.status !== "unauthenticated")
          this.setUnauthenticated();
        return null;
      }
      let deviceProof: string | undefined;
      try {
        deviceProof = await this.options.deviceBinding?.sign(session.token);
      } catch (error) {
        this.reportError(this.asError(error));
        return null;
      }
      try {
        const result = await this.retrying(() =>
          this.options.transport.action(this.options.api.refresh, {
            sessionToken: session.token,
            ...(deviceProof === undefined ? {} : { deviceProof }),
          }),
        );
        this.options.storage.writeSession({
          token: result.sessionToken,
          sessionId: result.sessionId,
        });
        this.options.storage.writeIdToken(result.idToken);
        await this.flushStorageReporting();
        return result.idToken;
      } catch (error) {
        if (sessionErrorKind(error) === "terminal") {
          // Signed out / revoked / reuse-killed: the session is gone for good.
          this.options.storage.clearAll();
          this.setUnauthenticated();
        }
        // Transient (Logto/Convex unreachable): keep the session token — the
        // next fetch after the network heals refreshes cleanly. Never a sign-out.
        return null;
      }
    };
    this.inflightRefresh = this.withLock(run).finally(() => {
      this.inflightRefresh = null;
    });
    return this.inflightRefresh;
  }

  // -- user actions --

  signIn(options?: { returnTo?: string }): Promise<void> {
    // Expo can only host one system-browser auth session at a time, and native
    // storage intentionally has one OAuth transaction slot. Share the entire
    // flow so a double-tap cannot overwrite its own login-CSRF state. The web
    // redirect path remains independent and unchanged.
    if (this.options.authFlow === undefined) return this.signInInner(options);
    if (this.inflightSignIn !== null) return this.inflightSignIn;
    this.inflightSignIn = this.signInInner(options).finally(() => {
      this.inflightSignIn = null;
    });
    return this.inflightSignIn;
  }

  private async signInInner(options?: { returnTo?: string }): Promise<void> {
    const returnTo = options?.returnTo;
    if (returnTo !== undefined && !isSafeReturnTo(returnTo)) {
      throw new Error(
        `convex-logto: signIn returnTo must be a same-origin path starting with "/" ` +
          `(got "${returnTo}") — full URLs and protocol-relative paths are rejected ` +
          `to prevent open redirects.`,
      );
    }
    try {
      await this.prepareStorage();
      await this.options.deviceBinding?.prepare();
    } catch (error) {
      const normalizedError = this.asError(error);
      this.reportError(normalizedError);
      throw normalizedError;
    }
    const redirectUri =
      this.options.authFlow?.redirectUri ??
      `${window.location.origin}${this.options.callbackPath}`;
    const { url } = await this.options.transport.action(
      this.options.api.signIn,
      {
        redirectUri,
        returnTo,
      },
    );
    // Bind the transaction to this tab (see completeCallback).
    // Always spend an abandoned state before considering the new authorize
    // URL: if Logto ever omits `state`, an old deep link must not match it.
    this.options.storage.takeTransaction();
    const state = new URL(url).searchParams.get("state");
    if (state !== null) this.options.storage.stashTransaction({ state });
    await this.flushStorageReporting();
    const authFlow = this.options.authFlow;
    if (authFlow === undefined) {
      window.location.assign(url);
      return;
    }

    let callbackUrl: string | null;
    try {
      callbackUrl = await authFlow.openAuthorization(url);
    } catch (error) {
      this.options.storage.takeTransaction();
      await this.flushStorageReporting();
      const normalizedError = this.asError(error);
      this.reportError(normalizedError);
      throw normalizedError;
    }
    if (callbackUrl === null) {
      // A cancelled browser session must not leave an OIDC state value that a
      // later deep link could replay against.
      this.options.storage.takeTransaction();
      await this.flushStorageReporting();
      return;
    }
    await this.completeSignIn(callbackUrl, redirectUri);
  }

  /** Complete a native system-browser return. Public for deep-link adapters/tests. */
  async completeSignIn(
    callbackUrl: string,
    redirectUri: string,
  ): Promise<void> {
    let url: URL;
    try {
      url = new URL(callbackUrl);
    } catch (error) {
      this.options.storage.takeTransaction();
      await this.flushStorageReporting();
      this.reportError(
        new Error("convex-logto: the native sign-in return URL is invalid.", {
          cause: error,
        }),
      );
      await this.restore();
      this.navigateReplace(this.options.afterSignIn);
      return;
    }
    const outcome = classifySignInSearch(url.search);
    if (outcome.kind === "pending") {
      await this.completeCallback(url.searchParams, redirectUri);
      return;
    }

    // A returned browser session spends the state even when Logto returned an
    // OAuth error or a malformed callback. This keeps the login-CSRF binding
    // single-use on native, where there is no callback route to revisit.
    this.options.storage.takeTransaction();
    await this.flushStorageReporting();
    this.reportError(
      new Error(
        outcome.kind === "error"
          ? outcome.message
          : "convex-logto: the native sign-in return did not include an authorization code and state.",
      ),
    );
    await this.restore();
    this.navigateReplace(this.options.afterSignIn);
  }

  async signOut(options?: {
    postLogoutRedirectUri?: string;
    federated?: boolean;
  }): Promise<void> {
    try {
      await this.prepareStorage();
    } catch (error) {
      const normalizedError = this.asError(error);
      this.reportError(normalizedError);
      // A broken async store must not trap the live React tree in an
      // authenticated snapshot. Queue deletion where the adapter still can,
      // then preserve the storage failure signal for the caller.
      this.lastServed = null;
      this.setUnauthenticated();
      try {
        this.options.storage.clearAll();
      } catch (clearError) {
        this.reportError(this.asError(clearError));
      }
      throw normalizedError;
    }
    const session = this.options.storage.readSession();
    // Clear before the network call: sign-out must not be blockable by a dead
    // Logto. The localStorage removal kicks other tabs via the storage event.
    this.options.storage.clearAll();
    this.lastServed = null;
    this.setUnauthenticated();
    let durableCleanupFailed = false;
    try {
      await this.flushStorage();
    } catch (error) {
      // Still attempt server revocation when durable local cleanup fails; a
      // second cleanup failure becomes a loud error after that independent try.
      durableCleanupFailed = true;
      this.reportError(this.asError(error));
    }
    let postLogoutRedirectUri: string | undefined;
    let endSessionUrl: string | undefined;
    let serverSessionStatus: SessionSignOutServerStatus =
      session === null ? "not_present" : "revocation_failed";
    let serverRevocationError: unknown;
    if (session !== null) {
      postLogoutRedirectUri =
        options?.postLogoutRedirectUri ??
        this.options.authFlow?.redirectUri ??
        window.location.origin;
      try {
        ({ endSessionUrl } = await this.options.transport.action(
          this.options.api.signOut,
          {
            sessionToken: session.token,
            postLogoutRedirectUri,
          },
        ));
        serverSessionStatus = "revoked";
      } catch (error) {
        serverRevocationError = error;
        // Best effort when local cleanup succeeded; a combined failure is
        // converted into a loud SessionSignOutError below.
      }
    }
    let signOutError: SessionSignOutError | undefined;
    if (durableCleanupFailed) {
      // SecureStore failures can be transient (for example, a temporarily
      // unavailable keystore). Retry once after the independent server kill.
      this.options.storage.clearAll();
      try {
        await this.flushStorage();
      } catch (error) {
        const durableCleanupError = this.asError(error);
        this.reportError(durableCleanupError);
        signOutError = new SessionSignOutError(serverSessionStatus, {
          durableCleanupError,
          ...(serverRevocationError === undefined
            ? {}
            : { serverRevocationError }),
        });
        this.reportError(signOutError);
      }
    }
    // Federated by default: also end Logto's SSO session so the next sign-in
    // isn't silent. The post sign-out redirect URI must be registered on the app.
    if (options?.federated !== false && endSessionUrl !== undefined) {
      if (
        this.options.authFlow !== undefined &&
        postLogoutRedirectUri !== undefined
      ) {
        try {
          await this.options.authFlow.openEndSession(
            endSessionUrl,
            postLogoutRedirectUri,
          );
        } catch (error) {
          this.reportError(this.asError(error));
        }
      } else {
        window.location.assign(endSessionUrl);
      }
    }
    if (signOutError !== undefined) throw signOutError;
  }

  // -- external events --

  /** Another tab signed out (our localStorage session key was removed). */
  handleExternalSignOut(): void {
    this.options.storage.clearIdToken();
    this.lastServed = null;
    this.setUnauthenticated();
  }

  /** The reactive `sessionValid` subscription pushed `false`: the session was revoked. */
  handleRevoked(): void {
    this.options.storage.clearAll();
    void this.flushStorage().catch((error: unknown) => {
      this.reportError(this.asError(error));
    });
    this.lastServed = null;
    this.setUnauthenticated();
  }

  // -- plumbing --

  private prepareStorage(): Promise<void> {
    if (this.storagePreparation === null) {
      this.storagePreparation = (
        this.options.storage.prepare?.() ?? Promise.resolve()
      ).catch((error: unknown) => {
        this.storagePreparation = null;
        throw error;
      });
    }
    return this.storagePreparation;
  }

  private flushStorage(): Promise<void> {
    return this.options.storage.flush?.() ?? Promise.resolve();
  }

  private async flushStorageReporting(): Promise<void> {
    try {
      await this.flushStorage();
    } catch (error) {
      const normalizedError = this.asError(error);
      this.reportError(normalizedError);
      throw normalizedError;
    }
  }

  private isFresh(idToken: string): boolean {
    return idTokenExpMs(idToken) - ID_TOKEN_SKEW_MS > this.now();
  }

  private async retrying<T>(fn: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await fn();
      } catch (error) {
        if (
          sessionErrorKind(error) === "terminal" ||
          attempt >= RETRY_DELAYS_MS.length
        ) {
          throw error;
        }
        await this.sleep(RETRY_DELAYS_MS[attempt]!);
      }
    }
  }

  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const locks =
      typeof navigator !== "undefined" ? navigator.locks : undefined;
    if (!locks) return fn();
    return locks.request(this.options.storage.sessionEventKey, fn);
  }

  private navigateReplace(to: string): void {
    if (this.options.navigate) this.options.navigate(to);
    else window.location.replace(to);
  }

  private reportError(error: Error): void {
    console.error(error);
    try {
      this.options.onAuthError?.(error);
    } catch {
      // A throwing error handler must not break the auth flow.
    }
  }

  private asError(error: unknown): Error {
    if (error instanceof Error) return error;
    return new SessionDeviceBindingError(
      "convex-logto: device binding failed without an Error value.",
      { cause: error },
    );
  }
}
