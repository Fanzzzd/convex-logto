// The framework-free half of session mode's client: storage, the auth state
// machine, and the refresh pipeline. `react-session.tsx` is thin React glue
// over this. No Logto SDK — the server (component) owns all OIDC traffic.

import type { FunctionReference } from "convex/server";
import { ConvexError } from "convex/values";
import { classifySignInSearch, isSafeReturnTo } from "./callback";
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

type StoredSession = { token: string; sessionId: string };
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
  storage: SessionStorageArea;
  callbackPath: string;
  afterSignIn: string;
  /** Replace-style navigation; falls back to `location.replace`. */
  navigate?: (to: string) => void;
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
  private snapshot: SessionSnapshot = SERVER_SNAPSHOT;
  private listeners = new Set<() => void>();
  private started = false;
  private inflightRefresh: Promise<string | null> | null = null;
  /** The last ID token handed to Convex — a forced fetch must never re-serve it. */
  private lastServed: string | null = null;
  private now: () => number;
  private sleep: (ms: number) => Promise<void>;

  constructor(private options: SessionEngineOptions) {
    this.now = options.now ?? (() => Date.now());
    this.sleep =
      options.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
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

  getServerSnapshot = (): SessionSnapshot => SERVER_SNAPSHOT;

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
    if (this.started || typeof window === "undefined") return;
    this.started = true;
    void this.startInner();
  }

  private async startInner(): Promise<void> {
    const onCallback = window.location.pathname === this.options.callbackPath;
    const outcome = onCallback
      ? classifySignInSearch(window.location.search)
      : ({ kind: "none" } as const);
    if (outcome.kind === "pending") {
      await this.completeCallback();
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

  private async completeCallback(): Promise<void> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code") ?? "";
    const state = params.get("state") ?? "";
    // Login-CSRF binding: only the browser tab that started this sign-in holds
    // the matching stash. A foreign (attacker-initiated) or replayed callback
    // is refused without ever calling the exchange.
    const transaction = this.options.storage.takeTransaction();
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
      const result = await this.retrying(() =>
        this.options.transport.action(this.options.api.callback, {
          code,
          state,
          redirectUri: `${window.location.origin}${this.options.callbackPath}`,
        }),
      );
      this.options.storage.writeSession({
        token: result.sessionToken,
        sessionId: result.sessionId,
      });
      this.options.storage.writeIdToken(result.idToken);
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
      this.setAuthenticated(cached);
      return;
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
      try {
        const result = await this.retrying(() =>
          this.options.transport.action(this.options.api.refresh, {
            sessionToken: session.token,
          }),
        );
        this.options.storage.writeSession({
          token: result.sessionToken,
          sessionId: result.sessionId,
        });
        this.options.storage.writeIdToken(result.idToken);
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

  async signIn(options?: { returnTo?: string }): Promise<void> {
    const returnTo = options?.returnTo;
    if (returnTo !== undefined && !isSafeReturnTo(returnTo)) {
      throw new Error(
        `convex-logto: signIn returnTo must be a same-origin path starting with "/" ` +
          `(got "${returnTo}") — full URLs and protocol-relative paths are rejected ` +
          `to prevent open redirects.`,
      );
    }
    const { url } = await this.options.transport.action(
      this.options.api.signIn,
      {
        redirectUri: `${window.location.origin}${this.options.callbackPath}`,
        returnTo,
      },
    );
    // Bind the transaction to this tab (see completeCallback).
    const state = new URL(url).searchParams.get("state");
    if (state !== null) this.options.storage.stashTransaction({ state });
    window.location.assign(url);
  }

  async signOut(options?: {
    postLogoutRedirectUri?: string;
    federated?: boolean;
  }): Promise<void> {
    const session = this.options.storage.readSession();
    // Clear before the network call: sign-out must not be blockable by a dead
    // Logto. The localStorage removal kicks other tabs via the storage event.
    this.options.storage.clearAll();
    this.lastServed = null;
    this.setUnauthenticated();
    if (session === null) return;
    let endSessionUrl: string | undefined;
    try {
      ({ endSessionUrl } = await this.options.transport.action(
        this.options.api.signOut,
        {
          sessionToken: session.token,
          postLogoutRedirectUri:
            options?.postLogoutRedirectUri ?? window.location.origin,
        },
      ));
    } catch {
      // Best effort: local sign-out already happened; the grant dies at its TTL.
    }
    // Federated by default: also end Logto's SSO session so the next sign-in
    // isn't silent. The post sign-out redirect URI must be registered on the app.
    if (options?.federated !== false && endSessionUrl !== undefined) {
      window.location.assign(endSessionUrl);
    }
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
    this.lastServed = null;
    this.setUnauthenticated();
  }

  // -- plumbing --

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
}
