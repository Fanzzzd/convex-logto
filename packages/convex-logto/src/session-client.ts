// The framework-free half of session mode's client: storage, the auth state
// machine, and the refresh pipeline. `react-session.tsx` is thin React glue
// over this. No Logto SDK — the server (component) owns all OIDC traffic.

import type {
  FunctionArgs,
  FunctionReference,
  FunctionReturnType,
} from "convex/server";
import { ConvexError } from "convex/values";
import {
  createAuthEventEmitter,
  type AuthEventEmitter,
  type LogtoAuthEventSink,
  type LogtoAuthEventSource,
} from "./auth-events";
import { classifySignInSearch, isSafeReturnTo } from "./callback";
import { asUserClaims, type LogtoUserClaims } from "./claims";
import {
  SESSION_LABEL_MAX_LENGTH,
  decodeJwtSegment,
  sessionLabelTooLong,
} from "./component/core";
import { normalizeHttpNavigationUrl } from "./component/endpoint";
import {
  SessionDeviceBindingError,
  type SessionDeviceBinding,
} from "./session-device";
import type {
  LogtoResourceTokenClaims,
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";

/** Where the short-lived ID token persists. The session token is always localStorage. */
export type TokenStorageKind = "session" | "memory" | "local";

/** Serve a cached ID token only if it has at least this much life left. */
const ID_TOKEN_SKEW_MS = 30 * 1000;

/** Backoff between retries of a transiently-failing action call. */
const RETRY_DELAYS_MS = [500, 2000];
/**
 * Backoff for re-presenting a session after a transient refresh failure. The
 * last entry repeats: an outage that outlives the ladder still has to end with
 * the tab signed in, not stranded.
 */
const RECOVERY_DELAYS_MS = [1_000, 2_000, 5_000, 10_000, 30_000];

/** Error objects already surfaced through the public auth-error channel. */
const REPORTED_AUTH_ERRORS = new WeakSet<Error>();

export type SessionSnapshot = {
  status: "restoring" | "authenticated" | "unauthenticated";
  sessionId: string | null;
  /** Decoded ID token claims (display only — verification is Convex's job). */
  user: LogtoUserClaims | undefined;
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
  /** Durability barrier: wait for queued writes. Every engine transition awaits it. */
  flush?(): Promise<void>;
  /**
   * Sign-out only: reject when a credential this area was asked to delete is
   * still in the browser.
   *
   * Deliberately not part of `flush()`. A surviving credential must fail the
   * sign-out that left it behind — and nothing else. Signing in again and
   * refreshing are the two ways a user recovers from a storage fault, and both
   * await the barrier, so folding the check into it locks the page out of its
   * own recovery paths for as long as it lives.
   */
  assertCredentialsRemoved?(): Promise<void>;
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
        ? "convex-logto: sign-out did not complete because local credential cleanup and server revocation both failed."
        : serverSessionStatus === "revoked"
          ? "convex-logto: the server session was revoked, but local credentials could not be durably wiped."
          : "convex-logto: local credentials could not be durably wiped.",
      cause === undefined ? undefined : { cause },
    );
    this.name = "SessionSignOutError";
    this.code = revocationAlsoFailed
      ? "local_cleanup_and_server_revocation_failed"
      : "local_cleanup_failed";
  }
}

class SessionApiUpgradeError extends Error {}
class BrowserSessionStorageError extends Error {}

function signOutEverywhereUpgradeError(
  cause?: unknown,
): SessionApiUpgradeError {
  return new SessionApiUpgradeError(
    "convex-logto: signOutEverywhere is unavailable because sessionApi does not export it. Re-export signOutEverywhere from logtoSessionApi(components.logto) in your Convex auth module, then deploy your Convex functions.",
    cause === undefined ? undefined : { cause },
  );
}

/** Generic version of the same rolling-upgrade hint for the newer actions. */
function sessionApiUpgradeError(
  name: string,
  cause?: unknown,
): SessionApiUpgradeError {
  return new SessionApiUpgradeError(
    `convex-logto: ${name} is unavailable because sessionApi does not export it. ` +
      `Re-export ${name} from logtoSessionApi(components.logto) in your Convex auth ` +
      "module, then deploy your Convex functions.",
    cause === undefined ? undefined : { cause },
  );
}

/**
 * Drop blank fields (and an all-blank descriptor) so a partially-filled app
 * option never stores whitespace the server would only have to trim.
 */
function normalizeClientDescriptor(
  descriptor: LogtoSessionClientDescriptor | undefined,
): LogtoSessionClientDescriptor | undefined {
  if (descriptor === undefined) return undefined;
  const entries = (["platform", "os", "browser"] as const).flatMap((key) => {
    const value = descriptor[key]?.trim();
    return value === undefined || value === "" ? [] : [[key, value] as const];
  });
  return entries.length === 0 ? undefined : Object.fromEntries(entries);
}

function isMissingSessionAction(error: unknown, name: string): boolean {
  const errorData: unknown =
    error instanceof ConvexError ? error.data : undefined;
  const data = isRecord(errorData) ? errorData : undefined;
  // The cookie handler answers with this code; a direct Convex call surfaces the
  // deployment's own "function not found".
  if (data?.code === "session_management_unavailable") return true;
  const message = [
    error instanceof Error ? error.message : "",
    typeof data?.message === "string" ? data.message : "",
  ].join(" ");
  return (
    message.includes(name) &&
    /(?:function.*not found|could not find.*function)/i.test(message)
  );
}

function isMissingSignOutEverywhereAction(error: unknown): boolean {
  const errorData: unknown =
    error instanceof ConvexError ? error.data : undefined;
  const data = isRecord(errorData) ? errorData : undefined;
  if (data?.code === "sign_out_everywhere_unavailable") return true;
  const message = [
    error instanceof Error ? error.message : "",
    typeof data?.message === "string" ? data.message : "",
  ].join(" ");
  return (
    message.includes("signOutEverywhere") &&
    /(?:function.*not found|could not find.*function)/i.test(message)
  );
}

export function decodeJwtPayload(
  token: string,
): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const payload = parts[1];
  if (payload === undefined) return null;
  // Shared with the component's own ID-token decode so both halves read a
  // non-ASCII claim the same way — and the same way the Logto SDK does, or
  // migrating from bridge mode would start garbling names.
  const decoded = decodeJwtSegment(payload);
  return isRecord(decoded) ? decoded : null;
}

function idTokenExpMs(token: string): number {
  const exp = decodeJwtPayload(token)?.exp;
  return typeof exp === "number" ? exp * 1000 : 0;
}

/** Terminal ends the session on the client; anything else is retried and never treated as a sign-out. */
export function sessionErrorKind(error: unknown): "terminal" | "transient" {
  if (error instanceof ConvexError) {
    const data: unknown = error.data;
    if (isRecord(data) && data.kind === "terminal") return "terminal";
  }
  return "transient";
}

/** The component's own error code, when the deployment answered with one. */
function sessionErrorCode(error: unknown): string | null {
  if (!(error instanceof ConvexError)) return null;
  const data: unknown = error.data;
  return isRecord(data) && typeof data.code === "string" ? data.code : null;
}

// --- storage -----------------------------------------------------------------

/**
 * Options every token-exchange method takes.
 *
 * `forceRefresh` is the escape hatch for a token the *resource server* has
 * stopped accepting. The component caches a minted token until it expires, so
 * without this a rejected one keeps being served for the rest of its lifetime
 * and the caller has no way to say "not that one". It costs a Logto grant:
 * reach for it on the failure path, not on every call.
 */
export type LogtoTokenExchangeOptions = { forceRefresh?: boolean };

export type StoredSession = { token: string; sessionId: string };
type StoredTransaction = { state: string };
type StorageKind = "local" | "session" | "memory";
type StoredValue =
  | { status: "missing" }
  | { status: "invalid" }
  | { status: "value"; value: unknown };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
 * keeping the flow alive within the tab. Failed removals remain pending until
 * a retry reaches browser storage; `flush()` makes explicit sign-out fail loud
 * instead of claiming success while durable credentials survive a reload.
 */
/** Artifacts whose durable removal failure must reach the caller. */
const CREDENTIAL_NAMES = new Set(["session", "idToken"]);

export class SessionStorageArea {
  private memory = new Map<string, string>();
  private failedBrowserAreas = new Set<Exclude<StorageKind, "memory">>();
  private pendingRemovals = new Map<string, unknown>();
  /**
   * Keys this instance has positive evidence for in a real browser area — it
   * either wrote one there or read one back. Only those can leave a *durable*
   * credential behind, so only their removal failures are worth failing on. A
   * blocked area (sandboxed iframe, "block all cookies") never stored anything,
   * and reporting its removal failures would wedge sign-in, sign-out and
   * refresh forever over credentials that only ever lived in memory.
   */
  private durableKeys = new Set<string>();

  constructor(
    private namespace: string,
    private tokenStorage: TokenStorageKind,
  ) {}

  private key(name: string): string {
    return `convex-logto:${this.namespace}:${name}`;
  }

  private memoryArea(): Pick<Storage, "getItem" | "setItem" | "removeItem"> {
    const memory = this.memory;
    return {
      getItem: (key) => memory.get(key) ?? null,
      setItem: (key, value) => void memory.set(key, value),
      removeItem: (key) => void memory.delete(key),
    };
  }

  private fallBack(kind: StorageKind): void {
    if (kind !== "memory") this.failedBrowserAreas.add(kind);
  }

  private pendingRemovalKey(
    kind: Exclude<StorageKind, "memory">,
    key: string,
  ): string {
    return `${kind}:${key}`;
  }

  /** The real browser area, or null when it is unavailable or known-broken. */
  private browserArea(
    kind: Exclude<StorageKind, "memory">,
  ): Pick<Storage, "getItem" | "setItem" | "removeItem"> | null {
    if (this.failedBrowserAreas.has(kind) || typeof window === "undefined") {
      return null;
    }
    try {
      const area =
        kind === "local" ? window.localStorage : window.sessionStorage;
      // Accessing the getter can itself throw (sandboxed iframes).
      area.getItem(this.key("probe"));
      return area;
    } catch {
      this.fallBack(kind);
      return null;
    }
  }

  private read(kind: StorageKind, name: string): StoredValue {
    const key = this.key(name);
    const browser = kind === "memory" ? null : this.browserArea(kind);
    let raw: string | null;
    try {
      raw = (browser ?? this.memoryArea()).getItem(key);
      // Reading a value back out of a real browser area proves it is durable
      // here, even when another page load is what wrote it.
      if (raw !== null && browser !== null && kind !== "memory") {
        this.durableKeys.add(this.pendingRemovalKey(kind, key));
      }
    } catch {
      // The probe can succeed even when reading the actual key is denied.
      // Trip the circuit breaker and retry against this instance's memory so
      // subsequent operations never return to the known-broken browser area.
      this.fallBack(kind);
      raw = this.memoryArea().getItem(key);
    }
    if (raw === null) return { status: "missing" };
    try {
      const value: unknown = JSON.parse(raw);
      return { status: "value", value };
    } catch {
      // Bad stored content is key-local, not an area failure. Keep the browser
      // area active so the public reader can remove the corrupt value.
      return { status: "invalid" };
    }
  }

  private write(kind: StorageKind, name: string, value: unknown): void {
    const key = this.key(name);
    const serialized = JSON.stringify(value);
    const browser = kind === "memory" ? null : this.browserArea(kind);
    try {
      (browser ?? this.memoryArea()).setItem(key, serialized);
      if (browser !== null && kind !== "memory") {
        this.durableKeys.add(this.pendingRemovalKey(kind, key));
      }
      return;
    } catch {
      this.fallBack(kind);
      // The durable copy is now superseded. Another tab builds its own area,
      // reads that value, and presents a session token this one has already
      // rotated away from — which trips reuse detection and kills the session
      // for every tab. Drop it; the memory copy below is the live one.
      this.remove(kind, name);
    }
    this.memoryArea().setItem(key, serialized);
  }

  private remove(kind: StorageKind, name: string): void {
    const key = this.key(name);
    this.memoryArea().removeItem(key);
    if (kind === "memory" || typeof window === "undefined") return;
    const pendingKey = this.pendingRemovalKey(kind, key);
    try {
      // Deliberately bypass the circuit breaker: a removal must still be tried
      // against an area this instance previously gave up on.
      const area =
        kind === "local" ? window.localStorage : window.sessionStorage;
      area.removeItem(key);
      this.durableKeys.delete(pendingKey);
      this.pendingRemovals.delete(pendingKey);
    } catch (error) {
      this.fallBack(kind);
      // Only a credential that is actually still there is a durable-removal
      // failure. A spent `txn` stash holds the OIDC `state` string, not a
      // bearer, so failing sign-out over it would be a false alarm.
      if (CREDENTIAL_NAMES.has(name) && this.survivedRemoval(kind, key)) {
        this.pendingRemovals.set(pendingKey, error);
      }
    }
  }

  /** Did a failed removal actually leave a credential in the browser area? */
  private survivedRemoval(
    kind: Exclude<StorageKind, "memory">,
    key: string,
  ): boolean {
    try {
      const area =
        kind === "local" ? window.localStorage : window.sessionStorage;
      return area.getItem(key) !== null;
    } catch {
      // The area cannot even be read. Anything this instance is known to have
      // put there is at risk; anything else never reached it at all.
      return this.durableKeys.has(this.pendingRemovalKey(kind, key));
    }
  }

  /** Browser writes are synchronous, so there is nothing queued to wait for. */
  flush(): Promise<void> {
    return Promise.resolve();
  }

  assertCredentialsRemoved(): Promise<void> {
    if (this.pendingRemovals.size === 0) return Promise.resolve();
    return Promise.reject(
      new BrowserSessionStorageError(
        "convex-logto: browser storage could not durably remove session credentials.",
        { cause: [...this.pendingRemovals.values()] },
      ),
    );
  }

  /** The localStorage key session writes land on — for `storage` event filtering. */
  get sessionEventKey(): string {
    return this.key("session");
  }

  readSession(): StoredSession | null {
    const stored = this.read("local", "session");
    if (
      stored.status === "value" &&
      isRecord(stored.value) &&
      typeof stored.value.token === "string" &&
      typeof stored.value.sessionId === "string"
    ) {
      return {
        token: stored.value.token,
        sessionId: stored.value.sessionId,
      };
    }
    if (stored.status !== "missing") this.remove("local", "session");
    return null;
  }

  writeSession(session: StoredSession): void {
    this.write("local", "session", session);
  }

  readIdToken(): string | null {
    const stored = this.read(this.tokenStorage, "idToken");
    if (stored.status === "value" && typeof stored.value === "string") {
      return stored.value;
    }
    if (stored.status !== "missing") {
      this.remove(this.tokenStorage, "idToken");
    }
    return null;
  }

  writeIdToken(idToken: string): void {
    this.write(this.tokenStorage, "idToken", idToken);
  }

  stashTransaction(transaction: StoredTransaction): void {
    this.write("session", "txn", transaction);
  }

  takeTransaction(): StoredTransaction | null {
    const stored = this.read("session", "txn");
    this.remove("session", "txn");
    return stored.status === "value" &&
      isRecord(stored.value) &&
      typeof stored.value.state === "string"
      ? { state: stored.value.state }
      : null;
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
  /**
   * Self-reported description of this client, stamped on the session at sign-in
   * so a user can recognise it in `listSessions()`. The app supplies it — the
   * library never sniffs a User-Agent or IP — and it is advisory display data,
   * never authenticated.
   *
   * A getter, not a value: apps often learn the description asynchronously, and
   * rebuilding the engine to deliver it would restart the mount state machine
   * mid-callback. It is read once, at the exchange.
   */
  clientDescriptor?: () => LogtoSessionClientDescriptor | undefined;
  /**
   * The session credential lives somewhere this code cannot delete — the
   * HttpOnly cookie of the same-site transport. Sign-out then has no local
   * fallback: if the server does not revoke, the user is still signed in, so
   * the failure must reach the caller instead of being reported as success.
   */
  serverHeldCredential?: boolean;
  /** Replace-style navigation; falls back to `location.replace`. */
  navigate?: (to: string) => void;
  /** Native system-browser/deep-link flow; absent preserves the web flow. */
  authFlow?: SessionAuthFlow;
  onAuthError?: (error: Error) => void;
  /**
   * Opt-in phase timings for the auth bootstrap. Absent — or a slot holding
   * `undefined` — means nothing is measured at all. React providers pass a slot
   * so a handler can arrive on a later render without rebuilding the engine.
   */
  onAuthEvent?: LogtoAuthEventSink;
  /** Injectable for tests. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /**
   * Separate from `sleep` on purpose: the retry backoff inside one action call
   * is something a test wants to skip, while the recovery loop is unbounded and
   * a test that skipped its waits would spin.
   */
  recoverySleep?: (ms: number) => Promise<void>;
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
  private readonly events: AuthEventEmitter;
  /** The first settle is the one that answers "how long until the app could query". */
  private settleReported = false;
  private inflightSignIn: Promise<void> | null = null;
  private inflightCompletion: Promise<void> | null = null;
  private inflightRefresh: Promise<string | null> | null = null;
  private recoveringFor: number | null = null;
  private storagePreparation: Promise<void> | null = null;
  /** Invalidates async credential work that started before a local sign-out. */
  private authGeneration = 0;
  /** The last ID token handed to Convex — a forced fetch must never re-serve it. */
  private lastServed: string | null = null;
  private now: () => number;
  private sleep: (ms: number) => Promise<void>;
  private recoverySleep: (ms: number) => Promise<void>;

  constructor(private options: SessionEngineOptions) {
    this.now = options.now ?? (() => Date.now());
    this.events = createAuthEventEmitter(options.onAuthEvent);
    this.sleep =
      options.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.recoverySleep =
      options.recoverySleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    if (options.initialSession !== undefined) {
      options.storage.writeSession(options.initialSession);
    }
    if (
      options.initialToken !== undefined &&
      options.initialSession !== undefined
    ) {
      options.storage.writeIdToken(options.initialToken);
      this.snapshot = {
        status: "authenticated",
        sessionId: options.initialSession.sessionId,
        user: asUserClaims(decodeJwtPayload(options.initialToken)),
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
    // Snapshot: a listener may subscribe or unsubscribe while being notified.
    // oxlint-disable-next-line unicorn/no-useless-spread
    for (const listener of [...this.listeners]) listener();
  }

  private setAuthenticated(
    idToken: string,
    source: LogtoAuthEventSource = "refresh",
  ): void {
    this.reportSettle("session_restored", source);
    this.setSnapshot({
      status: "authenticated",
      sessionId: this.options.storage.readSession()?.sessionId ?? null,
      user: asUserClaims(decodeJwtPayload(idToken)),
    });
  }

  private setUnauthenticated(): void {
    this.reportSettle("unauthenticated");
    this.setSnapshot({
      status: "unauthenticated",
      sessionId: null,
      user: undefined,
    });
  }

  /**
   * Only the first settle is a bootstrap phase. Later transitions have their own
   * events (`refresh_*`, `revoked`, `signed_out`), so re-reporting them here
   * would make a long-lived tab look like it kept re-mounting.
   */
  private reportSettle(
    phase: "session_restored" | "unauthenticated",
    source?: LogtoAuthEventSource,
  ): void {
    if (this.settleReported) return;
    this.settleReported = true;
    this.events(phase, source === undefined ? undefined : { source });
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
    this.events("bootstrap_start");
    void this.startInner().catch((error: unknown) => {
      this.reportError(this.asError(error));
      this.setUnauthenticated();
    });
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
    // Fence the exchange like a refresh. A sign-out that lands while the
    // authorization code is being redeemed sees no stored session yet, so it
    // cannot revoke anything; without this the exchange response would install
    // fresh credentials right after the user signed out.
    const generation = this.authGeneration;
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
      const client = normalizeClientDescriptor(
        this.options.clientDescriptor?.(),
      );
      // Nothing has been minted yet, so simply abandoning the code is enough.
      if (generation !== this.authGeneration) return;
      const result = await this.exchangeCallback({
        code,
        state,
        redirectUri,
        ...(devicePublicKey === undefined ? {} : { devicePublicKey }),
        ...(client === undefined ? {} : { client }),
      });
      if (generation !== this.authGeneration) {
        await this.revokeAbandonedSession(result.sessionToken);
        return;
      }
      // Signing in over a live session is ordinary — Logto's SSO cookie makes
      // it a silent redirect, so it is how a user retries anything that looks
      // like a sign-out. The row it replaces would otherwise keep a live Logto
      // grant that no client can reach, and sit in the user's own device list
      // until GC takes it 190 days later.
      const superseded = this.options.storage.readSession();
      this.options.storage.writeSession({
        token: result.sessionToken,
        sessionId: result.sessionId,
      });
      this.options.storage.writeIdToken(result.idToken);
      await this.flushStorage();
      // The credentials are stored by now, so a sign-out landing during the
      // flush finds and revokes the session itself. It must not then be
      // overwritten with an authenticated snapshot built from this exchange.
      if (generation !== this.authGeneration) return;
      this.lastServed = null;
      this.setAuthenticated(result.idToken, "callback");
      if (
        // Never in cookie mode. The stored value there is a marker, not a
        // credential, and the same-origin sign-out route reads the *cookie* —
        // which the callback just replaced with the new session. Revoking by
        // marker would sign the user straight back out of the session they just
        // created.
        this.options.serverHeldCredential !== true &&
        superseded !== null &&
        superseded.sessionId !== "" &&
        superseded.sessionId !== result.sessionId
      ) {
        // Awaited, and before the navigation: with no `navigate` prop the next
        // line is `location.replace`, which tears down an in-flight request —
        // so fire-and-forget would make the cleanup unreliable in exactly the
        // default configuration. Bounded by the transport's own deadline, and
        // reported rather than thrown, so it can delay a sign-in but never fail
        // one.
        await this.revokeAbandonedSession(
          superseded.token,
          "signed in over an existing session",
        );
      }
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

  /**
   * Run the single-use callback exchange, retrying only a failure that proves
   * nothing was consumed.
   *
   * The component consumes the transaction row before it contacts Logto, so a
   * blind retry can only report `transaction_not_found` — replacing whatever
   * actually went wrong with a stale-callback diagnosis. A `ConvexError` means
   * the deployment ran the function and answered, so the row is spent: never
   * retry one.
   *
   * A transport failure is the opposite case. A dropped connection or the
   * transport's own deadline may mean the request never arrived, and losing a
   * sign-in to one bad packet is worse than an attempt that finds nothing. Retry
   * once — and if the retry reports the row is gone, the first attempt did land
   * after all, so report *its* error rather than the stale-callback one.
   */
  private async exchangeCallback(
    args: FunctionArgs<LogtoSessionApi["callback"]>,
  ): Promise<FunctionReturnType<LogtoSessionApi["callback"]>> {
    try {
      return await this.options.transport.action(
        this.options.api.callback,
        args,
      );
    } catch (first) {
      if (first instanceof ConvexError) throw first;
      try {
        return await this.options.transport.action(
          this.options.api.callback,
          args,
        );
      } catch (second) {
        throw sessionErrorCode(second) === "transaction_not_found"
          ? first
          : second;
      }
    }
  }

  /**
   * Drop a component session no client holds a credential for any more — one the
   * server minted for a sign-in that was abandoned, or one a fresh sign-in
   * replaced. Without this the row, and the Logto grant behind it, outlive every
   * credential anyone holds for them.
   *
   * Never federated and never an RFC 7009 revoke: the component only deletes its
   * own row, because the Logto grant behind it can be shared with sibling
   * sessions of the same OP session.
   */
  private async revokeAbandonedSession(
    sessionToken: string,
    reason = "signed out during sign-in",
  ): Promise<void> {
    try {
      const deviceProof = await this.options.deviceBinding?.sign(sessionToken);
      await this.options.transport.action(this.options.api.signOut, {
        sessionToken,
        ...(deviceProof === undefined ? {} : { deviceProof }),
      });
    } catch (error) {
      this.reportError(
        new Error(
          `convex-logto: ${reason}, but the session the server had already ` +
            "created could not be revoked. It expires on its own.",
          { cause: error },
        ),
      );
    }
  }

  /**
   * Storage was seeded with the server-rendered token, so a restore that reads
   * it back is an SSR hand-off, not a warm cache from an earlier visit. Telling
   * them apart is the whole point of `source` — they have different costs.
   */
  private cachedTokenSource(cached: string): LogtoAuthEventSource {
    return cached === this.options.initialToken ? "ssr" : "cache";
  }

  private async restore(): Promise<void> {
    const cached = this.options.storage.readIdToken();
    if (cached !== null && this.isFresh(cached)) {
      const session = this.options.storage.readSession();
      if (session !== null && session.sessionId !== "") {
        this.setAuthenticated(cached, this.cachedTokenSource(cached));
        return;
      }
      if (session === null) {
        // A bearer without its session credential has lost the revocation and
        // rotation anchor. Treat it as orphaned even while its JWT is fresh.
        this.options.storage.clearIdToken();
        this.setUnauthenticated();
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
        this.setAuthenticated(cached, this.cachedTokenSource(cached));
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
    if (cached !== null && this.options.storage.readSession() === null) {
      // A short bearer is usable only while its rotating session credential
      // exists. Otherwise revocation cannot be observed or recovered.
      this.options.storage.clearIdToken();
      this.lastServed = null;
      this.setUnauthenticated();
      return null;
    }
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
    } else if (this.snapshot.status === "authenticated") {
      // Convex is about to park at `noAuth`, and it only re-arms when
      // `ConvexProviderWithAuth` calls `setAuth` again — which needs
      // `isAuthenticated` to flip. Staying "authenticated" here is what wedged
      // the tab: the app already reads as signed out, but nothing could ever
      // undo it.
      this.setUnauthenticated();
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
    const generation = this.authGeneration;
    const run = async (): Promise<string | null> => {
      if (generation !== this.authGeneration) return null;
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
        if (generation !== this.authGeneration) return null;
        this.reportError(this.asError(error));
        return null;
      }
      if (generation !== this.authGeneration) return null;
      this.events("refresh_started");
      // Every fenced exit below closes the span it just opened: a consumer that
      // pairs `refresh_started` with an end phase must never be left holding an
      // open one because a sign-out raced the refresh.
      const abandoned = (): null => {
        this.events("refresh_abandoned");
        return null;
      };
      try {
        const result = await this.retrying(() =>
          this.options.transport.action(this.options.api.refresh, {
            sessionToken: session.token,
            ...(deviceProof === undefined ? {} : { deviceProof }),
          }),
        );
        if (generation !== this.authGeneration) return abandoned();
        this.options.storage.writeSession({
          token: result.sessionToken,
          sessionId: result.sessionId,
        });
        this.options.storage.writeIdToken(result.idToken);
        await this.flushStorageReporting();
        if (generation !== this.authGeneration) return abandoned();
        this.events("refresh_succeeded");
        return result.idToken;
      } catch (error) {
        if (generation !== this.authGeneration) return abandoned();
        const errorKind = sessionErrorKind(error);
        this.events("refresh_failed", { errorKind });
        if (errorKind === "terminal") {
          // Signed out / revoked / reuse-killed: the session is gone for good.
          this.options.storage.clearAll();
          this.setUnauthenticated();
        }
        // Transient (Logto/Convex unreachable): keep the session token. Nothing
        // else will re-present it — `ConvexProviderWithAuth` calls
        // `fetchAccessToken` only while our snapshot says authenticated, and
        // Convex parks at `noAuth` after a single null — so retry on our own
        // clock. Never a sign-out.
        else this.scheduleRecovery();
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
    if (this.options.authFlow === undefined)
      return this.signInReporting(options);
    if (this.inflightSignIn !== null) return this.inflightSignIn;
    this.inflightSignIn = this.signInReporting(options).finally(() => {
      this.inflightSignIn = null;
    });
    return this.inflightSignIn;
  }

  private async signInReporting(options?: {
    returnTo?: string;
  }): Promise<void> {
    try {
      await this.signInInner(options);
    } catch (error) {
      const normalizedError = this.asError(error);
      this.reportError(normalizedError);
      throw normalizedError;
    }
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
    await this.prepareStorage();
    await this.options.deviceBinding?.prepare();
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
    let authorizationUrl: string;
    try {
      authorizationUrl = normalizeHttpNavigationUrl(url, "authorization");
    } catch (error) {
      // Persist the abandoned-state deletion even though navigation is
      // refused. Native storage queues deletes until flush().
      await this.flushStorage();
      throw error;
    }
    const state = new URL(authorizationUrl).searchParams.get("state");
    if (state !== null) this.options.storage.stashTransaction({ state });
    await this.flushStorage();
    const authFlow = this.options.authFlow;
    if (authFlow === undefined) {
      window.location.assign(authorizationUrl);
      return;
    }

    let callbackUrl: string | null;
    try {
      callbackUrl = await authFlow.openAuthorization(authorizationUrl);
    } catch (error) {
      this.options.storage.takeTransaction();
      await this.flushStorage();
      throw error;
    }
    if (callbackUrl === null) {
      // A cancelled browser session must not leave an OIDC state value that a
      // later deep link could replay against.
      this.options.storage.takeTransaction();
      await this.flushStorage();
      return;
    }
    await this.runCompletion(callbackUrl, redirectUri, {
      spendOnUnrecognized: true,
    });
  }

  /**
   * Complete a native sign-in from a deep link that arrived outside the
   * system-browser promise. Public for deep-link adapters.
   *
   * Two things this has to do that the in-flow path gets for free.
   *
   * Storage is prepared first. The cold start this exists for delivers the link
   * *before* the provider's mount effect — React commits child effects before
   * parent ones — and the OIDC stash lives in SecureStore, which reads as absent
   * until `prepare()` has run. Without the await, the deep link normally loses
   * that race and deletes the very transaction it came to spend.
   *
   * And it shares `signIn`'s single flight, because the documented wiring hands
   * the same URL to both `Linking.getInitialURL()` and the `url` listener, and
   * on Android `openAuthSessionAsync` resolving *and* Linking emitting is
   * routine. One transaction slot, one flow.
   */
  async completeSignIn(
    callbackUrl: string,
    redirectUri: string,
  ): Promise<void> {
    try {
      await this.prepareStorage();
    } catch (error) {
      this.reportError(this.asError(error));
      return;
    }
    await this.runCompletion(callbackUrl, redirectUri, {
      spendOnUnrecognized: false,
    });
  }

  /**
   * One completion at a time, whichever door the return came through.
   *
   * Deliberately not `inflightSignIn`: the case this whole path exists for is a
   * browser promise that never settles, so waiting on it would hang. This latch
   * only spans a completion, which always finishes.
   */
  private runCompletion(
    callbackUrl: string,
    redirectUri: string,
    options: { spendOnUnrecognized: boolean },
  ): Promise<void> {
    const existing = this.inflightCompletion;
    // The owner reports; a duplicate delivery only needs to wait for it.
    if (existing !== null) return existing.catch(() => {});
    const run = this.completeSignInInner(callbackUrl, redirectUri, options);
    this.inflightCompletion = run.finally(() => {
      this.inflightCompletion = null;
    });
    return this.inflightCompletion;
  }

  /**
   * `spendOnUnrecognized` separates the two callers. A URL handed back by the
   * system browser *is* this sign-in's return, so anything unusable about it
   * still spends the login-CSRF state — there is no callback route to revisit on
   * native. A deep link is only a candidate: the app forwards every link it
   * receives, and one that carries no OIDC response must leave an in-flight
   * sign-in alone.
   */
  private async completeSignInInner(
    callbackUrl: string,
    redirectUri: string,
    options: { spendOnUnrecognized: boolean },
  ): Promise<void> {
    let url: URL;
    try {
      url = new URL(callbackUrl);
    } catch (error) {
      this.reportError(
        new Error("convex-logto: the native sign-in return URL is invalid.", {
          cause: error,
        }),
      );
      if (!options.spendOnUnrecognized) return;
      this.options.storage.takeTransaction();
      await this.flushStorageReporting();
      await this.restore();
      this.navigateReplace(this.options.afterSignIn);
      return;
    }
    const outcome = classifySignInSearch(url.search);
    if (outcome.kind === "pending") {
      await this.completeCallback(url.searchParams, redirectUri);
      return;
    }
    if (outcome.kind === "none" && !options.spendOnUnrecognized) return;

    this.options.storage.takeTransaction();
    await this.flushStorageReporting();
    // `benign` is the user declining at Logto — a completed flow, not a fault.
    if (outcome.kind === "error") {
      this.reportError(new Error(outcome.message));
    } else if (outcome.kind === "none") {
      this.reportError(
        new Error(
          "convex-logto: the native sign-in return did not include an authorization code and state.",
        ),
      );
    }
    await this.restore();
    this.navigateReplace(this.options.afterSignIn);
  }

  async signOut(options?: {
    postLogoutRedirectUri?: string;
    federated?: boolean;
  }): Promise<void> {
    await this.performSignOut({
      postLogoutRedirectUri: options?.postLogoutRedirectUri,
      federated: options?.federated !== false,
      // A local credential can be destroyed without the server, so a dead Logto
      // must not block sign-out. A server-held one cannot: there the revoke
      // *is* the sign-out.
      requireServerSuccess: this.options.serverHeldCredential === true,
      revoke: async (sessionToken, deviceProof, postLogoutRedirectUri) =>
        await this.options.transport.action(this.options.api.signOut, {
          sessionToken,
          ...(deviceProof === undefined ? {} : { deviceProof }),
          postLogoutRedirectUri,
        }),
    });
  }

  /**
   * The caller's own sessions, for a "where am I signed in" screen. A snapshot,
   * not a subscription: the credential it authenticates with rotates, so a
   * reactive query keyed on it would resubscribe on every rotation. Call it
   * again after `revokeSession` or `renameSession`.
   */
  async listSessions(): Promise<{
    sessions: LogtoSessionSummary[];
    truncated: boolean;
  }> {
    const action = this.options.api.listSessions;
    if (action === undefined) throw sessionApiUpgradeError("listSessions");
    const credential = await this.sessionCallCredential("listSessions");
    return await this.callSessionAction("listSessions", () =>
      this.options.transport.action(action, credential),
    );
  }

  /**
   * Rename one of the caller's own sessions. Pass `undefined` to clear it.
   * Rejects with a terminal `session_not_found` for an id that is not the
   * caller's or has already been revoked — the same way the component refuses
   * to confirm that another subject's session exists.
   */
  async renameSession(
    targetSessionId: string,
    label: string | undefined,
  ): Promise<void> {
    const action = this.options.api.renameSession;
    if (action === undefined) throw sessionApiUpgradeError("renameSession");
    // Check the length here rather than learn it from the server. The component
    // reports an over-long label as a *terminal* session error, and terminal is
    // defined as "this session is gone" — an app that follows that taxonomy
    // would sign the user out for typing a long device name. Failing locally
    // also saves a round-trip on an input the user can simply shorten.
    if (label !== undefined && sessionLabelTooLong(label)) {
      throw new Error(
        `convex-logto: a session label may be at most ${SESSION_LABEL_MAX_LENGTH} characters.`,
      );
    }
    const credential = await this.sessionCallCredential("renameSession");
    await this.callSessionAction("renameSession", () =>
      this.options.transport.action(action, {
        ...credential,
        targetSessionId,
        ...(label === undefined ? {} : { label }),
      }),
    );
  }

  /**
   * Revoke one of the caller's own sessions, rejecting like `renameSession` for
   * an id that is not the caller's. Revoking the current one leaves this
   * client's credentials in place — call `signOut()` for that.
   */
  async revokeSession(targetSessionId: string): Promise<void> {
    const action = this.options.api.revokeSession;
    if (action === undefined) throw sessionApiUpgradeError("revokeSession");
    const credential = await this.sessionCallCredential("revokeSession");
    await this.callSessionAction("revokeSession", () =>
      this.options.transport.action(action, { ...credential, targetSessionId }),
    );
  }

  /**
   * The current ID token — the Short bearer Convex validates.
   *
   * Read from storage rather than the snapshot: the snapshot is what React
   * rendered, and a rotation that landed since the last render is already in
   * storage. Returns `null` when signed out, or when the stored token has aged
   * out; any Convex call mints a fresh one.
   *
   * Synchronous, which is what makes it usable in a render — and the reason it
   * has one caveat. On React Native the SecureStore-backed adapter reads as
   * empty until it has hydrated, so a call made while the engine is still
   * `restoring` answers `null` even though a live token exists. Gate on
   * `isAuthenticated` (false during restore) and that window is unreachable.
   */
  getIdToken(): string | null {
    const cached = this.options.storage.readIdToken();
    return cached !== null && this.isFresh(cached) ? cached : null;
  }

  /**
   * What an Organization token authorizes, without the token itself.
   *
   * Membership and organization *roles* do not need this — Logto puts them in
   * the ID token, so `user.organizations` and `user.organization_roles` are
   * already there and cost nothing. Reach for this only for fine-grained
   * organization **permissions**, which Logto issues nowhere else.
   */
  async getOrganizationTokenClaims(
    organizationId: string,
    scopes?: string[],
    options?: LogtoTokenExchangeOptions,
  ): Promise<LogtoResourceTokenClaims> {
    return (
      await this.exchange({
        organizationId,
        scopes,
        forceRefresh: options?.forceRefresh,
      })
    ).claims;
  }

  /**
   * What a Resource token authorizes, without the token itself.
   *
   * The resource must be in `resources` on `logtoSessionApi()`: Logto will not
   * issue a token for a resource the grant never named.
   */
  async getAccessTokenClaims(
    resource: string,
    scopes?: string[],
    options?: LogtoTokenExchangeOptions,
  ): Promise<LogtoResourceTokenClaims> {
    return (
      await this.exchange({
        resource,
        scopes,
        forceRefresh: options?.forceRefresh,
      })
    ).claims;
  }

  /**
   * The Organization token *string*.
   *
   * Available only where the deployment passed `exposeAccessTokens: true`;
   * otherwise this rejects with a terminal error naming the option, rather than
   * returning claims and letting the missing credential surface as an
   * authorization failure somewhere else. Prefer
   * {@link getOrganizationTokenClaims} — a token in `window` is one more thing
   * XSS can steal.
   */
  async getOrganizationToken(
    organizationId: string,
    scopes?: string[],
    options?: LogtoTokenExchangeOptions,
  ): Promise<string> {
    return this.requireToken(
      await this.exchange({
        organizationId,
        scopes,
        includeToken: true,
        forceRefresh: options?.forceRefresh,
      }),
    );
  }

  /** The Resource token *string*, under the same `exposeAccessTokens` gate. */
  async getAccessToken(
    resource: string,
    scopes?: string[],
    options?: LogtoTokenExchangeOptions,
  ): Promise<string> {
    return this.requireToken(
      await this.exchange({
        resource,
        scopes,
        includeToken: true,
        forceRefresh: options?.forceRefresh,
      }),
    );
  }

  /**
   * Logto's `/oidc/me`, fetched by the component.
   *
   * A round trip, unlike `user`: this is the live profile from Logto rather
   * than the copy the last ID token froze. Use it after a profile edit.
   */
  async fetchUserInfo(options?: LogtoTokenExchangeOptions): Promise<unknown> {
    const action = this.options.api.fetchUserInfo;
    if (action === undefined) throw sessionApiUpgradeError("fetchUserInfo");
    const credential = await this.sessionCallCredential("fetchUserInfo");
    // Also an exchange behind the scenes — it mints the opaque token Logto's
    // userinfo endpoint wants — so it takes the same lock for the same reason.
    return await this.withLock(() =>
      this.retrying(() =>
        this.callSessionAction("fetchUserInfo", () =>
          this.options.transport.action(action, {
            ...credential,
            ...(options?.forceRefresh === undefined
              ? {}
              : { forceRefresh: options.forceRefresh }),
          }),
        ),
      ),
    );
  }

  private async exchange(args: {
    organizationId?: string;
    resource?: string;
    scopes?: string[];
    includeToken?: boolean;
    forceRefresh?: boolean;
  }): Promise<{
    claims: LogtoResourceTokenClaims;
    accessToken?: string;
    minted: boolean;
  }> {
    const action = this.options.api.exchangeToken;
    if (action === undefined) throw sessionApiUpgradeError("exchangeToken");
    const credential = await this.sessionCallCredential("exchangeToken");
    // Under the same lock as `refreshIdToken`, and retried like it.
    //
    // The component runs this exchange inside the session's refresh claim, so
    // it and a refresh cannot both be in flight — the loser gets a transient
    // `refresh_in_flight`. Without the lock the loser is usually the *refresh*,
    // and a refresh that exhausts its retries drops the whole app to
    // unauthenticated until the recovery loop catches up. Serializing them in
    // the browser removes the case that actually happens; `retrying` covers
    // the rest (another tab, another device, a queued cron).
    return await this.withLock(() =>
      this.retrying(() => this.dispatchExchange(action, credential, args)),
    );
  }

  private async dispatchExchange(
    action: NonNullable<LogtoSessionApi["exchangeToken"]>,
    credential: { sessionToken: string; deviceProof?: string },
    args: {
      organizationId?: string;
      resource?: string;
      scopes?: string[];
      includeToken?: boolean;
      forceRefresh?: boolean;
    },
  ): Promise<{
    claims: LogtoResourceTokenClaims;
    accessToken?: string;
    minted: boolean;
  }> {
    return await this.callSessionAction("exchangeToken", () =>
      this.options.transport.action(action, {
        ...credential,
        ...(args.organizationId === undefined
          ? {}
          : { organizationId: args.organizationId }),
        ...(args.resource === undefined ? {} : { resource: args.resource }),
        ...(args.scopes === undefined ? {} : { scopes: args.scopes }),
        ...(args.includeToken === undefined
          ? {}
          : { includeToken: args.includeToken }),
        ...(args.forceRefresh === undefined
          ? {}
          : { forceRefresh: args.forceRefresh }),
      }),
    );
  }

  /**
   * The server refuses `includeToken` when the deployment did not opt in, so
   * this only fires for a component that answered without one anyway. Still an
   * error rather than an empty string: every caller here is about to put the
   * value in an `Authorization` header.
   */
  private requireToken(result: { accessToken?: string }): string {
    if (result.accessToken === undefined) {
      throw new Error(
        "convex-logto: the deployment did not return an access token. Pass " +
          "`exposeAccessTokens: true` to logtoSessionApi() to allow it.",
      );
    }
    return result.accessToken;
  }

  /**
   * The current session token plus its device proof — the argument prefix every
   * session-management action authenticates with.
   */
  private async sessionCallCredential(
    name: string,
  ): Promise<{ sessionToken: string; deviceProof?: string }> {
    await this.prepareStorage();
    const session = this.options.storage.readSession();
    if (session === null) {
      throw new Error(
        `convex-logto: ${name} requires an active session. Sign in first.`,
      );
    }
    const deviceProof = await this.options.deviceBinding?.sign(session.token);
    return {
      sessionToken: session.token,
      ...(deviceProof === undefined ? {} : { deviceProof }),
    };
  }

  /**
   * Translate "no such function" from a deployment whose app module predates
   * the action into the rolling-upgrade hint, the same way `signOutEverywhere`
   * does — the server-side check alone can't see a stale re-export.
   */
  private async callSessionAction<Result>(
    name: string,
    call: () => Promise<Result>,
  ): Promise<Result> {
    try {
      return await call();
    } catch (error) {
      if (isMissingSessionAction(error, name)) {
        throw sessionApiUpgradeError(name, error);
      }
      throw error;
    }
  }

  async signOutEverywhere(options?: {
    postLogoutRedirectUri?: string;
  }): Promise<void> {
    const action = this.options.api.signOutEverywhere;
    await this.performSignOut({
      postLogoutRedirectUri: options?.postLogoutRedirectUri,
      federated: true,
      // A single-device sign-out is locally complete even if the network is
      // down. "Everywhere" is not: report failure when the subject-wide
      // mutation did not run so callers never mistake a partial result for
      // success.
      requireServerSuccess: true,
      revoke: async (sessionToken, deviceProof, postLogoutRedirectUri) => {
        if (action === undefined) throw signOutEverywhereUpgradeError();
        try {
          return await this.options.transport.action(action, {
            sessionToken,
            ...(deviceProof === undefined ? {} : { deviceProof }),
            postLogoutRedirectUri,
          });
        } catch (error) {
          if (isMissingSignOutEverywhereAction(error)) {
            throw signOutEverywhereUpgradeError(error);
          }
          throw error;
        }
      },
    });
  }

  private async performSignOut(options: {
    postLogoutRedirectUri?: string;
    federated: boolean;
    requireServerSuccess: boolean;
    revoke: (
      sessionToken: string,
      deviceProof: string | undefined,
      postLogoutRedirectUri: string,
    ) => Promise<{ endSessionUrl?: string }>;
  }): Promise<void> {
    // Fence immediately, before any async storage preparation or network work:
    // a refresh that began in the previous generation must never resurrect it.
    this.authGeneration += 1;
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
    let deviceProof: string | undefined;
    let deviceProofError: Error | undefined;
    if (session !== null && this.options.deviceBinding !== undefined) {
      try {
        deviceProof = await this.options.deviceBinding.sign(session.token);
      } catch (error) {
        deviceProofError = this.asError(error);
      }
    }
    // Clear before the network call: sign-out must not be blockable by a dead
    // Logto. The localStorage removal kicks other tabs via the storage event.
    let cleanupError = this.clearStorageLocally();
    this.lastServed = null;
    this.events("signed_out");
    this.setUnauthenticated();
    cleanupError = await this.finishStorageCleanup(cleanupError);
    const durableCleanupFailed = cleanupError !== undefined;
    if (cleanupError !== undefined) {
      // Still attempt server revocation when durable local cleanup fails; a
      // second cleanup failure becomes a loud error after that independent try.
      this.reportError(cleanupError);
    }
    let postLogoutRedirectUri: string | undefined;
    let endSessionUrl: string | undefined;
    let serverSessionStatus: SessionSignOutServerStatus =
      session === null ? "not_present" : "revocation_failed";
    let serverRevocationError: unknown;
    let fatalServerError: Error | undefined;
    if (session !== null) {
      // `??` alone would forward an empty string, which every server-side
      // validator rejects — a caller passing `""` means "use the default".
      const requested = options.postLogoutRedirectUri?.trim();
      postLogoutRedirectUri =
        (requested === undefined || requested === "" ? undefined : requested) ??
        this.options.authFlow?.redirectUri ??
        window.location.origin;
      if (deviceProofError !== undefined) {
        serverRevocationError = deviceProofError;
        this.reportError(deviceProofError);
        if (options.requireServerSuccess) fatalServerError = deviceProofError;
      } else {
        try {
          ({ endSessionUrl } = await options.revoke(
            session.token,
            deviceProof,
            postLogoutRedirectUri,
          ));
          serverSessionStatus = "revoked";
        } catch (error) {
          serverRevocationError = error;
          if (
            error instanceof SessionApiUpgradeError ||
            options.requireServerSuccess
          ) {
            fatalServerError =
              error instanceof Error
                ? error
                : new Error(
                    "convex-logto: the server could not complete sign out everywhere.",
                    { cause: error },
                  );
            this.reportError(fatalServerError);
          } else {
            // Best effort, but never silent: the server session outlives this
            // sign-out until it expires, and only the app can decide whether
            // that matters enough to retry.
            this.reportError(this.asError(error));
          }
          // A combined failure is converted into a loud SessionSignOutError
          // below.
        }
      }
    }
    let signOutError: SessionSignOutError | undefined;
    if (durableCleanupFailed) {
      // Storage failures can be transient. Retry once after the independent
      // server kill, bypassing any adapter read fallback through clearAll().
      let durableCleanupError = this.clearStorageLocally();
      durableCleanupError =
        await this.finishStorageCleanup(durableCleanupError);
      if (durableCleanupError !== undefined) {
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
    let navigationError: Error | undefined;
    if (options.federated && endSessionUrl !== undefined) {
      let navigationUrl: string | undefined;
      try {
        navigationUrl = normalizeHttpNavigationUrl(
          endSessionUrl,
          "end-session",
        );
      } catch (error) {
        navigationError = this.asError(error);
        this.reportError(navigationError);
      }
      if (
        navigationUrl !== undefined &&
        this.options.authFlow !== undefined &&
        postLogoutRedirectUri !== undefined
      ) {
        try {
          await this.options.authFlow.openEndSession(
            navigationUrl,
            postLogoutRedirectUri,
          );
        } catch (error) {
          this.reportError(this.asError(error));
        }
      } else if (navigationUrl !== undefined) {
        window.location.assign(navigationUrl);
      }
    }
    if (signOutError !== undefined) throw signOutError;
    if (fatalServerError !== undefined) throw fatalServerError;
    if (navigationError !== undefined) throw navigationError;
  }

  /**
   * Re-present the session after a transient refresh failure until it works.
   *
   * Keeping the session token is only useful if something presents it again,
   * and nothing does: Convex clears its auth config after one `null` and only
   * `client.setAuth` re-arms it, which `ConvexProviderWithAuth` calls solely
   * when `isAuthenticated` flips. So the engine drives the retry itself and
   * flips its own snapshot back on success.
   *
   * Bounded by the session's existence and the auth generation, not by an
   * attempt count: a five-minute outage must still end with the tab signed in.
   */
  private scheduleRecovery(): void {
    // Keyed by generation, not a bare flag: a loop left over from before a
    // sign-out sleeps for up to 30s before it notices, and a bare flag would
    // make that stale loop swallow the arming of a fresh one — stranding the tab
    // in exactly the way this exists to prevent.
    if (this.recoveringFor === this.authGeneration) return;
    const generation = this.authGeneration;
    this.recoveringFor = generation;
    void this.recover(generation).finally(() => {
      if (this.recoveringFor === generation) this.recoveringFor = null;
    });
  }

  private async recover(generation: number): Promise<void> {
    for (let attempt = 0; ; attempt += 1) {
      // `Math.min` already clamps to the last entry, so the index is always in
      // range — no fallback to write, and none to leave silently wrong if the
      // ladder changes.
      const delay =
        RECOVERY_DELAYS_MS[Math.min(attempt, RECOVERY_DELAYS_MS.length - 1)];
      await this.recoverySleep(delay);
      // A sign-out, a revocation, or another tab getting there first all end the
      // retry: there is nothing left to re-present.
      if (generation !== this.authGeneration) return;
      if (this.options.storage.readSession() === null) return;
      const idToken = await this.refreshIdToken(null);
      if (generation !== this.authGeneration) return;
      if (idToken === null) continue;
      this.lastServed = idToken;
      if (this.snapshot.status !== "authenticated")
        this.setAuthenticated(idToken);
      return;
    }
  }

  // -- external events --

  /** Another tab signed out (our localStorage session key was removed). */
  handleExternalSignOut(): void {
    this.authGeneration += 1;
    this.events("signed_out", { source: "cross-tab" });
    this.options.storage.clearIdToken();
    this.lastServed = null;
    this.setUnauthenticated();
  }

  /**
   * Convex accepted the token: the app can run its first authenticated query.
   * The provider reports it because only Convex knows when it happened.
   */
  reportConvexAuthenticated(): void {
    this.events("convex_authenticated");
  }

  /**
   * Surface a failure the provider detected rather than the engine — today a
   * broken `sessionValid` subscription. Routed through the same observer as
   * every other auth error.
   */
  reportWatchFailure(error: Error): void {
    this.reportError(error);
  }

  /** The reactive `sessionValid` subscription pushed `false`: the session was revoked. */
  handleRevoked(): void {
    this.authGeneration += 1;
    // The credential in storage is shared with every tab on this origin, and the
    // session id this engine watches is its own. Another tab signing in replaces
    // that credential without telling us, so a revocation of the session we
    // *used* to hold must not delete the one that took its place — that would
    // sign every tab out and orphan the session just created. Adopt it instead.
    const stored = this.options.storage.readSession();
    const watched = this.snapshot.sessionId;
    if (
      this.options.serverHeldCredential !== true &&
      stored !== null &&
      watched !== null &&
      stored.sessionId !== "" &&
      stored.sessionId !== watched
    ) {
      void this.restore().catch((error: unknown) => {
        this.reportError(this.asError(error));
      });
      return;
    }
    this.events("revoked");
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

  private clearStorageLocally(): Error | undefined {
    try {
      this.options.storage.clearAll();
      return undefined;
    } catch (error) {
      return this.asError(error);
    }
  }

  private async finishStorageCleanup(
    clearError: Error | undefined,
  ): Promise<Error | undefined> {
    try {
      await this.flushStorage();
      // Sign-out is the one caller that must also fail over a credential that
      // survived removal — see `assertCredentialsRemoved`.
      await this.options.storage.assertCredentialsRemoved?.();
      return clearError;
    } catch (error) {
      const flushError = this.asError(error);
      return clearError === undefined
        ? flushError
        : new Error(
            "convex-logto: clearing and flushing local session credentials both failed.",
            { cause: { clearError, flushError } },
          );
    }
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
        const retryDelay = RETRY_DELAYS_MS[attempt];
        if (
          sessionErrorKind(error) === "terminal" ||
          retryDelay === undefined
        ) {
          throw error;
        }
        await this.sleep(retryDelay);
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
    // Nested recovery helpers may report and rethrow the same Error. Preserve
    // the rejection while routing that object through the observer only once.
    if (REPORTED_AUTH_ERRORS.has(error)) return;
    REPORTED_AUTH_ERRORS.add(error);
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
