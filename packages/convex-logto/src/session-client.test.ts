// @vitest-environment happy-dom
//
// SessionAuthEngine state-machine tests: the mount paths (callback exchange,
// zero-RTT cached restore, refresh restore), the fetchAccessToken contract
// (cached / forced / merged / cross-tab adoption), the login-CSRF stash
// refusal, terminal-vs-transient error handling, and sign-out ordering.
// The Convex transport is a stub dispatching on function-reference identity.
import { ConvexError } from "convex/values";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  SessionAuthEngine,
  SessionStorageArea,
  type SessionSnapshot,
  type SessionStorageAdapter,
  type SessionTransport,
  type StoredSession,
  type TokenStorageKind,
} from "./session-client";
import type { LogtoSessionApi } from "./session";
import {
  SessionDeviceBindingError,
  WebCryptoSessionDeviceBinding,
  type SessionDeviceBinding,
} from "./session-device";
import {
  COOKIE_SESSION_MARKER,
  createCookieSessionMarker,
} from "./session-cookie";

// --- harness -----------------------------------------------------------------

function setURL(url: string): void {
  (
    window as unknown as { happyDOM: { setURL: (url: string) => void } }
  ).happyDOM.setURL(url);
}

function fakeIdToken(payload: Record<string, unknown>): string {
  const enc = (o: unknown) =>
    btoa(JSON.stringify(o))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "ES384" })}.${enc(payload)}.sig`;
}

const freshToken = (sub = "user1") =>
  fakeIdToken({ sub, exp: Math.floor(Date.now() / 1000) + 3600 });
const staleToken = (sub = "user1") =>
  fakeIdToken({ sub, exp: Math.floor(Date.now() / 1000) + 10 });

const terminalError = () =>
  new ConvexError({
    kind: "terminal",
    code: "session_not_found",
    message: "gone",
  });
const transientError = () =>
  new ConvexError({
    kind: "transient",
    code: "logto_unreachable",
    message: "down",
  });

// Sentinel function references; the stub transport dispatches on identity.
const api = {
  signIn: { fn: "signIn" },
  callback: { fn: "callback" },
  refresh: { fn: "refresh" },
  signOut: { fn: "signOut" },
  signOutEverywhere: { fn: "signOutEverywhere" },
  listSessions: { fn: "listSessions" },
  renameSession: { fn: "renameSession" },
  revokeSession: { fn: "revokeSession" },
  sessionValid: { fn: "sessionValid" },
} as unknown as LogtoSessionApi;

type Handlers = {
  signIn: ReturnType<typeof vi.fn>;
  callback: ReturnType<typeof vi.fn>;
  refresh: ReturnType<typeof vi.fn>;
  signOut: ReturnType<typeof vi.fn>;
  signOutEverywhere: ReturnType<typeof vi.fn>;
  listSessions: ReturnType<typeof vi.fn>;
  renameSession: ReturnType<typeof vi.fn>;
  revokeSession: ReturnType<typeof vi.fn>;
};

function makeHarness(options?: {
  tokenStorage?: TokenStorageKind;
  afterSignIn?: string;
  initialToken?: string;
  initialSession?: StoredSession;
  storedIdToken?: string;
  storedSession?: StoredSession;
  cookieBootstrap?: { initialSessionId?: string | null };
  deviceBinding?: SessionDeviceBinding;
  sessionApi?: LogtoSessionApi;
  storage?: SessionStorageAdapter;
  serverHeldCredential?: boolean;
  clientDescriptor?: {
    platform?: string;
    os?: string;
    browser?: string;
  };
}) {
  const handlers: Handlers = {
    signIn: vi.fn(),
    callback: vi.fn(),
    refresh: vi.fn(),
    signOut: vi.fn(),
    signOutEverywhere: vi.fn(),
    listSessions: vi.fn(),
    renameSession: vi.fn(),
    revokeSession: vi.fn(),
  };
  const transport = {
    action: (ref: unknown, args: unknown) =>
      handlers[(ref as { fn: keyof Handlers }).fn](args),
  } as SessionTransport;
  const storage =
    options?.storage ??
    new SessionStorageArea("test", options?.tokenStorage ?? "session");
  if (options?.storedSession) storage.writeSession(options.storedSession);
  if (options?.storedIdToken) storage.writeIdToken(options.storedIdToken);
  const initialSession = options?.cookieBootstrap
    ? createCookieSessionMarker(
        storage.readSession(),
        options.cookieBootstrap.initialSessionId,
      )
    : options?.initialSession;
  const navigate = vi.fn();
  const onAuthError = vi.fn();
  const engine = new SessionAuthEngine({
    transport,
    api: options?.sessionApi ?? api,
    storage,
    callbackPath: "/callback",
    afterSignIn: options?.afterSignIn ?? "/",
    initialToken: options?.initialToken,
    initialSession,
    deviceBinding: options?.deviceBinding,
    serverHeldCredential: options?.serverHeldCredential,
    clientDescriptor: options?.clientDescriptor,
    navigate,
    onAuthError,
    sleep: () => Promise.resolve(), // skip retry backoff in tests
  });
  return { engine, storage, handlers, navigate, onAuthError };
}

/** Resolves once the engine leaves `restoring`. */
function settled(engine: SessionAuthEngine): Promise<SessionSnapshot> {
  return new Promise((resolve) => {
    const check = () => {
      const snapshot = engine.getSnapshot();
      if (snapshot.status !== "restoring") {
        unsubscribe();
        resolve(snapshot);
      }
    };
    const unsubscribe = engine.subscribe(check);
    check();
  });
}

const sessionResult = (n: number, sub = "user1") => ({
  idToken: freshToken(sub),
  sessionToken: `session-token-${n}`,
  sessionId: `session-id-${n}`,
});

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
} {
  let settle: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    settle = resolve;
  });
  return {
    promise,
    resolve(value) {
      if (settle === undefined) throw new Error("deferred was not initialized");
      settle(value);
    },
  };
}

function persistentStorageStub(
  entries: ReadonlyArray<readonly [string, string]>,
  failedRemovalAttempts: number,
): {
  values: Map<string, string>;
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">;
} {
  const values = new Map(entries);
  let removalAttempts = 0;
  return {
    values,
    storage: {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => void values.set(key, value),
      removeItem: (key) => {
        removalAttempts += 1;
        if (removalAttempts <= failedRemovalAttempts) {
          throw new Error("storage removal unavailable");
        }
        values.delete(key);
      },
    },
  };
}

const devicePublicKey = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: "public-x",
  y: "public-y",
};

function fakeDeviceBinding(proof = "device-proof") {
  return {
    prepare: vi.fn().mockResolvedValue(undefined),
    getPublicKey: vi.fn().mockResolvedValue(devicePublicKey),
    sign: vi.fn().mockResolvedValue(proof),
  } satisfies SessionDeviceBinding;
}

beforeEach(() => {
  setURL("http://localhost:5173/");
  localStorage.clear();
  sessionStorage.clear();
  vi.spyOn(window.location, "assign").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// --- storage -----------------------------------------------------------------

describe("SessionStorageArea", () => {
  it("keeps the session in localStorage and the ID token in the chosen area", () => {
    const store = new SessionStorageArea("ns", "session");
    store.writeSession({ token: "t", sessionId: "s" });
    store.writeIdToken("id-token");
    expect(localStorage.getItem("convex-logto:ns:session")).toContain('"t"');
    expect(sessionStorage.getItem("convex-logto:ns:idToken")).toBe(
      '"id-token"',
    );
    expect(store.sessionEventKey).toBe("convex-logto:ns:session");

    const local = new SessionStorageArea("ns2", "local");
    local.writeIdToken("id-token");
    expect(localStorage.getItem("convex-logto:ns2:idToken")).toBe('"id-token"');

    const memory = new SessionStorageArea("ns3", "memory");
    memory.writeIdToken("id-token");
    expect(localStorage.getItem("convex-logto:ns3:idToken")).toBeNull();
    expect(sessionStorage.getItem("convex-logto:ns3:idToken")).toBeNull();
    expect(memory.readIdToken()).toBe("id-token");
  });

  it("takeTransaction is one-shot", () => {
    const store = new SessionStorageArea("ns", "session");
    store.stashTransaction({ state: "s1" });
    expect(store.takeTransaction()).toEqual({ state: "s1" });
    expect(store.takeTransaction()).toBeNull();
  });

  it("sticks to memory when localStorage rejects a session write", () => {
    let writeAttempts = 0;
    vi.stubGlobal("localStorage", {
      getItem: () => null,
      setItem: () => {
        writeAttempts += 1;
        throw new Error("quota exceeded");
      },
      removeItem: () => undefined,
    });
    const store = new SessionStorageArea("ns", "session");

    store.writeSession({ token: "t", sessionId: "s" });

    expect(store.readSession()).toEqual({ token: "t", sessionId: "s" });
    expect(writeAttempts).toBe(1);
  });

  it("reports failed durable removal and clears it after a successful retry", async () => {
    const values = new Map<string, string>();
    let removeAttempts = 0;
    let removalFails = true;
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => void values.set(key, value),
      removeItem: (key: string) => {
        removeAttempts += 1;
        if (removalFails) throw new Error("storage unavailable");
        values.delete(key);
      },
    });
    const store = new SessionStorageArea("ns", "session");
    store.writeSession({ token: "t", sessionId: "s" });

    store.clearAll();

    expect(store.readSession()).toBeNull();
    expect(removeAttempts).toBe(1);
    await expect(store.flush()).rejects.toThrow(/durably remove/);

    removalFails = false;
    store.clearAll();
    await expect(store.flush()).resolves.toBeUndefined();
    expect(values.get("convex-logto:ns:session")).toBeUndefined();
    expect(removeAttempts).toBe(2);
  });

  it("sticks to memory when the real getItem fails after the probe", () => {
    let artifactReads = 0;
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => {
        if (key.endsWith(":probe")) return null;
        artifactReads += 1;
        throw new Error("storage read unavailable");
      },
      setItem: () => undefined,
      removeItem: () => undefined,
    });
    const store = new SessionStorageArea("ns", "session");

    expect(store.readSession()).toBeNull();
    expect(store.readSession()).toBeNull();
    expect(artifactReads).toBe(1);
  });

  it("cleans a non-string ID token without throwing", () => {
    const store = new SessionStorageArea("ns", "session");
    sessionStorage.setItem(
      "convex-logto:ns:idToken",
      JSON.stringify({ exp: "not-a-token" }),
    );

    expect(store.readIdToken()).toBeNull();
    expect(sessionStorage.getItem("convex-logto:ns:idToken")).toBeNull();
  });

  it("removes malformed JSON without disabling the browser storage area", () => {
    const key = "convex-logto:ns:idToken";
    sessionStorage.setItem(key, "{");
    const store = new SessionStorageArea("ns", "session");

    expect(store.readIdToken()).toBeNull();
    expect(sessionStorage.getItem(key)).toBeNull();

    store.writeIdToken("next-token");
    expect(sessionStorage.getItem(key)).toBe('"next-token"');
    expect(store.readIdToken()).toBe("next-token");
  });

  it("does not report durable removal for an area that never accepted a write", async () => {
    // "Block all cookies", a sandboxed iframe, or blocked site data: every
    // access throws, so the credential only ever lived in memory. Reporting its
    // removal would wedge sign-in, sign-out and refresh for the whole page.
    const blocked = () => {
      throw new Error("storage blocked");
    };
    vi.stubGlobal("localStorage", {
      getItem: blocked,
      setItem: blocked,
      removeItem: blocked,
    });
    const store = new SessionStorageArea("ns", "local");
    store.writeSession({ token: "t", sessionId: "s" });
    expect(store.readSession()).toEqual({ token: "t", sessionId: "s" });

    store.clearAll();

    expect(store.readSession()).toBeNull();
    expect(store.readIdToken()).toBeNull();
    await expect(store.flush()).resolves.toBeUndefined();
  });

  it("does not fail sign-out over a spent transaction stash", async () => {
    const values = new Map<string, string>();
    vi.stubGlobal("sessionStorage", {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => void values.set(key, value),
      removeItem: () => {
        throw new Error("storage unavailable");
      },
    });
    const store = new SessionStorageArea("ns", "local");
    store.stashTransaction({ state: "s1" });

    store.clearAll();

    // The stash holds the OIDC `state`, not a bearer — not a credential leak.
    await expect(store.flush()).resolves.toBeUndefined();
  });

  it("clearAll removes every artifact", () => {
    const store = new SessionStorageArea("ns", "session");
    store.writeSession({ token: "t", sessionId: "s" });
    store.writeIdToken("id");
    store.stashTransaction({ state: "s1" });
    store.clearAll();
    expect(store.readSession()).toBeNull();
    expect(store.readIdToken()).toBeNull();
    expect(store.takeTransaction()).toBeNull();
  });
});

// --- mount paths -------------------------------------------------------------

describe("mount", () => {
  it("SSR initialToken authenticates the server snapshot and hydrates storage", () => {
    const token = freshToken("ssr-user");
    const { engine, storage } = makeHarness({
      initialToken: token,
      initialSession: { token: "cookie-session", sessionId: "session-id-1" },
    });
    expect(engine.getServerSnapshot()).toEqual({
      status: "authenticated",
      sessionId: "session-id-1",
      user: expect.objectContaining({ sub: "ssr-user" }),
    });
    expect(engine.getSnapshot()).toEqual(engine.getServerSnapshot());
    expect(storage.readIdToken()).toBe(token);
    expect(storage.readSession()).toEqual({
      token: "cookie-session",
      sessionId: "session-id-1",
    });
  });

  it("SSR initialToken without its paired session cannot authenticate", () => {
    const { engine, storage } = makeHarness({ initialToken: freshToken() });

    expect(engine.getServerSnapshot().status).toBe("restoring");
    expect(engine.getSnapshot().status).toBe("restoring");
    expect(storage.readIdToken()).toBeNull();
  });

  it("nothing stored → unauthenticated, no network", async () => {
    const { engine, handlers } = makeHarness();
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("a corrupt stored ID token still settles unauthenticated", async () => {
    sessionStorage.setItem(
      "convex-logto:test:idToken",
      JSON.stringify({ exp: "not-a-token" }),
    );
    const { engine, storage } = makeHarness();

    engine.start();

    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(storage.readIdToken()).toBeNull();
  });

  it("a restore storage failure is reported and still settles", async () => {
    const storage = new SessionStorageArea("test", "session");
    vi.spyOn(storage, "readIdToken").mockImplementation(() => {
      throw new Error("storage failed during restore");
    });
    const { engine, onAuthError } = makeHarness({ storage });

    engine.start();

    await vi.waitFor(() => {
      expect(engine.getSnapshot().status).toBe("unauthenticated");
    });
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({ message: "storage failed during restore" }),
    );
  });

  it("an orphaned fresh ID token cannot authenticate the mount", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeIdToken(freshToken());

    engine.start();

    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(storage.readIdToken()).toBeNull();
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("reports device-key initialization failure instead of degrading to unbound", async () => {
    const deviceBinding = fakeDeviceBinding();
    deviceBinding.prepare.mockRejectedValue(
      new Error("convex-logto: IndexedDB unavailable"),
    );
    const { engine, handlers, onAuthError } = makeHarness({ deviceBinding });

    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "convex-logto: IndexedDB unavailable",
      }),
    );
    expect(handlers.callback).not.toHaveBeenCalled();
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("fresh cached ID token → authenticated with zero round-trips", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken("alice"));
    engine.start();
    const snapshot = await settled(engine);
    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.sessionId).toBe("s1");
    expect(snapshot.user?.sub).toBe("alice");
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("cookie reload with a fresh cached token preserves the stored session id", async () => {
    const { engine, storage, handlers } = makeHarness({
      storedSession: {
        token: "legacy-session-secret",
        sessionId: "real-session-id",
      },
      storedIdToken: freshToken("alice"),
      cookieBootstrap: {},
    });
    expect(storage.readSession()).toEqual({
      token: COOKIE_SESSION_MARKER,
      sessionId: "real-session-id",
    });

    engine.start();
    const snapshot = await settled(engine);
    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.sessionId).toBe("real-session-id");
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("cookie reload with an empty session id refreshes once to recover it", async () => {
    const { engine, storage, handlers } = makeHarness({
      storedSession: {
        token: COOKIE_SESSION_MARKER,
        sessionId: "",
      },
      storedIdToken: freshToken("alice"),
    });
    handlers.refresh.mockResolvedValue({
      ...sessionResult(2, "alice"),
      sessionToken: COOKIE_SESSION_MARKER,
    });

    engine.start();
    const snapshot = await settled(engine);
    expect(handlers.refresh).toHaveBeenCalledTimes(1);
    expect(handlers.refresh).toHaveBeenCalledWith({
      sessionToken: COOKIE_SESSION_MARKER,
    });
    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.sessionId).toBe("session-id-2");
    expect(snapshot.user?.sub).toBe("alice");
    expect(storage.readSession()).toEqual({
      token: COOKIE_SESSION_MARKER,
      sessionId: "session-id-2",
    });
  });

  it("empty-id recovery falls back to a fresh cached token on transient failure", async () => {
    const cached = freshToken("alice");
    const { engine, storage, handlers } = makeHarness({
      storedSession: {
        token: COOKIE_SESSION_MARKER,
        sessionId: "",
      },
      storedIdToken: cached,
    });
    handlers.refresh.mockRejectedValue(transientError());

    engine.start();
    const snapshot = await settled(engine);
    expect(handlers.refresh).toHaveBeenCalledTimes(3);
    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.sessionId).toBe("");
    expect(snapshot.user?.sub).toBe("alice");
    expect(storage.readIdToken()).toBe(cached);
    expect(storage.readSession()).toEqual({
      token: COOKIE_SESSION_MARKER,
      sessionId: "",
    });
  });

  it("session with a stale ID token → refresh → authenticated, rotation persisted", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(staleToken());
    handlers.refresh.mockResolvedValue(sessionResult(2));
    engine.start();
    expect((await settled(engine)).status).toBe("authenticated");
    expect(handlers.refresh).toHaveBeenCalledWith({ sessionToken: "t1" });
    expect(storage.readSession()).toEqual({
      token: "session-token-2",
      sessionId: "session-id-2",
    });
  });

  it("bound refresh signs the presented token and sends the PoP once", async () => {
    const deviceBinding = fakeDeviceBinding("proof-for-t1");
    const { engine, storage, handlers } = makeHarness({ deviceBinding });
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(staleToken());
    handlers.refresh.mockResolvedValue(sessionResult(2));

    engine.start();
    expect((await settled(engine)).status).toBe("authenticated");
    expect(deviceBinding.prepare).toHaveBeenCalledTimes(1);
    expect(deviceBinding.sign).toHaveBeenCalledWith("t1");
    expect(handlers.refresh).toHaveBeenCalledWith({
      sessionToken: "t1",
      deviceProof: "proof-for-t1",
    });
  });

  it("terminal refresh on restore → storage cleared, unauthenticated", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.refresh.mockRejectedValue(terminalError());
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(storage.readSession()).toBeNull();
    expect(handlers.refresh).toHaveBeenCalledTimes(1); // terminal: no retries
  });

  it("transient refresh on restore → unauthenticated but the session token SURVIVES", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.refresh.mockRejectedValue(transientError());
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(storage.readSession()).toEqual({ token: "t1", sessionId: "s1" });
    expect(handlers.refresh).toHaveBeenCalledTimes(3); // initial + 2 backoff retries
  });

  it("start is idempotent (StrictMode double-effect)", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.refresh.mockResolvedValue(sessionResult(2));
    engine.start();
    engine.start();
    await settled(engine);
    expect(handlers.refresh).toHaveBeenCalledTimes(1);
  });
});

// --- callback landing --------------------------------------------------------

describe("callback", () => {
  it("matching stash → exchange → authenticated, navigate(returnTo)", async () => {
    const { engine, storage, handlers, navigate } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    handlers.callback.mockResolvedValue({
      ...sessionResult(1),
      returnTo: "/dash",
    });
    engine.start();
    const snapshot = await settled(engine);
    expect(snapshot.status).toBe("authenticated");
    expect(handlers.callback).toHaveBeenCalledWith({
      code: "c1",
      state: "s1",
      redirectUri: "http://localhost:5173/callback",
    });
    expect(storage.readSession()).toEqual({
      token: "session-token-1",
      sessionId: "session-id-1",
    });
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith("/dash"));
    expect(storage.takeTransaction()).toBeNull(); // stash consumed
  });

  it("bound callback captures the device public key in the new session", async () => {
    const deviceBinding = fakeDeviceBinding();
    const { engine, storage, handlers } = makeHarness({ deviceBinding });
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    handlers.callback.mockResolvedValue(sessionResult(1));

    engine.start();
    expect((await settled(engine)).status).toBe("authenticated");
    expect(deviceBinding.getPublicKey).toHaveBeenCalledTimes(1);
    expect(handlers.callback).toHaveBeenCalledWith({
      code: "c1",
      state: "s1",
      redirectUri: "http://localhost:5173/callback",
      devicePublicKey,
    });
  });

  it("a sign-out mid-exchange discards and revokes the minted session", async () => {
    const { engine, storage, handlers } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    const exchange = deferred<ReturnType<typeof sessionResult>>();
    handlers.callback.mockReturnValue(exchange.promise);
    handlers.signOut.mockResolvedValue({});

    engine.start();
    await vi.waitFor(() => expect(handlers.callback).toHaveBeenCalled());
    // The exchange is in flight, so no session is stored yet: sign-out has
    // nothing local to revoke and must not be undone by the response.
    await engine.signOut();
    exchange.resolve(sessionResult(7));
    await vi.waitFor(() =>
      expect(handlers.signOut).toHaveBeenCalledWith(
        expect.objectContaining({ sessionToken: "session-token-7" }),
      ),
    );

    expect(storage.readSession()).toBeNull();
    expect(storage.readIdToken()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("a cross-tab sign-out mid-exchange discards the minted session", async () => {
    const { engine, storage, handlers } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    const exchange = deferred<ReturnType<typeof sessionResult>>();
    handlers.callback.mockReturnValue(exchange.promise);
    handlers.signOut.mockResolvedValue({});

    engine.start();
    await vi.waitFor(() => expect(handlers.callback).toHaveBeenCalled());
    engine.handleExternalSignOut();
    exchange.resolve(sessionResult(8));
    await vi.waitFor(() =>
      expect(handlers.signOut).toHaveBeenCalledWith(
        expect.objectContaining({ sessionToken: "session-token-8" }),
      ),
    );

    expect(storage.readSession()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("a sign-out during the storage flush does not flip back to authenticated", async () => {
    // The credentials are already written at this point, so sign-out finds and
    // revokes the session properly — but the callback must not then re-assert
    // an authenticated snapshot on top of it.
    const { engine, storage, handlers, onAuthError } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    const flushed = deferred<void>();
    const realFlush = storage.flush.bind(storage);
    let signOutDuringFlush: Promise<void> | undefined;
    storage.flush = () => {
      if (signOutDuringFlush === undefined && storage.readSession() !== null) {
        signOutDuringFlush = engine.signOut({ federated: false });
        return flushed.promise;
      }
      return realFlush();
    };
    handlers.callback.mockResolvedValue(sessionResult(9));
    handlers.signOut.mockResolvedValue({});

    engine.start();
    await vi.waitFor(() => expect(signOutDuringFlush).toBeDefined());
    flushed.resolve(undefined);
    await signOutDuringFlush;
    await vi.waitFor(() =>
      expect(engine.getSnapshot().status).not.toBe("restoring"),
    );

    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(storage.readSession()).toBeNull();
    void onAuthError;
  });

  it("an unsafe server returnTo falls back to afterSignIn", async () => {
    const { engine, storage, handlers, navigate } = makeHarness({
      afterSignIn: "/home",
    });
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    handlers.callback.mockResolvedValue({
      ...sessionResult(1),
      returnTo: "//evil.com",
    });
    engine.start();
    await settled(engine);
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith("/home"));
  });

  it("no stash (foreign/forged callback) → refused without calling the exchange", async () => {
    const { engine, handlers, navigate, onAuthError } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(handlers.callback).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalled();
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith("/"));
  });

  it("state mismatch → refused without calling the exchange", async () => {
    const { engine, storage, handlers, onAuthError } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "OTHER" });
    engine.start();
    await settled(engine);
    expect(handlers.callback).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalled();
  });

  it("a refused callback still restores a surviving session", async () => {
    const { engine, storage } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    engine.start();
    expect((await settled(engine)).status).toBe("authenticated");
  });

  it("terminal exchange failure (spent transaction) → report, land in the app, unauthenticated", async () => {
    const { engine, storage, handlers, navigate, onAuthError } = makeHarness();
    setURL("http://localhost:5173/callback?code=c1&state=s1");
    storage.stashTransaction({ state: "s1" });
    handlers.callback.mockRejectedValue(terminalError());
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(onAuthError).toHaveBeenCalled();
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith("/"));
  });

  it("benign ?error=access_denied → back to the app without reporting an error", async () => {
    const { engine, navigate, onAuthError } = makeHarness();
    setURL("http://localhost:5173/callback?error=access_denied&state=s1");
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(onAuthError).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith("/"));
  });

  it("setup ?error=invalid_scope → reported", async () => {
    const { engine, onAuthError } = makeHarness();
    setURL("http://localhost:5173/callback?error=invalid_scope&state=s1");
    engine.start();
    await settled(engine);
    expect(onAuthError).toHaveBeenCalled();
  });

  it("a ?code=&state= on a NON-callback route is ignored", async () => {
    const { engine, handlers } = makeHarness();
    setURL("http://localhost:5173/products?code=c1&state=s1");
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(handlers.callback).not.toHaveBeenCalled();
  });
});

// --- fetchAccessToken --------------------------------------------------------

describe("fetchAccessToken", () => {
  it("serves a fresh cached token without touching the network", async () => {
    const { engine, storage, handlers } = makeHarness();
    const token = freshToken();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(token);
    expect(await engine.fetchAccessToken(false)).toBe(token);
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("refuses an orphaned fresh ID token without a session", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeIdToken(freshToken());

    expect(await engine.fetchAccessToken(false)).toBeNull();
    expect(storage.readIdToken()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("a forced fetch never re-serves the token it just served", async () => {
    const { engine, storage, handlers } = makeHarness();
    const tokenA = freshToken();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(tokenA);
    expect(await engine.fetchAccessToken(false)).toBe(tokenA);
    const next = sessionResult(2);
    handlers.refresh.mockResolvedValue(next);
    expect(await engine.fetchAccessToken(true)).toBe(next.idToken);
    expect(handlers.refresh).toHaveBeenCalledWith({ sessionToken: "t1" });
  });

  it("a forced fetch adopts a token another tab already rotated in", async () => {
    const { engine, storage, handlers } = makeHarness();
    const tokenA = freshToken("a");
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(tokenA);
    expect(await engine.fetchAccessToken(false)).toBe(tokenA);
    // Another tab rotated: new session token + new ID token landed in storage.
    const tokenB = freshToken("b");
    storage.writeSession({ token: "t2", sessionId: "s1" });
    storage.writeIdToken(tokenB);
    expect(await engine.fetchAccessToken(true)).toBe(tokenB);
    expect(handlers.refresh).not.toHaveBeenCalled();
  });

  it("concurrent stale fetches merge into ONE refresh call", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(staleToken());
    const next = sessionResult(2);
    handlers.refresh.mockResolvedValue(next);
    const [a, b] = await Promise.all([
      engine.fetchAccessToken(false),
      engine.fetchAccessToken(false),
    ]);
    expect(a).toBe(next.idToken);
    expect(b).toBe(next.idToken);
    expect(handlers.refresh).toHaveBeenCalledTimes(1);
  });

  it("terminal refresh → clears the session, flips unauthenticated, returns null", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.refresh.mockRejectedValue(terminalError());
    expect(await engine.fetchAccessToken(false)).toBeNull();
    expect(storage.readSession()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("transient refresh → returns null but KEEPS the session token", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.refresh.mockRejectedValue(transientError());
    expect(await engine.fetchAccessToken(false)).toBeNull();
    expect(storage.readSession()).toEqual({ token: "t1", sessionId: "s1" });
  });
});

// --- signIn / signOut --------------------------------------------------------

describe("signIn", () => {
  it("mints the URL, stashes the state, and navigates to Logto", async () => {
    const { engine, storage, handlers } = makeHarness();
    handlers.signIn.mockResolvedValue({
      url: "https://auth.example.com/oidc/auth?state=st-1&code_challenge=ch",
    });
    await engine.signIn({ returnTo: "/dash" });
    expect(handlers.signIn).toHaveBeenCalledWith({
      redirectUri: "http://localhost:5173/callback",
      returnTo: "/dash",
    });
    expect(storage.takeTransaction()).toEqual({ state: "st-1" });
    expect(window.location.assign).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/auth?state=st-1&code_challenge=ch",
    );
  });

  it("rejects an unsafe returnTo before any network call", async () => {
    const { engine, handlers, onAuthError } = makeHarness();
    await expect(
      engine.signIn({ returnTo: "https://evil.com" }),
    ).rejects.toThrow(/same-origin path/);
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(handlers.signIn).not.toHaveBeenCalled();
  });

  it("refuses an unsafe authorization URL returned by the server", async () => {
    const { engine, storage, handlers, onAuthError } = makeHarness();
    handlers.signIn.mockResolvedValue({
      url: "javascript:globalThis.compromised=true//?state=st-1",
    });

    await expect(engine.signIn()).rejects.toThrow(/unsafe javascript: scheme/);

    expect(window.location.assign).not.toHaveBeenCalled();
    expect(storage.takeTransaction()).toBeNull();
    expect(onAuthError).toHaveBeenCalledTimes(1);
  });

  it("reports and rejects a sign-in action failure exactly once", async () => {
    const failure = new Error("Convex unreachable");
    const { engine, handlers, onAuthError } = makeHarness();
    handlers.signIn.mockRejectedValue(failure);

    await expect(engine.signIn()).rejects.toBe(failure);

    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(onAuthError).toHaveBeenCalledWith(failure);
    expect(console.error).toHaveBeenCalledTimes(1);
  });

  it("reports and rejects a device-key preparation failure", async () => {
    const deviceBinding = new WebCryptoSessionDeviceBinding({
      read: () => Promise.reject(new Error("IndexedDB unavailable")),
      add: () => Promise.resolve(true),
    });
    const { engine, handlers, onAuthError } = makeHarness({ deviceBinding });

    await expect(engine.signIn()).rejects.toBeInstanceOf(
      SessionDeviceBindingError,
    );
    expect(onAuthError).toHaveBeenCalledWith(
      expect.any(SessionDeviceBindingError),
    );
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(handlers.signIn).not.toHaveBeenCalled();
  });
});

describe("signOut", () => {
  it("signs a bound token before clearing it and sends the proof", async () => {
    const deviceBinding = fakeDeviceBinding("proof-for-t1");
    const { engine, storage, handlers } = makeHarness({ deviceBinding });
    storage.writeSession({ token: "t1", sessionId: "s1" });
    deviceBinding.sign.mockImplementation((token: string) => {
      expect(token).toBe("t1");
      expect(storage.readSession()).toEqual({ token: "t1", sessionId: "s1" });
      return Promise.resolve("proof-for-t1");
    });

    await engine.signOut({ federated: false });

    expect(handlers.signOut).toHaveBeenCalledWith({
      sessionToken: "t1",
      deviceProof: "proof-for-t1",
      postLogoutRedirectUri: "http://localhost:5173",
    });
    expect(storage.readSession()).toBeNull();
  });

  it("clears locally but never downgrades to proofless sign-out when signing fails", async () => {
    const failure = new Error("device key unavailable");
    const deviceBinding = fakeDeviceBinding();
    deviceBinding.sign.mockRejectedValue(failure);
    const { engine, storage, handlers, onAuthError } = makeHarness({
      deviceBinding,
    });
    storage.writeSession({ token: "t1", sessionId: "s1" });

    await engine.signOut({ federated: false });

    expect(storage.readSession()).toBeNull();
    expect(handlers.signOut).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledWith(failure);
  });

  it("clears storage FIRST, revokes server-side, then ends the SSO session", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    let sessionAtCallTime: unknown = "not-called";
    handlers.signOut.mockImplementation((args: unknown) => {
      sessionAtCallTime = storage.readSession();
      expect(args).toEqual({
        sessionToken: "t1",
        postLogoutRedirectUri: "http://localhost:5173",
      });
      return Promise.resolve({
        endSessionUrl: "https://auth.example.com/oidc/session/end?x",
      });
    });
    await engine.signOut();
    expect(sessionAtCallTime).toBeNull(); // cleared before the network call
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(window.location.assign).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/session/end?x",
    );
  });

  it("local sign-out survives a dead server, and skips the SSO redirect", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOut.mockRejectedValue(new Error("network"));
    await engine.signOut();
    expect(storage.readSession()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("rejects loudly when browser cleanup and server revocation both fail", async () => {
    const sessionKey = "convex-logto:test:session";
    const idTokenKey = "convex-logto:test:idToken";
    const localValues = new Map([
      [sessionKey, JSON.stringify({ token: "t1", sessionId: "s1" })],
    ]);
    const sessionValues = new Map([[idTokenKey, JSON.stringify(freshToken())]]);
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => localValues.get(key) ?? null,
      setItem: () => {
        throw new Error("localStorage write unavailable");
      },
      removeItem: () => {
        throw new Error("localStorage removal unavailable");
      },
    });
    vi.stubGlobal("sessionStorage", {
      getItem: (key: string) => sessionValues.get(key) ?? null,
      setItem: () => {
        throw new Error("sessionStorage write unavailable");
      },
      removeItem: () => {
        throw new Error("sessionStorage removal unavailable");
      },
    });
    const { engine, handlers } = makeHarness();
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));

    await expect(engine.signOut({ federated: false })).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_and_server_revocation_failed",
      serverSessionStatus: "revocation_failed",
    });

    expect(handlers.signOut).toHaveBeenCalledTimes(1);
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(localValues.get(sessionKey)).toContain('"t1"');
    expect(sessionValues.get(idTokenKey)).toContain("eyJ");

    const { engine: coldEngine } = makeHarness();
    coldEngine.start();
    expect((await settled(coldEngine)).status).toBe("authenticated");
  });

  it("resolves a dead-server sign-out only after browser cleanup succeeds on retry", async () => {
    const sessionKey = "convex-logto:test:session";
    const idTokenKey = "convex-logto:test:idToken";
    const local = persistentStorageStub(
      [[sessionKey, JSON.stringify({ token: "t1", sessionId: "s1" })]],
      1,
    );
    const session = persistentStorageStub(
      [[idTokenKey, JSON.stringify(freshToken())]],
      1,
    );
    vi.stubGlobal("localStorage", local.storage);
    vi.stubGlobal("sessionStorage", session.storage);
    const { engine, handlers } = makeHarness();
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));

    await expect(engine.signOut({ federated: false })).resolves.toBeUndefined();

    expect(local.values.has(sessionKey)).toBe(false);
    expect(session.values.has(idTokenKey)).toBe(false);
    const { engine: coldEngine, handlers: coldHandlers } = makeHarness();
    coldEngine.start();
    expect((await settled(coldEngine)).status).toBe("unauthenticated");
    expect(coldHandlers.refresh).not.toHaveBeenCalled();
  });

  it("prioritizes durable browser cleanup failure after successful revocation", async () => {
    const sessionKey = "convex-logto:test:session";
    const idTokenKey = "convex-logto:test:idToken";
    const local = persistentStorageStub(
      [[sessionKey, JSON.stringify({ token: "t1", sessionId: "s1" })]],
      Number.POSITIVE_INFINITY,
    );
    const session = persistentStorageStub(
      [[idTokenKey, JSON.stringify(freshToken())]],
      Number.POSITIVE_INFINITY,
    );
    vi.stubGlobal("localStorage", local.storage);
    vi.stubGlobal("sessionStorage", session.storage);
    const { engine, handlers } = makeHarness();
    handlers.signOut.mockResolvedValue({});

    await expect(engine.signOut({ federated: false })).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_failed",
      serverSessionStatus: "revoked",
    });

    expect(handlers.signOut).toHaveBeenCalledTimes(1);
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("rejects when a surviving session token could refresh after reload", async () => {
    const sessionKey = "convex-logto:test:session";
    const idTokenKey = "convex-logto:test:idToken";
    const local = persistentStorageStub(
      [[sessionKey, JSON.stringify({ token: "t1", sessionId: "s1" })]],
      Number.POSITIVE_INFINITY,
    );
    const session = persistentStorageStub(
      [[idTokenKey, JSON.stringify(freshToken())]],
      0,
    );
    vi.stubGlobal("localStorage", local.storage);
    vi.stubGlobal("sessionStorage", session.storage);
    const { engine, handlers } = makeHarness();
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));

    await expect(engine.signOut({ federated: false })).rejects.toMatchObject({
      code: "local_cleanup_and_server_revocation_failed",
    });

    expect(session.values.has(idTokenKey)).toBe(false);
    const { engine: coldEngine, handlers: coldHandlers } = makeHarness();
    coldHandlers.refresh.mockResolvedValue(sessionResult(2));
    coldEngine.start();
    expect((await settled(coldEngine)).status).toBe("authenticated");
    expect(coldHandlers.refresh).toHaveBeenCalledWith({ sessionToken: "t1" });
  });

  it("rejects an ID-token cleanup failure even though reload fails closed", async () => {
    const sessionKey = "convex-logto:test:session";
    const idTokenKey = "convex-logto:test:idToken";
    const local = persistentStorageStub(
      [[sessionKey, JSON.stringify({ token: "t1", sessionId: "s1" })]],
      0,
    );
    const session = persistentStorageStub(
      [[idTokenKey, JSON.stringify(freshToken())]],
      Number.POSITIVE_INFINITY,
    );
    vi.stubGlobal("localStorage", local.storage);
    vi.stubGlobal("sessionStorage", session.storage);
    const { engine, handlers } = makeHarness();
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));

    await expect(engine.signOut({ federated: false })).rejects.toMatchObject({
      code: "local_cleanup_and_server_revocation_failed",
    });

    expect(local.values.has(sessionKey)).toBe(false);
    expect(session.values.has(idTokenKey)).toBe(true);
    const { engine: coldEngine, handlers: coldHandlers } = makeHarness();
    coldEngine.start();
    expect((await settled(coldEngine)).status).toBe("unauthenticated");
    expect(coldHandlers.refresh).not.toHaveBeenCalled();
  });

  it("still clears the live snapshot and revokes remotely when clearAll throws", async () => {
    const cleanupError = new Error("storage clear unavailable");
    const remoteError = new Error("network unavailable");
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    engine.start();
    expect((await settled(engine)).status).toBe("authenticated");
    vi.spyOn(storage, "clearAll").mockImplementation(() => {
      throw cleanupError;
    });
    handlers.signOut.mockRejectedValue(remoteError);

    await expect(engine.signOut({ federated: false })).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_and_server_revocation_failed",
      serverSessionStatus: "revocation_failed",
      cause: { serverRevocationError: remoteError },
    });

    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(handlers.signOut).toHaveBeenCalledTimes(1);
  });

  it("federated: false skips the SSO redirect", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOut.mockResolvedValue({
      endSessionUrl: "https://auth.example.com/end",
    });
    await engine.signOut({ federated: false });
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("refuses an end-session URL containing credentials", async () => {
    const { engine, storage, handlers, onAuthError } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOut.mockResolvedValue({
      endSessionUrl: "https://alice@auth.example.com/oidc/session/end",
    });

    await expect(engine.signOut()).rejects.toThrow(/credentials/);

    expect(storage.readSession()).toBeNull();
    expect(window.location.assign).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledTimes(1);
  });

  it("signOut with nothing stored is a no-op locally and remotely", async () => {
    const { engine, handlers } = makeHarness();
    await engine.signOut();
    expect(handlers.signOut).not.toHaveBeenCalled();
  });

  it("an old in-flight refresh cannot restore credentials after sign-out", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(staleToken());
    const pendingRefresh = deferred<ReturnType<typeof sessionResult>>();
    handlers.refresh.mockReturnValue(pendingRefresh.promise);
    handlers.signOut.mockResolvedValue({});

    const refreshing = engine.fetchAccessToken(false);
    await vi.waitFor(() => expect(handlers.refresh).toHaveBeenCalledTimes(1));
    await engine.signOut({ federated: false });
    pendingRefresh.resolve(sessionResult(2));

    expect(await refreshing).toBeNull();
    expect(storage.readSession()).toBeNull();
    expect(storage.readIdToken()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });
});

describe("server-held credential sign-out", () => {
  it("rejects and reports when the server revoke fails", async () => {
    // Cookie mode: the credential is an HttpOnly cookie only the server can
    // expire. Reporting success would leave the user signed in.
    const { engine, storage, handlers, onAuthError } = makeHarness({
      serverHeldCredential: true,
      storedSession: { token: "cookie-session", sessionId: "session-id-1" },
    });
    void storage;
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));

    await expect(engine.signOut({ federated: false })).rejects.toThrow(
      /network unavailable/,
    );
    expect(onAuthError).toHaveBeenCalled();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("still resolves for a local credential, but never silently", async () => {
    // A local session token is destroyed without the server, so a dead Logto
    // must not block sign-out — the failure still has to surface.
    const { engine, handlers, onAuthError } = makeHarness({
      storedSession: { token: "local-session", sessionId: "session-id-1" },
    });
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));

    await expect(engine.signOut({ federated: false })).resolves.toBeUndefined();
    expect(onAuthError).toHaveBeenCalled();
  });

  it("treats an empty postLogoutRedirectUri as absent", async () => {
    const { engine, handlers } = makeHarness({
      storedSession: { token: "local-session", sessionId: "session-id-1" },
    });
    handlers.signOut.mockResolvedValue({});

    await engine.signOut({ postLogoutRedirectUri: "  ", federated: false });

    expect(handlers.signOut).toHaveBeenCalledWith(
      expect.objectContaining({
        postLogoutRedirectUri: "http://localhost:5173",
      }),
    );
  });
});

describe("signOutEverywhere", () => {
  it("sends device proof before revoking every bound session", async () => {
    const deviceBinding = fakeDeviceBinding("proof-for-t1");
    const { engine, storage, handlers } = makeHarness({ deviceBinding });
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOutEverywhere.mockResolvedValue({ count: 1 });

    await engine.signOutEverywhere();

    expect(handlers.signOutEverywhere).toHaveBeenCalledWith({
      sessionToken: "t1",
      deviceProof: "proof-for-t1",
      postLogoutRedirectUri: "http://localhost:5173",
    });
  });

  it("rejects without a proofless fallback when bound signing fails", async () => {
    const failure = new Error("device key unavailable");
    const deviceBinding = fakeDeviceBinding();
    deviceBinding.sign.mockRejectedValue(failure);
    const { engine, storage, handlers, onAuthError } = makeHarness({
      deviceBinding,
    });
    storage.writeSession({ token: "t1", sessionId: "s1" });

    await expect(engine.signOutEverywhere()).rejects.toBe(failure);

    expect(storage.readSession()).toBeNull();
    expect(handlers.signOutEverywhere).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledWith(failure);
  });

  it("prioritizes combined cleanup failure over the remote fatal error", async () => {
    const remoteError = new Error("subject revocation unavailable");
    const sessionKey = "convex-logto:test:session";
    const idTokenKey = "convex-logto:test:idToken";
    const local = persistentStorageStub(
      [[sessionKey, JSON.stringify({ token: "t1", sessionId: "s1" })]],
      Number.POSITIVE_INFINITY,
    );
    const session = persistentStorageStub(
      [[idTokenKey, JSON.stringify(freshToken())]],
      Number.POSITIVE_INFINITY,
    );
    vi.stubGlobal("localStorage", local.storage);
    vi.stubGlobal("sessionStorage", session.storage);
    const { engine, handlers } = makeHarness();
    handlers.signOutEverywhere.mockRejectedValue(remoteError);

    await expect(engine.signOutEverywhere()).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_and_server_revocation_failed",
      serverSessionStatus: "revocation_failed",
      cause: { serverRevocationError: remoteError },
    });

    expect(handlers.signOutEverywhere).toHaveBeenCalledTimes(1);
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("clears local state first, kills the subject sessions, then navigates to Logto", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    let sessionAtCallTime: unknown = "not-called";
    handlers.signOutEverywhere.mockImplementation((args: unknown) => {
      sessionAtCallTime = storage.readSession();
      expect(args).toEqual({
        sessionToken: "t1",
        postLogoutRedirectUri: "https://app.example.com/signed-out",
      });
      return Promise.resolve({
        count: 3,
        endSessionUrl: "https://auth.example.com/oidc/session/end?all=1",
      });
    });

    await engine.signOutEverywhere({
      postLogoutRedirectUri: "https://app.example.com/signed-out",
    });

    expect(sessionAtCallTime).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(window.location.assign).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/session/end?all=1",
    );
  });

  it("clears locally before reporting a legacy app module's missing action", async () => {
    const legacyApi = {
      signIn: api.signIn,
      callback: api.callback,
      refresh: api.refresh,
      signOut: api.signOut,
      sessionValid: api.sessionValid,
    } as LogtoSessionApi;
    const { engine, storage, handlers, onAuthError } = makeHarness({
      sessionApi: legacyApi,
    });
    storage.writeSession({ token: "t1", sessionId: "s1" });

    await expect(engine.signOutEverywhere()).rejects.toThrow(
      /Re-export signOutEverywhere from logtoSessionApi/,
    );

    expect(storage.readSession()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(handlers.signOutEverywhere).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringMatching(/sessionApi does not export it/),
      }),
    );
  });

  it("translates the generated-api proxy's missing-function response", async () => {
    const { engine, storage, handlers, onAuthError } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOutEverywhere.mockRejectedValue(
      new Error("Could not find public function auth:signOutEverywhere"),
    );

    await expect(engine.signOutEverywhere()).rejects.toThrow(
      /Re-export signOutEverywhere from logtoSessionApi/,
    );

    expect(storage.readSession()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({ name: "Error" }),
    );
  });

  it("rejects a server failure after completing the unblockable local clear", async () => {
    const { engine, storage, handlers, onAuthError } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOutEverywhere.mockRejectedValue(
      new Error("network unavailable"),
    );

    await expect(engine.signOutEverywhere()).rejects.toThrow(
      "network unavailable",
    );

    expect(storage.readSession()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({ message: "network unavailable" }),
    );
  });
});

// --- external events ---------------------------------------------------------

describe("external events", () => {
  it("handleRevoked clears everything and flips unauthenticated", async () => {
    const { engine, storage } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    engine.start();
    await settled(engine);
    engine.handleRevoked();
    expect(storage.readSession()).toBeNull();
    expect(storage.readIdToken()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("handleExternalSignOut clears this tab's bearer and flips unauthenticated", async () => {
    const { engine, storage } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    engine.start();
    await settled(engine);
    // The other tab already removed the localStorage session; mirror that.
    localStorage.removeItem(storage.sessionEventKey);
    engine.handleExternalSignOut();
    expect(storage.readIdToken()).toBeNull();
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });
});

describe("session management", () => {
  const summary = {
    sessionId: "s2",
    current: false,
    createdAt: 1,
    lastRefreshedAt: 2,
    deviceBound: false,
  };

  it("authenticates the list with the current token and its device proof", async () => {
    const deviceBinding = fakeDeviceBinding("proof-for-t1");
    const { engine, storage, handlers } = makeHarness({ deviceBinding });
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.listSessions.mockResolvedValue({
      sessions: [summary],
      truncated: false,
    });

    await expect(engine.listSessions()).resolves.toEqual({
      sessions: [summary],
      truncated: false,
    });
    expect(handlers.listSessions).toHaveBeenCalledWith({
      sessionToken: "t1",
      deviceProof: "proof-for-t1",
    });
  });

  it("omits the proof field entirely for an unbound session", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.listSessions.mockResolvedValue({ sessions: [], truncated: false });

    await engine.listSessions();

    expect(handlers.listSessions).toHaveBeenCalledWith({ sessionToken: "t1" });
  });

  it("passes a label through and treats undefined as a clear", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.renameSession.mockResolvedValue(true);

    await expect(engine.renameSession("s2", "Phone")).resolves.toBe(true);
    expect(handlers.renameSession).toHaveBeenCalledWith({
      sessionToken: "t1",
      targetSessionId: "s2",
      label: "Phone",
    });

    await engine.renameSession("s2", undefined);
    expect(handlers.renameSession).toHaveBeenLastCalledWith({
      sessionToken: "t1",
      targetSessionId: "s2",
    });
  });

  it("revokes another session without touching this client's credentials", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    storage.writeIdToken(freshToken());
    handlers.revokeSession.mockResolvedValue(true);

    await expect(engine.revokeSession("s2")).resolves.toBe(true);

    expect(handlers.revokeSession).toHaveBeenCalledWith({
      sessionToken: "t1",
      targetSessionId: "s2",
    });
    expect(storage.readSession()).toEqual({ token: "t1", sessionId: "s1" });
  });

  it.each([
    ["listSessions", (engine: SessionAuthEngine) => engine.listSessions()],
    [
      "renameSession",
      (engine: SessionAuthEngine) => engine.renameSession("s2", "Phone"),
    ],
    [
      "revokeSession",
      (engine: SessionAuthEngine) => engine.revokeSession("s2"),
    ],
  ])("rejects %s without an active session", async (_name, call) => {
    const { engine, handlers } = makeHarness();

    await expect(call(engine)).rejects.toThrow(/requires an active session/);
    expect(handlers.listSessions).not.toHaveBeenCalled();
    expect(handlers.renameSession).not.toHaveBeenCalled();
    expect(handlers.revokeSession).not.toHaveBeenCalled();
  });

  it.each([
    ["listSessions", (engine: SessionAuthEngine) => engine.listSessions()],
    [
      "renameSession",
      (engine: SessionAuthEngine) => engine.renameSession("s2", "Phone"),
    ],
    [
      "revokeSession",
      (engine: SessionAuthEngine) => engine.revokeSession("s2"),
    ],
  ])(
    "reports the upgrade hint when %s is not re-exported",
    async (name, call) => {
      const legacyApi = {
        signIn: api.signIn,
        callback: api.callback,
        refresh: api.refresh,
        signOut: api.signOut,
        signOutEverywhere: api.signOutEverywhere,
        sessionValid: api.sessionValid,
      } as LogtoSessionApi;
      const { engine, storage } = makeHarness({ sessionApi: legacyApi });
      storage.writeSession({ token: "t1", sessionId: "s1" });

      await expect(call(engine)).rejects.toThrow(
        new RegExp(`Re-export ${name} from logtoSessionApi`),
      );
      // Unlike sign-out, a failed management call must leave the session alone.
      expect(storage.readSession()).toEqual({ token: "t1", sessionId: "s1" });
    },
  );

  it("translates a deployed-but-stale module's missing-function error", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.listSessions.mockRejectedValue(
      new Error("Could not find public function auth:listSessions"),
    );

    await expect(engine.listSessions()).rejects.toThrow(
      /Re-export listSessions from logtoSessionApi/,
    );
  });

  it("translates the cookie handler's 409 upgrade response", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.revokeSession.mockRejectedValue(
      new ConvexError({
        kind: "terminal",
        code: "session_management_unavailable",
        message: "sessionApi must re-export revokeSession",
      }),
    );

    await expect(engine.revokeSession("s2")).rejects.toThrow(
      /Re-export revokeSession from logtoSessionApi/,
    );
  });

  it("surfaces an ordinary failure unchanged", async () => {
    const failure = transientError();
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.listSessions.mockRejectedValue(failure);

    await expect(engine.listSessions()).rejects.toBe(failure);
  });
});

describe("client descriptor", () => {
  const completeCallback = async (options?: {
    clientDescriptor?: { platform?: string; os?: string; browser?: string };
  }) => {
    const harness = makeHarness(options);
    harness.storage.stashTransaction({ state: "st" });
    setURL("http://localhost:5173/callback?code=c&state=st");
    harness.handlers.callback.mockResolvedValue({
      idToken: freshToken(),
      sessionToken: "t1",
      sessionId: "s1",
    });
    harness.engine.start();
    await settled(harness.engine);
    return harness;
  };

  it("stamps the app-supplied descriptor on the session at sign-in", async () => {
    const harness = await completeCallback({
      clientDescriptor: { platform: "web", browser: "Firefox" },
    });

    expect(harness.handlers.callback).toHaveBeenCalledWith(
      expect.objectContaining({
        client: { platform: "web", browser: "Firefox" },
      }),
    );
  });

  it("sends nothing when every field is blank or absent", async () => {
    for (const clientDescriptor of [
      undefined,
      { platform: "  ", os: "", browser: undefined },
    ]) {
      const harness = await completeCallback({ clientDescriptor });

      expect(harness.handlers.callback.mock.calls[0]?.[0]).not.toHaveProperty(
        "client",
      );
      localStorage.clear();
      sessionStorage.clear();
    }
  });

  it("drops blank fields but keeps the filled ones", async () => {
    const harness = await completeCallback({
      clientDescriptor: { platform: " ", os: " macOS ", browser: "" },
    });

    expect(harness.handlers.callback).toHaveBeenCalledWith(
      expect.objectContaining({ client: { os: "macOS" } }),
    );
  });
});
