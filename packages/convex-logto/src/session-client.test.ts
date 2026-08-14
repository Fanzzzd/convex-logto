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
  type SessionTransport,
  type StoredSession,
  type TokenStorageKind,
} from "./session-client";
import type { LogtoSessionApi } from "./session";
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
  sessionValid: { fn: "sessionValid" },
} as unknown as LogtoSessionApi;

type Handlers = {
  signIn: ReturnType<typeof vi.fn>;
  callback: ReturnType<typeof vi.fn>;
  refresh: ReturnType<typeof vi.fn>;
  signOut: ReturnType<typeof vi.fn>;
};

function makeHarness(options?: {
  tokenStorage?: TokenStorageKind;
  afterSignIn?: string;
  initialToken?: string;
  initialSession?: StoredSession;
  storedIdToken?: string;
  storedSession?: StoredSession;
  cookieBootstrap?: { initialSessionId?: string | null };
}) {
  const handlers: Handlers = {
    signIn: vi.fn(),
    callback: vi.fn(),
    refresh: vi.fn(),
    signOut: vi.fn(),
  };
  const transport = {
    action: (ref: unknown, args: unknown) =>
      handlers[(ref as { fn: keyof Handlers }).fn](args),
  } as SessionTransport;
  const storage = new SessionStorageArea(
    "test",
    options?.tokenStorage ?? "session",
  );
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
    api,
    storage,
    callbackPath: "/callback",
    afterSignIn: options?.afterSignIn ?? "/",
    initialToken: options?.initialToken,
    initialSession,
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

beforeEach(() => {
  setURL("http://localhost:5173/");
  localStorage.clear();
  sessionStorage.clear();
  vi.spyOn(window.location, "assign").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
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

  it("nothing stored → unauthenticated, no network", async () => {
    const { engine, handlers } = makeHarness();
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
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
    const { engine, handlers } = makeHarness();
    await expect(
      engine.signIn({ returnTo: "https://evil.com" }),
    ).rejects.toThrow(/same-origin path/);
    expect(handlers.signIn).not.toHaveBeenCalled();
  });
});

describe("signOut", () => {
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

  it("federated: false skips the SSO redirect", async () => {
    const { engine, storage, handlers } = makeHarness();
    storage.writeSession({ token: "t1", sessionId: "s1" });
    handlers.signOut.mockResolvedValue({
      endSessionUrl: "https://auth.example.com/end",
    });
    await engine.signOut({ federated: false });
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("signOut with nothing stored is a no-op locally and remotely", async () => {
    const { engine, handlers } = makeHarness();
    await engine.signOut();
    expect(handlers.signOut).not.toHaveBeenCalled();
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
