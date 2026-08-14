import type { LogtoSessionApi } from "./session";
import {
  createNativeSessionAuthFlow,
  NativeSessionStorageArea,
  NativeSessionStorageError,
  type NativeSecureStore,
  type NativeWebBrowser,
} from "./native-session-client";
import {
  SessionAuthEngine,
  SessionSignOutError,
  type SessionSnapshot,
  type SessionTransport,
  type StoredSession,
} from "./session-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function fakeIdToken(payload: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "RS256" })}.${encode(payload)}.signature`;
}

const freshToken = (sub = "native-user") =>
  fakeIdToken({ sub, exp: Math.floor(Date.now() / 1000) + 3600 });
const staleToken = () =>
  fakeIdToken({ sub: "native-user", exp: Math.floor(Date.now() / 1000) + 10 });

type FakeSecureStore = NativeSecureStore & { data: Map<string, string> };

function fakeSecureStore(): FakeSecureStore {
  const data = new Map<string, string>();
  return {
    data,
    isAvailableAsync: vi.fn().mockResolvedValue(true),
    getItemAsync: vi.fn((key: string) =>
      Promise.resolve(data.get(key) ?? null),
    ),
    setItemAsync: vi.fn((key: string, value: string) => {
      data.set(key, value);
      return Promise.resolve();
    }),
    deleteItemAsync: vi.fn((key: string) => {
      data.delete(key);
      return Promise.resolve();
    }),
  };
}

function fakeWebBrowser(
  result: { type: string; url?: string } = {
    type: "success",
    url: "io.logto://callback?code=code-1&state=state-1",
  },
): NativeWebBrowser & {
  openAuthSessionAsync: ReturnType<typeof vi.fn>;
} {
  return {
    openAuthSessionAsync: vi.fn().mockResolvedValue(result),
  };
}

const api = {
  signIn: { fn: "signIn" },
  callback: { fn: "callback" },
  refresh: { fn: "refresh" },
  signOut: { fn: "signOut" },
  signOutEverywhere: { fn: "signOutEverywhere" },
  sessionValid: { fn: "sessionValid" },
} as unknown as LogtoSessionApi;

type Handlers = {
  signIn: ReturnType<typeof vi.fn>;
  callback: ReturnType<typeof vi.fn>;
  refresh: ReturnType<typeof vi.fn>;
  signOut: ReturnType<typeof vi.fn>;
  signOutEverywhere: ReturnType<typeof vi.fn>;
};

function makeHarness(options?: {
  secureStore?: FakeSecureStore;
  webBrowser?: ReturnType<typeof fakeWebBrowser>;
  initialToken?: string;
  initialSession?: StoredSession;
}) {
  const secureStore = options?.secureStore ?? fakeSecureStore();
  const webBrowser = options?.webBrowser ?? fakeWebBrowser();
  const storage = new NativeSessionStorageArea(
    "https://native.convex.cloud",
    secureStore,
  );
  const handlers: Handlers = {
    signIn: vi.fn().mockResolvedValue({
      url: "https://auth.example.com/oidc/auth?state=state-1",
    }),
    callback: vi.fn().mockResolvedValue({
      idToken: freshToken(),
      sessionToken: "session-token-1",
      sessionId: "session-id-1",
    }),
    refresh: vi.fn().mockResolvedValue({
      idToken: freshToken("refreshed-user"),
      sessionToken: "session-token-2",
      sessionId: "session-id-1",
    }),
    signOut: vi.fn().mockResolvedValue({
      endSessionUrl: "https://auth.example.com/oidc/session/end",
    }),
    signOutEverywhere: vi.fn().mockResolvedValue({
      count: 2,
      endSessionUrl: "https://auth.example.com/oidc/session/end?all=1",
    }),
  };
  const transport = {
    action: (reference: unknown, args: unknown) =>
      handlers[(reference as { fn: keyof Handlers }).fn](args),
  } as SessionTransport;
  const onAuthError = vi.fn();
  const navigate = vi.fn();
  const engine = new SessionAuthEngine({
    transport,
    api,
    storage,
    callbackPath: "",
    afterSignIn: "",
    initialToken: options?.initialToken,
    initialSession: options?.initialSession,
    authFlow: createNativeSessionAuthFlow("io.logto://callback", webBrowser),
    navigate,
    onAuthError,
    sleep: () => Promise.resolve(),
  });
  return {
    engine,
    storage,
    secureStore,
    webBrowser,
    handlers,
    onAuthError,
    navigate,
  };
}

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

async function seedSession(
  secureStore: FakeSecureStore,
  idToken: string,
): Promise<void> {
  const storage = new NativeSessionStorageArea(
    "https://native.convex.cloud",
    secureStore,
  );
  await storage.prepare();
  storage.writeSession({
    token: "session-token-old",
    sessionId: "session-id-1",
  });
  storage.writeIdToken(idToken);
  await storage.flush();
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("native session adapters", () => {
  it("completes system-browser sign-in and durably stores the session", async () => {
    const { engine, storage, webBrowser, handlers, secureStore } =
      makeHarness();
    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");

    await engine.signIn();

    expect(handlers.signIn).toHaveBeenCalledWith({
      redirectUri: "io.logto://callback",
      returnTo: undefined,
    });
    expect(webBrowser.openAuthSessionAsync).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/auth?state=state-1",
      "io.logto://callback",
    );
    expect(handlers.callback).toHaveBeenCalledWith({
      code: "code-1",
      state: "state-1",
      redirectUri: "io.logto://callback",
    });
    expect(storage.readSession()).toEqual({
      token: "session-token-1",
      sessionId: "session-id-1",
    });
    expect(storage.readIdToken()).toBeTruthy();
    expect(storage.takeTransaction()).toBeNull();
    expect(engine.getSnapshot()).toMatchObject({
      status: "authenticated",
      sessionId: "session-id-1",
      user: { sub: "native-user" },
    });
    expect(secureStore.data.size).toBe(2);
  });

  it("shares one native sign-in flow across concurrent calls", async () => {
    let finishBrowser!: (result: { type: string; url?: string }) => void;
    const webBrowser = fakeWebBrowser();
    webBrowser.openAuthSessionAsync.mockImplementation(
      () =>
        new Promise((resolve) => {
          finishBrowser = resolve;
        }),
    );
    const { engine, handlers } = makeHarness({ webBrowser });
    engine.start();
    await settled(engine);

    const first = engine.signIn();
    const second = engine.signIn();

    expect(second).toBe(first);
    await vi.waitFor(() => {
      expect(webBrowser.openAuthSessionAsync).toHaveBeenCalledTimes(1);
    });
    expect(handlers.signIn).toHaveBeenCalledTimes(1);

    finishBrowser({ type: "cancel" });
    await Promise.all([first, second]);
  });

  it("hydrates a cold start and rotates a stale session token", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, staleToken());
    const { engine, storage, handlers } = makeHarness({ secureStore });

    engine.start();
    const snapshot = await settled(engine);

    expect(handlers.refresh).toHaveBeenCalledWith({
      sessionToken: "session-token-old",
    });
    expect(snapshot).toMatchObject({
      status: "authenticated",
      sessionId: "session-id-1",
      user: { sub: "refreshed-user" },
    });
    expect(storage.readSession()?.token).toBe("session-token-2");

    const coldStart = new NativeSessionStorageArea(
      "https://native.convex.cloud",
      secureStore,
    );
    await coldStart.prepare();
    expect(coldStart.readSession()?.token).toBe("session-token-2");
  });

  it("clears SecureStore when reactive revocation fires", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    const { engine, storage } = makeHarness({ secureStore });
    engine.start();
    expect((await settled(engine)).status).toBe("authenticated");

    engine.handleRevoked();
    await storage.flush();

    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(secureStore.data.size).toBe(0);
  });

  it("uses a custom post-logout URI for the action and browser return", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    const webBrowser = fakeWebBrowser({ type: "dismiss" });
    const { engine, handlers } = makeHarness({ secureStore, webBrowser });
    handlers.signOut.mockImplementation(() => {
      expect(secureStore.data.size).toBe(0);
      return Promise.resolve({
        endSessionUrl: "https://auth.example.com/oidc/session/end",
      });
    });
    engine.start();
    await settled(engine);

    await engine.signOut({
      postLogoutRedirectUri: "io.logto://signed-out",
    });

    expect(handlers.signOut).toHaveBeenCalledWith({
      sessionToken: "session-token-old",
      postLogoutRedirectUri: "io.logto://signed-out",
    });
    expect(webBrowser.openAuthSessionAsync).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/session/end",
      "io.logto://signed-out",
    );
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("signs out every device and completes federated logout in the native browser", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    const webBrowser = fakeWebBrowser({ type: "dismiss" });
    const { engine, handlers } = makeHarness({ secureStore, webBrowser });
    handlers.signOutEverywhere.mockImplementation(() => {
      expect(secureStore.data.size).toBe(0);
      return Promise.resolve({
        count: 2,
        endSessionUrl: "https://auth.example.com/oidc/session/end?all=1",
      });
    });
    engine.start();
    await settled(engine);

    await engine.signOutEverywhere({
      postLogoutRedirectUri: "io.logto://signed-out-everywhere",
    });

    expect(handlers.signOutEverywhere).toHaveBeenCalledWith({
      sessionToken: "session-token-old",
      postLogoutRedirectUri: "io.logto://signed-out-everywhere",
    });
    expect(webBrowser.openAuthSessionAsync).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/session/end?all=1",
      "io.logto://signed-out-everywhere",
    );
    expect(engine.getSnapshot().status).toBe("unauthenticated");
  });

  it("preserves loud durable-cleanup failure semantics for sign out everywhere", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    secureStore.deleteItemAsync = vi
      .fn()
      .mockRejectedValue(new Error("keystore delete failed"));
    const { engine, handlers, onAuthError } = makeHarness({ secureStore });
    engine.start();
    await settled(engine);

    await expect(engine.signOutEverywhere()).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_failed",
      serverSessionStatus: "revoked",
    });

    expect(handlers.signOutEverywhere).toHaveBeenCalledTimes(1);
    expect(secureStore.deleteItemAsync).toHaveBeenCalledTimes(6);
    expect(secureStore.data.size).toBe(2);
    expect(onAuthError).toHaveBeenCalledWith(expect.any(SessionSignOutError));
  });

  it("rejects loudly when durable cleanup and server revocation both fail", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    secureStore.deleteItemAsync = vi
      .fn()
      .mockRejectedValue(new Error("keystore delete failed"));
    const { engine, handlers, onAuthError } = makeHarness({ secureStore });
    handlers.signOut.mockRejectedValue(new Error("network unavailable"));
    engine.start();
    await settled(engine);

    await expect(engine.signOut()).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_and_server_revocation_failed",
      serverSessionStatus: "revocation_failed",
      message: expect.stringMatching(/did not complete/),
    });

    expect(handlers.signOut).toHaveBeenCalledTimes(1);
    expect(secureStore.deleteItemAsync).toHaveBeenCalledTimes(6);
    expect(secureStore.data.size).toBe(2);
    expect(onAuthError).toHaveBeenCalledWith(expect.any(SessionSignOutError));
  });

  it("returns normally when a failed durable cleanup succeeds on retry", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    let firstDelete = true;
    secureStore.deleteItemAsync = vi.fn((key: string) => {
      if (firstDelete) {
        firstDelete = false;
        return Promise.reject(new Error("keystore delete failed"));
      }
      secureStore.data.delete(key);
      return Promise.resolve();
    });
    const { engine, handlers, onAuthError } = makeHarness({ secureStore });
    engine.start();
    await settled(engine);

    await expect(engine.signOut({ federated: false })).resolves.toBeUndefined();

    expect(handlers.signOut).toHaveBeenCalledTimes(1);
    expect(secureStore.deleteItemAsync).toHaveBeenCalledTimes(6);
    expect(secureStore.data.size).toBe(0);
    expect(onAuthError).toHaveBeenCalledWith(
      expect.any(NativeSessionStorageError),
    );
    expect(onAuthError).not.toHaveBeenCalledWith(
      expect.any(SessionSignOutError),
    );
  });

  it("rejects distinctly when revocation succeeds but durable cleanup fails twice", async () => {
    const secureStore = fakeSecureStore();
    await seedSession(secureStore, freshToken());
    secureStore.deleteItemAsync = vi
      .fn()
      .mockRejectedValue(new Error("keystore delete failed"));
    const { engine, handlers, onAuthError } = makeHarness({ secureStore });
    engine.start();
    await settled(engine);

    await expect(engine.signOut({ federated: false })).rejects.toMatchObject({
      name: "SessionSignOutError",
      code: "local_cleanup_failed",
      serverSessionStatus: "revoked",
      message: expect.stringMatching(/server session was revoked/),
    });

    expect(handlers.signOut).toHaveBeenCalledTimes(1);
    expect(secureStore.deleteItemAsync).toHaveBeenCalledTimes(6);
    expect(secureStore.data.size).toBe(2);
    expect(onAuthError).toHaveBeenCalledWith(expect.any(SessionSignOutError));
  });

  it("refuses a foreign return and a replay after its state is spent", async () => {
    const webBrowser = fakeWebBrowser({
      type: "success",
      url: "io.logto://callback?code=attacker-code&state=foreign-state",
    });
    const { engine, storage, handlers, onAuthError } = makeHarness({
      webBrowser,
    });
    engine.start();
    await settled(engine);

    await engine.signIn();
    expect(handlers.callback).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringMatching(/doesn't match/),
      }),
    );
    expect(storage.takeTransaction()).toBeNull();

    await engine.completeSignIn(
      "io.logto://callback?code=late-code&state=state-1",
      "io.logto://callback",
    );
    expect(handlers.callback).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledTimes(2);
  });

  it("refuses a return when the authorization URL had no state", async () => {
    const { engine, handlers, onAuthError } = makeHarness();
    handlers.signIn.mockResolvedValue({
      url: "https://auth.example.com/oidc/auth",
    });
    engine.start();
    await settled(engine);

    await engine.signIn();

    expect(handlers.callback).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringMatching(/doesn't match/),
      }),
    );
  });

  it("clears an abandoned state before handling an authorize URL without state", async () => {
    const { engine, storage, handlers, onAuthError } = makeHarness();
    engine.start();
    await settled(engine);
    storage.stashTransaction({ state: "state-1" });
    await storage.flush();
    handlers.signIn.mockResolvedValue({
      url: "https://auth.example.com/oidc/auth",
    });

    await engine.signIn();

    expect(handlers.callback).not.toHaveBeenCalled();
    expect(storage.takeTransaction()).toBeNull();
    expect(onAuthError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringMatching(/doesn't match/),
      }),
    );
  });

  it("spends the state without exchanging when the system browser is cancelled", async () => {
    const webBrowser = fakeWebBrowser({ type: "cancel" });
    const { engine, storage, handlers, onAuthError } = makeHarness({
      webBrowser,
    });
    engine.start();
    await settled(engine);

    await engine.signIn();

    expect(storage.takeTransaction()).toBeNull();
    expect(handlers.callback).not.toHaveBeenCalled();
    expect(onAuthError).not.toHaveBeenCalled();
  });

  it("fails loudly when SecureStore is unavailable", async () => {
    const secureStore = fakeSecureStore();
    secureStore.isAvailableAsync = vi.fn().mockResolvedValue(false);
    const { engine, onAuthError } = makeHarness({ secureStore });

    engine.start();
    expect((await settled(engine)).status).toBe("unauthenticated");
    expect(onAuthError).toHaveBeenCalledWith(
      expect.any(NativeSessionStorageError),
    );
  });

  it("drops the live auth snapshot when sign-out storage preparation fails", async () => {
    const secureStore = fakeSecureStore();
    secureStore.isAvailableAsync = vi.fn().mockResolvedValue(false);
    const { engine, storage, handlers, onAuthError } = makeHarness({
      secureStore,
      initialToken: freshToken(),
      initialSession: {
        token: "session-token-old",
        sessionId: "session-id-1",
      },
    });
    expect(engine.getSnapshot().status).toBe("authenticated");

    await expect(engine.signOut()).rejects.toBeInstanceOf(
      NativeSessionStorageError,
    );

    expect(engine.getSnapshot().status).toBe("unauthenticated");
    expect(storage.readSession()).toBeNull();
    expect(handlers.signOut).not.toHaveBeenCalled();
    expect(onAuthError).toHaveBeenCalledWith(
      expect.any(NativeSessionStorageError),
    );
  });

  it("reports a SecureStore write failure instead of opening the browser", async () => {
    const secureStore = fakeSecureStore();
    secureStore.setItemAsync = vi
      .fn()
      .mockRejectedValue(new Error("keystore write failed"));
    const { engine, webBrowser, onAuthError } = makeHarness({ secureStore });
    engine.start();
    await settled(engine);

    await expect(engine.signIn()).rejects.toBeInstanceOf(
      NativeSessionStorageError,
    );
    expect(onAuthError).toHaveBeenCalledWith(
      expect.any(NativeSessionStorageError),
    );
    expect(webBrowser.openAuthSessionAsync).not.toHaveBeenCalled();
  });
});
