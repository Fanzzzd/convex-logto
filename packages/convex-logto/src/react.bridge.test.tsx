// @vitest-environment happy-dom
//
// Bridge-behavior tests: what the provider reports to Convex (`useAuth`), how
// callback handling is gated to `callbackPath` (regression conditions C1/C7 of
// the 0.4 tightening), the `signIn({ returnTo })` contract, and the
// fetchAccessToken in-flight merge. `@logto/react` and `convex/react` are
// mocked at the module boundary so every input is controllable.
import { StrictMode, act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ConvexLogtoProviderProps } from "./react";
import { ConvexLogtoProvider, useLogtoAuth } from "./react";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

// --- module mocks -----------------------------------------------------------

const mockLogto = {
  isAuthenticated: false,
  isLoading: false,
  error: undefined as Error | undefined,
  getIdToken: vi.fn<() => Promise<string | undefined>>(async () => "id-token"),
  getAccessToken: vi.fn<() => Promise<string | undefined>>(async () => "at"),
  clearAccessToken: vi.fn<() => Promise<void>>(async () => {}),
  getIdTokenClaims: vi.fn<() => Promise<undefined>>(async () => undefined),
  signIn: vi.fn<(redirectUri?: string) => Promise<void>>(async () => {}),
  signOut: vi.fn<(postLogoutRedirectUri?: string) => Promise<void>>(
    async () => {},
  ),
};

vi.mock("@logto/react", () => ({
  LogtoProvider: ({ children }: { children: unknown }) => children,
  useLogto: () => mockLogto,
  useHandleSignInCallback: () => ({
    isLoading: false,
    isAuthenticated: false,
    error: undefined,
  }),
  UserScope: { Email: "email" },
}));

type CapturedAuth = {
  isLoading: boolean;
  isAuthenticated: boolean;
  fetchAccessToken: (args: {
    forceRefreshToken: boolean;
  }) => Promise<string | null>;
};
let capturedAuth: CapturedAuth | null = null;

vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({
    useAuth,
    children,
  }: {
    useAuth: () => CapturedAuth;
    children: unknown;
  }) => {
    capturedAuth = useAuth();
    return children;
  },
  useConvexAuth: () => ({ isLoading: false, isAuthenticated: false }),
}));

// --- harness ----------------------------------------------------------------

const config = { endpoint: "https://example.logto.app", appId: "app123" };
const fakeClientValue = {};
const fakeClient = fakeClientValue as never;

type AuthApi = ReturnType<typeof useLogtoAuth>;
let capturedApi: AuthApi | null = null;
function ApiProbe() {
  capturedApi = useLogtoAuth();
  return null;
}

let root: Root | null = null;
function providerTree(
  props?: Partial<ConvexLogtoProviderProps> & { probe?: boolean },
) {
  const { probe, ...rest } = props ?? {};
  // The config XOR configQuery union rejects partial spreads; the harness always
  // supplies static `config`, so pin the spread to that branch of the union.
  const merged = { client: fakeClient, config, ...rest } as unknown as Omit<
    Extract<ConvexLogtoProviderProps, { config: typeof config }>,
    "children"
  >;
  return (
    <ConvexLogtoProvider {...merged}>
      {probe ? <ApiProbe /> : <span />}
    </ConvexLogtoProvider>
  );
}

async function renderProvider(
  props?: Partial<ConvexLogtoProviderProps> & { probe?: boolean },
) {
  root = createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(providerTree(props));
  });
}

async function rerenderProvider(
  props?: Partial<ConvexLogtoProviderProps> & { probe?: boolean },
) {
  if (root === null) throw new Error("renderProvider must run first");
  await act(async () => {
    root!.render(providerTree(props));
  });
}

function setUrl(url: string) {
  (
    window as unknown as { happyDOM: { setURL: (url: string) => void } }
  ).happyDOM.setURL(url);
}

beforeEach(() => {
  setUrl("http://localhost:3000/");
  mockLogto.isAuthenticated = false;
  mockLogto.isLoading = false;
  mockLogto.error = undefined;
  // Reset call history AND implementations back to the defaults — a plain
  // clearAllMocks leaves per-test implementations behind to leak forward.
  mockLogto.getIdToken.mockReset().mockResolvedValue("id-token");
  mockLogto.getAccessToken.mockReset().mockResolvedValue("at");
  mockLogto.clearAccessToken.mockReset().mockResolvedValue(undefined);
  mockLogto.getIdTokenClaims.mockReset().mockResolvedValue(undefined);
  mockLogto.signIn.mockReset().mockResolvedValue(undefined);
  mockLogto.signOut.mockReset().mockResolvedValue(undefined);
  sessionStorage.clear();
});

afterEach(async () => {
  if (root) {
    const r = root;
    root = null;
    await act(async () => {
      r.unmount();
    });
  }
  capturedAuth = null;
  capturedApi = null;
});

const flush = () =>
  act(async () => {
    await Promise.resolve();
  });

// --- callback gating (C1 / C7) ---------------------------------------------

it("C1: holds isLoading on the callback route while a code exchange is pending", async () => {
  setUrl("http://localhost:3000/callback?code=c123&state=s456");
  await renderProvider();
  // Not authenticated, on /callback with a real code redirect: the bridge must
  // report loading — never a settled logged-out frame (#11).
  expect(capturedAuth?.isLoading).toBe(true);
});

it("C7: a stray code+state outside the callback route neither pends nor spins", async () => {
  setUrl("http://localhost:3000/some-page?code=c123&state=s456");
  await renderProvider();
  await flush();
  // Off the callback route the same query is not a sign-in transaction: the
  // bridge settles immediately (previously this pinned a 10s loading state).
  expect(capturedAuth?.isLoading).toBe(false);
});

it("respects a custom callbackPath for gating", async () => {
  setUrl("http://localhost:3000/auth/done?code=c123&state=s456");
  await renderProvider({ callbackPath: "/auth/done" });
  expect(capturedAuth?.isLoading).toBe(true);
});

it("default /callback does not pend when callbackPath points elsewhere", async () => {
  setUrl("http://localhost:3000/callback?code=c123&state=s456");
  await renderProvider({ callbackPath: "/auth/done" });
  await flush();
  expect(capturedAuth?.isLoading).toBe(false);
});

// --- callback outcomes ------------------------------------------------------

it("benign callback (user cancelled) returns to the stashed returnTo via navigate", async () => {
  setUrl("http://localhost:3000/callback?state=s456&error=access_denied");
  sessionStorage.setItem("convex-logto:returnTo", "/deep/page");
  const navigate = vi.fn<(to: string) => void>();
  await renderProvider({ navigate });
  await flush();
  expect(navigate).toHaveBeenCalledWith("/deep/page");
  // The stash is consumed — a later sign-out/sign-in must not replay it.
  expect(sessionStorage.getItem("convex-logto:returnTo")).toBeNull();
});

it("setup-error callback reports via onAuthError and recovers (no render throw)", async () => {
  setUrl("http://localhost:3000/callback?state=s456&error=invalid_scope");
  const navigate = vi.fn<(to: string) => void>();
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await renderProvider({ navigate, onAuthError });
    await flush();
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(String(onAuthError.mock.calls[0]?.[0])).toMatch(/invalid_scope/);
    expect(navigate).toHaveBeenCalledWith("/");
  } finally {
    consoleError.mockRestore();
  }
});

it("a hostile stash value is discarded, not navigated to", async () => {
  setUrl("http://localhost:3000/callback?state=s456&error=access_denied");
  sessionStorage.setItem("convex-logto:returnTo", "//evil.example.com");
  const navigate = vi.fn<(to: string) => void>();
  await renderProvider({ navigate });
  await flush();
  expect(navigate).toHaveBeenCalledWith("/");
});

// --- signIn contract --------------------------------------------------------

it("signIn() defaults the redirect to origin + callbackPath", async () => {
  await renderProvider({ probe: true });
  await act(async () => {
    await capturedApi!.signIn();
  });
  expect(mockLogto.signIn).toHaveBeenCalledWith(
    "http://localhost:3000/callback",
  );
});

it("signIn({ returnTo }) stashes the destination and uses the callback redirect", async () => {
  await renderProvider({ probe: true });
  await act(async () => {
    await capturedApi!.signIn({ returnTo: "/dashboard?tab=1" });
  });
  expect(mockLogto.signIn).toHaveBeenCalledWith(
    "http://localhost:3000/callback",
  );
  expect(sessionStorage.getItem("convex-logto:returnTo")).toBe(
    "/dashboard?tab=1",
  );
});

it.each(["//evil.example.com", "https://evil.example.com", "back\\slash"])(
  "signIn reports and rejects unsafe returnTo %s",
  async (returnTo) => {
    const onAuthError = vi.fn<(error: Error) => void>();
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    try {
      await renderProvider({ probe: true, onAuthError });
      await expect(capturedApi!.signIn({ returnTo })).rejects.toThrow(
        /same-origin path/,
      );
      expect(onAuthError).toHaveBeenCalledTimes(1);
      expect(onAuthError).toHaveBeenCalledWith(expect.any(Error));
      expect(consoleError).toHaveBeenCalledTimes(1);
      expect(mockLogto.signIn).not.toHaveBeenCalled();
    } finally {
      consoleError.mockRestore();
    }
  },
);

it("resolves a cancelled sign-in once, even under StrictMode", async () => {
  // Every shipped example wraps the provider in StrictMode, where React
  // double-invokes effects. `takeReturnTo()` is destructive, so a second pass
  // finds the stash empty and sends the user to `afterSignIn` instead of the
  // page they were signing in to reach.
  setUrl("http://localhost:3000/callback?state=xyz&error=access_denied");
  sessionStorage.setItem("convex-logto:returnTo", "/post/123");
  const navigate = vi.fn();

  root = createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(<StrictMode>{providerTree({ navigate })}</StrictMode>);
  });

  expect(navigate).toHaveBeenCalledTimes(1);
  expect(navigate).toHaveBeenCalledWith("/post/123");
});

it("stops holding isLoading once a callback resolves without authenticating", async () => {
  // The provider is mounted above the router in every SPA example, so the soft
  // navigation out of /callback re-renders only the router subtree. Anything the
  // loading veto reads from `window.location` would stay frozen at "still on
  // /callback", and Convex would sit at isLoading forever — the app never shows
  // a Sign in button again, and only a page reload recovers.
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    setUrl("http://localhost:3000/callback?code=abc&state=xyz");
    mockLogto.error = new Error("state mismatch");
    const navigate = vi.fn((to: string) => {
      setUrl(`http://localhost:3000${to}`);
    });

    await renderProvider({ navigate });

    expect(navigate).toHaveBeenCalledWith("/");
    expect(capturedAuth?.isLoading).toBe(false);
    expect(capturedAuth?.isAuthenticated).toBe(false);
  } finally {
    consoleError.mockRestore();
  }
});

it("mounts the sign-in error observer once the callback has resolved", async () => {
  // A router's `navigate` is asynchronous, so a provider re-render right after
  // the callback resolves can still see /callback in the URL. Gating the
  // observer on the URL leaves it unmounted for the rest of the page session,
  // and the swallowed sign-in failure #53 exists to surface is lost again.
  const failure = new Error("OIDC discovery unreachable");
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    setUrl("http://localhost:3000/callback?code=abc&state=xyz");
    mockLogto.isAuthenticated = true;
    const navigate = vi.fn();

    await renderProvider({ probe: true, onAuthError, navigate });
    expect(navigate).toHaveBeenCalledWith("/");

    mockLogto.signIn.mockImplementation(async () => {
      mockLogto.error = failure;
    });
    await act(async () => {
      void capturedApi!.signIn();
      await Promise.resolve();
    });
    await rerenderProvider({ probe: true, onAuthError, navigate });

    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(onAuthError).toHaveBeenCalledWith(failure);
  } finally {
    consoleError.mockRestore();
  }
});

it("reports an SDK-stored initiation error once when signIn() is discarded", async () => {
  const failure = new Error("OIDC discovery unreachable");
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  mockLogto.signIn.mockImplementation(async () => {
    // @logto/react's proxy catches the real rejection, stores this error in
    // context, and resolves the public promise.
    mockLogto.error = failure;
  });
  try {
    await renderProvider({ probe: true, onAuthError });
    await act(async () => {
      void capturedApi!.signIn();
      await Promise.resolve();
    });
    expect(onAuthError).not.toHaveBeenCalled();

    // The SDK context update is what exposes the swallowed failure.
    await rerenderProvider({ probe: true, onAuthError });
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(onAuthError).toHaveBeenCalledWith(failure);
    expect(consoleError).toHaveBeenCalledTimes(1);

    // The same SDK error object surviving another render is not a new failure.
    await rerenderProvider({ probe: true, onAuthError });
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(consoleError).toHaveBeenCalledTimes(1);
  } finally {
    consoleError.mockRestore();
  }
});

it("reports and rethrows a direct signIn rejection exactly once", async () => {
  const failure = new Error("future SDK rejection");
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  mockLogto.signIn.mockRejectedValue(failure);
  try {
    await renderProvider({ probe: true, onAuthError });
    await expect(capturedApi!.signIn()).rejects.toBe(failure);
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(onAuthError).toHaveBeenCalledWith(failure);
    expect(consoleError).toHaveBeenCalledTimes(1);
  } finally {
    consoleError.mockRestore();
  }
});

it("does not double-report callback errors through the initiation observer", async () => {
  setUrl("http://localhost:3000/callback?code=c123&state=s456");
  mockLogto.error = new Error("callback exchange failed");
  const navigate = vi.fn<(to: string) => void>();
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await renderProvider({ probe: true, navigate, onAuthError });
    await flush();
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(String(onAuthError.mock.calls[0]?.[0])).toMatch(/callback/i);
    expect(consoleError).toHaveBeenCalledTimes(1);

    await rerenderProvider({ probe: true, navigate, onAuthError });
    await flush();
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(consoleError).toHaveBeenCalledTimes(1);
  } finally {
    consoleError.mockRestore();
  }
});

it("deprecated signIn(string) passes through, warning when the path can't be handled", async () => {
  await renderProvider({ probe: true });
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await act(async () => {
      await capturedApi!.signIn("http://localhost:3000/callback");
    });
    expect(consoleError).not.toHaveBeenCalled();
    await act(async () => {
      await capturedApi!.signIn("http://localhost:3000/custom-callback");
    });
    expect(consoleError).toHaveBeenCalledTimes(1);
    expect(String(consoleError.mock.calls[0]?.[0])).toMatch(/callbackPath/);
    expect(mockLogto.signIn).toHaveBeenLastCalledWith(
      "http://localhost:3000/custom-callback",
    );
  } finally {
    consoleError.mockRestore();
  }
});

// --- fetchAccessToken -------------------------------------------------------

it("forceRefreshToken clears the access token, refreshes, and returns the rotated ID token", async () => {
  await renderProvider();
  const calls: string[] = [];
  mockLogto.clearAccessToken.mockImplementation(async () => {
    calls.push("clear");
  });
  mockLogto.getAccessToken.mockImplementation(async () => {
    calls.push("access");
    return "at";
  });
  mockLogto.getIdToken.mockImplementation(async () => {
    calls.push("id");
    return "rotated-id-token";
  });

  const token = await capturedAuth!.fetchAccessToken({
    forceRefreshToken: true,
  });
  expect(token).toBe("rotated-id-token");
  expect(calls).toEqual(["clear", "access", "id"]);
});

it("forceRefreshToken returns null when the refresh round-trip yields no access token", async () => {
  await renderProvider();
  mockLogto.getAccessToken.mockResolvedValue(undefined);
  const token = await capturedAuth!.fetchAccessToken({
    forceRefreshToken: true,
  });
  expect(token).toBeNull();
  expect(mockLogto.getIdToken).not.toHaveBeenCalled();
});

it("errors surface as null (clean unauthenticated transition), never as rejections", async () => {
  await renderProvider();
  mockLogto.getIdToken.mockRejectedValue(new Error("refresh token expired"));
  await expect(
    capturedAuth!.fetchAccessToken({ forceRefreshToken: false }),
  ).resolves.toBeNull();
});

it("concurrent same-kind fetches merge into one in-flight request", async () => {
  await renderProvider();
  let release!: (value: string) => void;
  mockLogto.getIdToken.mockImplementation(
    () => new Promise<string>((r) => (release = r)),
  );

  const first = capturedAuth!.fetchAccessToken({ forceRefreshToken: false });
  const second = capturedAuth!.fetchAccessToken({ forceRefreshToken: false });
  release("merged-token");
  await expect(first).resolves.toBe("merged-token");
  await expect(second).resolves.toBe("merged-token");
  expect(mockLogto.getIdToken).toHaveBeenCalledTimes(1);

  // After settling, a new fetch is a fresh request (no stale-cache merging).
  mockLogto.getIdToken.mockResolvedValue("fresh-token");
  await expect(
    capturedAuth!.fetchAccessToken({ forceRefreshToken: false }),
  ).resolves.toBe("fresh-token");
});

it("a forced fetch is never satisfied by a plain in-flight fetch", async () => {
  await renderProvider();
  let releasePlain!: (value: string) => void;
  mockLogto.getIdToken
    .mockImplementationOnce(
      () => new Promise<string>((r) => (releasePlain = r)),
    )
    .mockResolvedValueOnce("forced-token");

  const plain = capturedAuth!.fetchAccessToken({ forceRefreshToken: false });
  const forced = capturedAuth!.fetchAccessToken({ forceRefreshToken: true });
  releasePlain("plain-token");
  await expect(plain).resolves.toBe("plain-token");
  await expect(forced).resolves.toBe("forced-token");
  expect(mockLogto.clearAccessToken).toHaveBeenCalledTimes(1);
});
