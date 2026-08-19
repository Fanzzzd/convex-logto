import { anyApi, getFunctionName, type FunctionReference } from "convex/server";
import { ConvexError } from "convex/values";
import { describe, expect, it, vi } from "vitest";
import { SESSION_GC_AFTER_MS } from "./component/core";
import type { LogtoSessionApi } from "./session";
import {
  COOKIE_SESSION_MARKER,
  LOGTO_SESSION_COOKIE_NAME,
  LOGTO_SESSION_CSRF_HEADER,
  LOGTO_SESSION_CSRF_VALUE,
  assertLogtoSessionCookieCompatibility,
  createLogtoSessionCookieHandler,
  createLogtoSessionCookieTransport,
  type LogtoSessionAction,
} from "./session-cookie";

const APP_ORIGIN = "https://app.example.com";
const BASE_PATH = "/api/logto";

const api = anyApi.auth as unknown as LogtoSessionApi;

type HandlerName =
  | "signIn"
  | "callback"
  | "refresh"
  | "signOut"
  | "signOutEverywhere"
  | "listSessions"
  | "renameSession"
  | "revokeSession";
type Handlers = Record<HandlerName, ReturnType<typeof vi.fn>>;

function makeHarness(options?: { deviceBinding?: boolean }) {
  const handlers: Handlers = {
    signIn: vi.fn().mockResolvedValue({
      url: "https://auth.example.com/oidc/auth?state=state-1",
    }),
    callback: vi.fn().mockResolvedValue({
      idToken: "id-token-1",
      sessionToken: "session-token-1",
      sessionId: "session-id-1",
      returnTo: "/dashboard",
    }),
    refresh: vi.fn().mockResolvedValue({
      idToken: "id-token-2",
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
    listSessions: vi.fn().mockResolvedValue({
      sessions: [
        {
          sessionId: "session-id-1",
          current: true,
          createdAt: 1,
          lastRefreshedAt: 2,
          label: "Laptop",
          client: { browser: "Firefox" },
          deviceBound: false,
        },
      ],
      truncated: false,
    }),
    renameSession: vi.fn().mockResolvedValue(true),
    revokeSession: vi.fn().mockResolvedValue(true),
  };
  const action = vi.fn((reference: unknown, args: unknown) => {
    const name = getFunctionName(
      reference as FunctionReference<"action">,
    ).split(":")[1] as HandlerName;
    return (handlers[name] as unknown as (a: unknown) => Promise<unknown>)(
      args,
    );
  }) as unknown as LogtoSessionAction;
  const handler = createLogtoSessionCookieHandler({
    sessionApi: api,
    action,
    allowedOrigins: [APP_ORIGIN],
    basePath: BASE_PATH,
    deviceBinding: options?.deviceBinding,
  });
  return { handler, handlers, action };
}

function cookie(value: string): string {
  return `${LOGTO_SESSION_COOKIE_NAME}=${encodeURIComponent(value)}`;
}

function persistentCookie(value: string): string {
  return (
    `${cookie(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; ` +
    `Max-Age=${SESSION_GC_AFTER_MS / 1000}`
  );
}

function request(
  route: "sign-in" | "callback" | "token" | "sign-out" | "sessions",
  options?: {
    method?: string;
    origin?: string | null;
    csrf?: string | null;
    cookie?: string;
    userAgent?: string;
    body?: Record<string, unknown>;
  },
): Request {
  const method = options?.method ?? "POST";
  const headers = new Headers();
  if (options?.origin !== null)
    headers.set("Origin", options?.origin ?? APP_ORIGIN);
  if (options?.csrf !== null)
    headers.set(
      LOGTO_SESSION_CSRF_HEADER,
      options?.csrf ?? LOGTO_SESSION_CSRF_VALUE,
    );
  if (options?.cookie) headers.set("Cookie", options.cookie);
  if (options?.userAgent) headers.set("User-Agent", options.userAgent);
  if (method === "POST") headers.set("Content-Type", "application/json");
  return new Request(`${APP_ORIGIN}${BASE_PATH}/${route}`, {
    method,
    headers,
    body: method === "POST" ? JSON.stringify(options?.body ?? {}) : undefined,
  });
}

describe("fixed CSRF policy", () => {
  it("rejects every non-POST application request", async () => {
    const { handler, action } = makeHarness();
    const response = await handler(request("token", { method: "GET" }));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST, OPTIONS");
    expect(action).not.toHaveBeenCalled();
  });

  it("rejects a missing or wrong custom header", async () => {
    const { handler, action } = makeHarness();
    expect((await handler(request("token", { csrf: null }))).status).toBe(403);
    expect((await handler(request("token", { csrf: "wrong" }))).status).toBe(
      403,
    );
    expect(action).not.toHaveBeenCalled();
  });

  it("rejects a missing or unlisted Origin", async () => {
    const { handler, action } = makeHarness();
    expect((await handler(request("token", { origin: null }))).status).toBe(
      403,
    );
    expect(
      (await handler(request("token", { origin: "https://attacker.example" })))
        .status,
    ).toBe(403);
    expect(action).not.toHaveBeenCalled();
  });

  it("answers a valid credentialed CORS preflight", async () => {
    const { handler, action } = makeHarness();
    const response = await handler(
      new Request(`${APP_ORIGIN}${BASE_PATH}/token`, {
        method: "OPTIONS",
        headers: {
          Origin: APP_ORIGIN,
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": `${LOGTO_SESSION_CSRF_HEADER}, content-type`,
        },
      }),
    );
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(
      APP_ORIGIN,
    );
    expect(response.headers.get("access-control-allow-credentials")).toBe(
      "true",
    );
    expect(action).not.toHaveBeenCalled();
  });
});

describe("request validation", () => {
  it("returns 400 without logging or dispatching malformed action arguments", async () => {
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const { handler, action } = makeHarness();
    const cases: Array<{
      route: Parameters<typeof request>[0];
      body: Record<string, unknown>;
      cookie?: string;
      message: string;
    }> = [
      {
        route: "sign-in",
        body: { redirectUri: 42 },
        message: "redirectUri must be a non-empty string",
      },
      {
        route: "sign-in",
        body: { redirectUri: "not a URL" },
        message: "redirectUri must use the calling browser origin",
      },
      {
        route: "sign-out",
        body: { postLogoutRedirectUri: 42 },
        cookie: cookie("session-token-1"),
        message:
          "postLogoutRedirectUri must be a non-empty string when provided",
      },
    ];

    for (const testCase of cases) {
      const response = await handler(
        request(testCase.route, {
          body: testCase.body,
          cookie: testCase.cookie,
        }),
      );
      expect(response.status).toBe(400);
      // Structured, so the client can classify it rather than surfacing a bare
      // "responded 400" that swallows the reason.
      await expect(response.json()).resolves.toEqual({
        error: {
          kind: "terminal",
          code: "invalid_request",
          message: testCase.message,
        },
      });
    }
    expect(action).not.toHaveBeenCalled();
    expect(consoleError).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it.each([
    ["without Content-Length", undefined],
    ["with a falsely small Content-Length", "1"],
  ])(
    "returns 413 for a cookie request over 64 KiB %s",
    async (_name, length) => {
      const { handler, action } = makeHarness();
      const headers = new Headers({
        Origin: APP_ORIGIN,
        [LOGTO_SESSION_CSRF_HEADER]: LOGTO_SESSION_CSRF_VALUE,
        "Content-Type": "application/json",
      });
      if (length !== undefined) headers.set("Content-Length", length);
      const oversized = new Request(`${APP_ORIGIN}${BASE_PATH}/sign-in`, {
        method: "POST",
        headers,
        body: "x".repeat(64 * 1024 + 1),
      });

      const response = await handler(oversized);

      expect(response.status).toBe(413);
      expect(action).not.toHaveBeenCalled();
    },
  );

  it("returns 400 when a cookie request body stream fails", async () => {
    const { handler, action } = makeHarness();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("read failed"));
      },
    });
    const failing = new Request(`${APP_ORIGIN}${BASE_PATH}/sign-in`, {
      method: "POST",
      headers: {
        Origin: APP_ORIGIN,
        [LOGTO_SESSION_CSRF_HEADER]: LOGTO_SESSION_CSRF_VALUE,
        "Content-Type": "application/json",
      },
      body: stream,
      duplex: "half",
    } as RequestInit);

    const response = await handler(failing);

    expect(response.status).toBe(400);
    expect(action).not.toHaveBeenCalled();
  });
});

describe("cookie session flows", () => {
  it("sign-in calls the existing action without touching a cookie", async () => {
    const { handler, handlers } = makeHarness();
    const response = await handler(
      request("sign-in", {
        body: {
          redirectUri: `${APP_ORIGIN}/callback`,
          returnTo: "/dashboard",
        },
      }),
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      url: "https://auth.example.com/oidc/auth?state=state-1",
    });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(handlers.signIn).toHaveBeenCalledWith({
      redirectUri: `${APP_ORIGIN}/callback`,
      returnTo: "/dashboard",
    });
  });

  it("callback moves the session token into a strict __Host- cookie", async () => {
    const { handler, handlers } = makeHarness();
    const response = await handler(
      request("callback", {
        body: {
          code: "code-1",
          state: "state-1",
          redirectUri: `${APP_ORIGIN}/callback`,
        },
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toBe(
      persistentCookie("session-token-1"),
    );
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toEqual({
      idToken: "id-token-1",
      sessionId: "session-id-1",
      returnTo: "/dashboard",
    });
    expect(JSON.stringify(body)).not.toContain("session-token-1");
    expect(handlers.callback).toHaveBeenCalledWith({
      code: "code-1",
      state: "state-1",
      redirectUri: `${APP_ORIGIN}/callback`,
    });
  });

  it("token presents the cookie and rolls it on every successful rotation", async () => {
    const { handler, handlers } = makeHarness();
    const response = await handler(
      request("token", { cookie: cookie("session-token-1") }),
    );
    expect(response.status).toBe(200);
    expect(handlers.refresh).toHaveBeenCalledWith({
      sessionToken: "session-token-1",
    });
    expect(response.headers.get("set-cookie")).toBe(
      persistentCookie("session-token-2"),
    );
    await expect(response.json()).resolves.toEqual({
      idToken: "id-token-2",
      sessionId: "session-id-1",
    });
  });

  it("sign-out revokes through the existing action and expires the cookie", async () => {
    const { handler, handlers } = makeHarness();
    const response = await handler(
      request("sign-out", {
        cookie: cookie("session-token-2"),
        body: { postLogoutRedirectUri: APP_ORIGIN },
      }),
    );
    expect(response.status).toBe(200);
    expect(handlers.signOut).toHaveBeenCalledWith({
      sessionToken: "session-token-2",
      postLogoutRedirectUri: APP_ORIGIN,
    });
    expect(response.headers.get("set-cookie")).toBe(
      `${LOGTO_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
    await expect(response.json()).resolves.toEqual({
      endSessionUrl: "https://auth.example.com/oidc/session/end",
    });
  });

  it("multiplexes sign out everywhere through the existing sign-out route", async () => {
    const { handler, handlers } = makeHarness();
    const response = await handler(
      request("sign-out", {
        cookie: cookie("session-token-2"),
        body: { postLogoutRedirectUri: APP_ORIGIN, everywhere: true },
      }),
    );

    expect(response.status).toBe(200);
    expect(handlers.signOutEverywhere).toHaveBeenCalledWith({
      sessionToken: "session-token-2",
      postLogoutRedirectUri: APP_ORIGIN,
    });
    expect(handlers.signOut).not.toHaveBeenCalled();
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    await expect(response.json()).resolves.toEqual({
      count: 2,
      endSessionUrl: "https://auth.example.com/oidc/session/end?all=1",
    });
  });

  it("answers a cookieless sign-out in the shape the caller asked for", async () => {
    // The cookie can leave the jar while a tab lives (privacy extension, ITP
    // eviction, another tab clearing cookies). Signing out is then a no-op —
    // but a bare `{}` fails the client's `count` check, so it would retry twice
    // and then throw, turning a clean no-op into a hard error.
    const { handler, handlers } = makeHarness();
    const everywhere = await handler(
      request("sign-out", { body: { everywhere: true } }),
    );
    expect(everywhere.status).toBe(200);
    await expect(everywhere.json()).resolves.toEqual({ count: 0 });

    const local = await handler(request("sign-out", {}));
    expect(local.status).toBe(200);
    await expect(local.json()).resolves.toEqual({});

    expect(handlers.signOut).not.toHaveBeenCalled();
    expect(handlers.signOutEverywhere).not.toHaveBeenCalled();
  });

  it("translates a legacy app module's missing sign-out-everywhere action", async () => {
    const { handler, handlers } = makeHarness();
    handlers.signOutEverywhere.mockRejectedValue(
      new Error("Function not found: auth:signOutEverywhere"),
    );

    const response = await handler(
      request("sign-out", {
        cookie: cookie("session-token-2"),
        body: { everywhere: true },
      }),
    );

    expect(response.status).toBe(409);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    await expect(response.json()).resolves.toMatchObject({
      error: {
        kind: "terminal",
        code: "sign_out_everywhere_unavailable",
        message: expect.stringMatching(/re-export signOutEverywhere/),
      },
    });
  });

  it("clears a terminal token cookie", async () => {
    const { handler, handlers } = makeHarness();
    handlers.refresh.mockRejectedValueOnce(
      new ConvexError({
        kind: "terminal",
        code: "session_not_found",
        message: "gone",
      }),
    );
    const response = await handler(
      request("token", { cookie: cookie("spent") }),
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(response.headers.get("set-cookie")).toContain("Path=/");
  });
});

describe("sign-out always expires the cookie", () => {
  const clears = (res: Response) =>
    (res.headers.get("Set-Cookie") ?? "").includes("Max-Age=0");

  it.each([
    ["a rejected postLogoutRedirectUri", { postLogoutRedirectUri: 123 }],
    ["a rejected everywhere flag", { everywhere: "yes" }],
  ])("clears the cookie on %s", async (_name, body) => {
    const { handler } = makeHarness();

    const res = await handler(
      request("sign-out", { cookie: cookie("session-token-1"), body }),
    );

    expect(res.status).toBe(400);
    // The cookie is the only credential and JavaScript cannot delete it, so a
    // rejected request must not leave the caller signed in.
    expect(clears(res)).toBe(true);
    const payload = (await res.json()) as { error: { code: string } };
    expect(payload.error.code).toBe("invalid_request");
  });

  it("clears the cookie on a malformed body", async () => {
    const { handler } = makeHarness();
    const headers = new Headers({
      Origin: APP_ORIGIN,
      [LOGTO_SESSION_CSRF_HEADER]: LOGTO_SESSION_CSRF_VALUE,
      "Content-Type": "application/json",
      Cookie: cookie("session-token-1"),
    });
    const res = await handler(
      new Request(`${APP_ORIGIN}${BASE_PATH}/sign-out`, {
        method: "POST",
        headers,
        body: "{not json",
      }),
    );

    expect(res.status).toBe(400);
    expect(clears(res)).toBe(true);
  });

  it("answers 409 with the upgrade hint when signOutEverywhere is absent", async () => {
    const { handler } = makeHarness();
    const withoutEverywhere = createLogtoSessionCookieHandler({
      sessionApi: { ...api, signOutEverywhere: undefined },
      action: vi.fn() as unknown as LogtoSessionAction,
      allowedOrigins: [APP_ORIGIN],
      basePath: BASE_PATH,
    });
    void handler;

    const res = await withoutEverywhere(
      request("sign-out", {
        cookie: cookie("session-token-1"),
        body: { everywhere: true },
      }),
    );

    expect(res.status).toBe(409);
    expect(clears(res)).toBe(true);
    const payload = (await res.json()) as { error: { code: string } };
    expect(payload.error.code).toBe("sign_out_everywhere_unavailable");
  });
});

describe("SSR seed", () => {
  it("returns a fresh initialToken and the rolled Set-Cookie header", async () => {
    const { handler, handlers } = makeHarness();
    const seed = await handler.getInitialToken(
      new Request(`${APP_ORIGIN}/dashboard`, {
        headers: { Cookie: cookie("session-token-1") },
      }),
    );
    expect(handlers.refresh).toHaveBeenCalledWith({
      sessionToken: "session-token-1",
    });
    expect(seed.initialToken).toBe("id-token-2");
    expect(seed.initialSessionId).toBe("session-id-1");
    expect(seed.headers.get("set-cookie")).toContain(
      `${LOGTO_SESSION_COOKIE_NAME}=session-token-2`,
    );
  });

  it("returns an empty seed without a cookie and does no work", async () => {
    const { handler, action } = makeHarness();
    const seed = await handler.getInitialToken(
      new Request(`${APP_ORIGIN}/dashboard`),
    );
    expect(seed.initialToken).toBeNull();
    expect(seed.initialSessionId).toBeNull();
    expect(seed.headers.get("set-cookie")).toBeNull();
    expect(action).not.toHaveBeenCalled();
  });

  it("leaves the cookie intact and returns an empty seed after a terminal error", async () => {
    const { handler, handlers } = makeHarness();
    handlers.refresh.mockRejectedValueOnce(
      new ConvexError({
        kind: "terminal",
        code: "session_not_found",
        message: "gone",
      }),
    );
    const seed = await handler.getInitialToken(
      new Request(`${APP_ORIGIN}/dashboard`, {
        headers: { Cookie: cookie("spent") },
      }),
    );
    expect(seed.initialToken).toBeNull();
    expect(seed.initialSessionId).toBeNull();
    expect(seed.headers.get("set-cookie")).toBeNull();
  });

  it("leaves the cookie intact and returns an empty seed after an unclassifiable error", async () => {
    // What an unreachable Logto looks like: the component rethrows a raw fetch
    // failure unclassified on purpose. Rethrowing here would turn that outage
    // into a 500 document for every signed-in visitor, while the browser
    // `/token` route treats the same failure as transient and keeps going.
    const { handler, handlers } = makeHarness();
    handlers.refresh.mockRejectedValueOnce(new Error("fetch failed"));
    const seed = await handler.getInitialToken(
      new Request(`${APP_ORIGIN}/dashboard`, {
        headers: { Cookie: cookie("still-valid") },
      }),
    );
    expect(seed.initialToken).toBeNull();
    expect(seed.initialSessionId).toBeNull();
    expect(seed.headers.get("set-cookie")).toBeNull();
  });

  it("leaves the cookie intact and returns an empty seed after a transient error", async () => {
    const { handler, handlers } = makeHarness();
    handlers.refresh.mockRejectedValueOnce(
      new ConvexError({
        kind: "transient",
        code: "refresh_in_flight",
        message: "retry shortly",
      }),
    );
    const seed = await handler.getInitialToken(
      new Request(`${APP_ORIGIN}/dashboard`, {
        headers: { Cookie: cookie("still-valid") },
      }),
    );
    expect(seed.initialToken).toBeNull();
    expect(seed.initialSessionId).toBeNull();
    expect(seed.headers.get("set-cookie")).toBeNull();
  });
});

describe("browser transport", () => {
  it("dispatches fresh Convex proxy references by name and exposes only a non-secret marker", async () => {
    expect(api.callback).not.toBe(api.callback);
    const fetchMock = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input);
      if (url.endsWith("/callback")) {
        return Response.json({
          idToken: "id-token-1",
          sessionId: "session-id-1",
          returnTo: "/dashboard",
        });
      }
      throw new Error(`unexpected route ${url}`);
    });
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: fetchMock,
    });
    const result = await transport.action(api.callback, {
      code: "code-1",
      state: "state-1",
      redirectUri: `${APP_ORIGIN}/callback`,
    });
    expect(result).toEqual({
      idToken: "id-token-1",
      sessionId: "session-id-1",
      returnTo: "/dashboard",
      sessionToken: COOKIE_SESSION_MARKER,
    });
    const [, init] = fetchMock.mock.calls[0]!;
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(new Headers(init?.headers).get(LOGTO_SESSION_CSRF_HEADER)).toBe(
      LOGTO_SESSION_CSRF_VALUE,
    );
  });

  it("dispatches sign out everywhere through the sign-out route selector", async () => {
    const fetchMock = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        count: 2,
        endSessionUrl: "https://auth.example.com/oidc/session/end?all=1",
      }),
    );
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: fetchMock,
    });

    await transport.action(api.signOutEverywhere!, {
      sessionToken: COOKIE_SESSION_MARKER,
      postLogoutRedirectUri: APP_ORIGIN,
    });

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`${BASE_PATH}/sign-out`);
    expect(JSON.parse(String(init?.body))).toEqual({
      postLogoutRedirectUri: APP_ORIGIN,
      everywhere: true,
    });
  });

  it.each([
    [
      "sign-in",
      api.signIn,
      { redirectUri: `${APP_ORIGIN}/callback` },
      {
        url: " HTTPS://AUTH.EXAMPLE.COM:443/oidc/auth?state=one two ",
      },
      { url: "https://auth.example.com/oidc/auth?state=one%20two" },
    ],
    [
      "sign-out",
      api.signOut,
      { sessionToken: COOKIE_SESSION_MARKER },
      { endSessionUrl: "http://LOCALHOST:80/oidc/session/end" },
      { endSessionUrl: "http://localhost/oidc/session/end" },
    ],
  ] as const)(
    "canonicalizes a valid %s navigation response",
    async (_route, action, args, responseBody, expected) => {
      const transport = createLogtoSessionCookieTransport(api, {
        endpoint: BASE_PATH,
        fetch: vi
          .fn<typeof globalThis.fetch>()
          .mockResolvedValue(Response.json(responseBody)),
      });

      await expect(transport.action(action, args)).resolves.toEqual(expected);
    },
  );

  it.each([
    [
      "sign-in",
      api.signIn,
      { redirectUri: `${APP_ORIGIN}/callback` },
      { url: "javascript:alert(document.domain)" },
    ],
    [
      "callback",
      api.callback,
      {
        code: "code-1",
        state: "state-1",
        redirectUri: `${APP_ORIGIN}/callback`,
      },
      { unexpected: true },
    ],
    [
      "token",
      api.refresh,
      { sessionToken: COOKIE_SESSION_MARKER },
      { unexpected: true },
    ],
    [
      "sign-out",
      api.signOut,
      { sessionToken: COOKIE_SESSION_MARKER },
      { endSessionUrl: "javascript:alert(document.domain)" },
    ],
    [
      "sign-in-credentials",
      api.signIn,
      { redirectUri: `${APP_ORIGIN}/callback` },
      { url: "https://alice@auth.example.com/oidc/auth" },
    ],
    [
      "sign-out-invalid-url",
      api.signOut,
      { sessionToken: COOKIE_SESSION_MARKER },
      { endSessionUrl: "not an absolute URL" },
    ],
    [
      "sign-out-everywhere",
      api.signOutEverywhere!,
      { sessionToken: COOKIE_SESSION_MARKER },
      { count: -1 },
    ],
  ] as const)(
    "rejects a malformed successful %s response at the Fetch boundary",
    async (_route, action, args, responseBody) => {
      const transport = createLogtoSessionCookieTransport(api, {
        endpoint: BASE_PATH,
        fetch: vi
          .fn<typeof globalThis.fetch>()
          .mockResolvedValue(Response.json(responseBody)),
      });

      await expect(transport.action(action, args)).rejects.toThrow(
        /returned an invalid response/,
      );
    },
  );

  it("times out a custom fetch while waiting for response headers", async () => {
    vi.useFakeTimers();
    let observedSignal: AbortSignal | undefined;
    let markFetchStarted = () => {};
    const fetchStarted = new Promise<void>((resolve) => {
      markFetchStarted = resolve;
    });
    const fetchMock = vi.fn<typeof globalThis.fetch>((_input, init) => {
      observedSignal = init?.signal ?? undefined;
      markFetchStarted();
      return new Promise<Response>((_resolve, reject) => {
        setTimeout(() => reject(new Error("test fallback")), 10_001);
      });
    });
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: fetchMock,
    });
    const action = transport.action(api.refresh, {
      sessionToken: COOKIE_SESSION_MARKER,
    });
    void action.catch(() => {});
    try {
      await fetchStarted;
      await vi.advanceTimersByTimeAsync(10_000);
      expect(observedSignal?.aborted).toBe(true);
      await expect(action).rejects.toThrow(/timed out/i);
      const [, init] = fetchMock.mock.calls[0]!;
      expect(init).toMatchObject({
        method: "POST",
        credentials: "include",
      });
      expect(new Headers(init?.headers).get(LOGTO_SESSION_CSRF_HEADER)).toBe(
        LOGTO_SESSION_CSRF_VALUE,
      );
    } finally {
      await vi.advanceTimersByTimeAsync(1);
      await action.catch(() => {});
      vi.useRealTimers();
    }
  });

  it("times out and cancels a hanging custom response body", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    let observedSignal: AbortSignal | undefined;
    const fetchMock = vi
      .fn<typeof globalThis.fetch>()
      .mockImplementation((_input, init) => {
        observedSignal = init?.signal ?? undefined;
        const stream = new ReadableStream<Uint8Array>({
          pull() {
            // Remain pending until the transport aborts or the test fallback.
          },
          cancel,
        });
        setTimeout(() => {}, 10_001);
        return Promise.resolve(new Response(stream));
      });
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: fetchMock,
    });
    const action = transport.action(api.refresh, {
      sessionToken: COOKIE_SESSION_MARKER,
    });
    void action.catch(() => {});
    try {
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(10_000);
      expect(observedSignal?.aborted).toBe(true);
      await expect(action).rejects.toThrow(/timed out/i);
      await Promise.resolve();
      expect(cancel).toHaveBeenCalledTimes(1);
    } finally {
      await vi.advanceTimersByTimeAsync(1);
      vi.useRealTimers();
    }
  });

  it("cancels a falsely-small response after the first byte over 256 KiB", async () => {
    const cancel = vi.fn();
    const chunks = [new Uint8Array(256 * 1024), new Uint8Array([0])] as const;
    let chunkIndex = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[chunkIndex];
        if (chunk === undefined) return;
        chunkIndex += 1;
        controller.enqueue(chunk);
      },
      cancel,
    });
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        new Response(stream, {
          headers: { "Content-Length": "1" },
        }),
      ),
    });

    await expect(
      transport.action(api.refresh, {
        sessionToken: COOKIE_SESSION_MARKER,
      }),
    ).rejects.toThrow(/response is too large/i);
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it("classifies a custom response stream failure without parsing it", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("stream failed"));
      },
    });
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: vi
        .fn<typeof globalThis.fetch>()
        .mockResolvedValue(new Response(stream)),
    });

    await expect(
      transport.action(api.refresh, {
        sessionToken: COOKIE_SESSION_MARKER,
      }),
    ).rejects.toThrow(/could not read/i);
  });

  it("clears the browser transport timer after a successful response", async () => {
    vi.useFakeTimers();
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        Response.json({
          idToken: "id-token-1",
          sessionId: "session-id-1",
        }),
      ),
    });
    try {
      await expect(
        transport.action(api.refresh, {
          sessionToken: COOKIE_SESSION_MARKER,
        }),
      ).resolves.toMatchObject({ idToken: "id-token-1" });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("preserves a small non-2xx handler ConvexError", async () => {
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        Response.json(
          {
            error: {
              kind: "terminal",
              code: "session_not_found",
              message: "Sign in again.",
            },
          },
          { status: 401 },
        ),
      ),
    });

    await expect(
      transport.action(api.refresh, {
        sessionToken: COOKIE_SESSION_MARKER,
      }),
    ).rejects.toMatchObject({
      data: {
        kind: "terminal",
        code: "session_not_found",
        message: "Sign in again.",
      },
    });
  });

  it("preserves an immediate custom Fetch rejection", async () => {
    const networkError = new TypeError("custom fetch failed");
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: vi.fn<typeof globalThis.fetch>().mockRejectedValue(networkError),
    });

    await expect(
      transport.action(api.refresh, {
        sessionToken: COOKIE_SESSION_MARKER,
      }),
    ).rejects.toBe(networkError);
  });
});

describe("cookie transport and device-binding exclusion", () => {
  const safari =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15";
  const chrome =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

  it("throws the same loud error regardless of browser", () => {
    const check = (userAgent: string) =>
      assertLogtoSessionCookieCompatibility({
        deviceBinding: true,
        userAgent,
      });
    expect(() => check(safari)).toThrow(/cannot be enabled together/);
    expect(() => check(chrome)).toThrow(/cannot be enabled together/);
  });

  it("rejects enabling cookie transport after binding in the browser adapter", () => {
    expect(() =>
      createLogtoSessionCookieTransport(api, {
        endpoint: BASE_PATH,
        deviceBinding: true,
      }),
    ).toThrow(/cannot be enabled together/);
  });

  it("rejects enabling binding after cookie transport in the fetch handler", () => {
    expect(() => makeHarness({ deviceBinding: true })).toThrow(
      /cannot be enabled together/,
    );
  });
});

describe("sessions route", () => {
  it("lists the caller's sessions using only the cookie's token", async () => {
    const { handler, handlers } = makeHarness();

    const res = await handler(
      request("sessions", {
        cookie: cookie("session-token-1"),
        body: { op: "list" },
      }),
    );

    expect(res.status).toBe(200);
    expect(handlers.listSessions).toHaveBeenCalledWith({
      sessionToken: "session-token-1",
    });
    await expect(res.json()).resolves.toEqual({
      sessions: [
        {
          sessionId: "session-id-1",
          current: true,
          createdAt: 1,
          lastRefreshedAt: 2,
          label: "Laptop",
          client: { browser: "Firefox" },
          deviceBound: false,
        },
      ],
      truncated: false,
    });
  });

  it("renames, and forwards an absent label as a clear", async () => {
    const { handler, handlers } = makeHarness();

    const named = await handler(
      request("sessions", {
        cookie: cookie("session-token-1"),
        body: { op: "rename", targetSessionId: "session-id-2", label: "Phone" },
      }),
    );
    await expect(named.json()).resolves.toEqual({ renamed: true });
    expect(handlers.renameSession).toHaveBeenCalledWith({
      sessionToken: "session-token-1",
      targetSessionId: "session-id-2",
      label: "Phone",
    });

    await handler(
      request("sessions", {
        cookie: cookie("session-token-1"),
        body: { op: "rename", targetSessionId: "session-id-2" },
      }),
    );
    expect(handlers.renameSession).toHaveBeenLastCalledWith({
      sessionToken: "session-token-1",
      targetSessionId: "session-id-2",
      label: undefined,
    });
  });

  it.each([
    ["an empty label", ""],
    ["a blank label", "   "],
  ])(
    "treats %s as a clear, matching every other transport",
    async (_n, label) => {
      const { handler, handlers } = makeHarness();

      const res = await handler(
        request("sessions", {
          cookie: cookie("session-token-1"),
          body: { op: "rename", targetSessionId: "session-id-2", label },
        }),
      );

      expect(res.status).toBe(200);
      expect(handlers.renameSession).toHaveBeenCalledWith({
        sessionToken: "session-token-1",
        targetSessionId: "session-id-2",
        label: undefined,
      });
    },
  );

  it("keeps a sign-in working when a descriptor field is blank", async () => {
    // The component drops blank fields; rejecting the whole callback here would
    // make an app-built descriptor fail sign-in in cookie mode alone.
    const { handler, handlers } = makeHarness();

    const res = await handler(
      request("callback", {
        body: {
          code: "code-1",
          state: "state-1",
          redirectUri: `${APP_ORIGIN}/callback`,
          client: { platform: "", os: "macOS" },
        },
      }),
    );

    expect(res.status).toBe(200);
    expect(handlers.callback).toHaveBeenCalledWith(
      expect.objectContaining({ client: { os: "macOS" } }),
    );
  });

  it("revokes another session without clearing this browser's cookie", async () => {
    const { handler, handlers } = makeHarness();

    const res = await handler(
      request("sessions", {
        cookie: cookie("session-token-1"),
        body: { op: "revoke", targetSessionId: "session-id-2" },
      }),
    );

    await expect(res.json()).resolves.toEqual({ revoked: true });
    expect(handlers.revokeSession).toHaveBeenCalledWith({
      sessionToken: "session-token-1",
      targetSessionId: "session-id-2",
    });
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("rejects a request with no session cookie", async () => {
    const { handler, handlers } = makeHarness();

    const res = await handler(request("sessions", { body: { op: "list" } }));

    expect(res.status).toBe(401);
    const payload = (await res.json()) as { error: { code: string } };
    expect(payload.error.code).toBe("session_cookie_missing");
    expect(handlers.listSessions).not.toHaveBeenCalled();
  });

  it.each([
    ["an unknown op", { op: "delete-everything" }],
    ["a missing op", {}],
    ["a rename without a target", { op: "rename", label: "Phone" }],
    ["a revoke without a target", { op: "revoke" }],
  ])("rejects %s as a structured 400", async (_name, body) => {
    const { handler, handlers } = makeHarness();

    const res = await handler(
      request("sessions", { cookie: cookie("session-token-1"), body }),
    );

    expect(res.status).toBe(400);
    const payload = (await res.json()) as { error: { code: string } };
    expect(payload.error.code).toBe("invalid_request");
    expect(handlers.renameSession).not.toHaveBeenCalled();
    expect(handlers.revokeSession).not.toHaveBeenCalled();
  });

  it.each(["list", "rename", "revoke"])(
    "answers 409 with the upgrade hint when %s is not re-exported",
    async (op) => {
      const legacy = createLogtoSessionCookieHandler({
        sessionApi: {
          ...api,
          listSessions: undefined,
          renameSession: undefined,
          revokeSession: undefined,
        },
        action: vi.fn() as unknown as LogtoSessionAction,
        allowedOrigins: [APP_ORIGIN],
        basePath: BASE_PATH,
      });

      const res = await legacy(
        request("sessions", {
          cookie: cookie("session-token-1"),
          body: { op, targetSessionId: "session-id-2" },
        }),
      );

      expect(res.status).toBe(409);
      const payload = (await res.json()) as { error: { code: string } };
      expect(payload.error.code).toBe("session_management_unavailable");
    },
  );

  it("forwards the app-supplied client descriptor through callback", async () => {
    const { handler, handlers } = makeHarness();

    await handler(
      request("callback", {
        body: {
          code: "code-1",
          state: "state-1",
          redirectUri: `${APP_ORIGIN}/callback`,
          client: { platform: "web", browser: "Firefox", os: "  " },
        },
      }),
    );

    expect(handlers.callback).toHaveBeenCalledWith(
      expect.objectContaining({
        client: { platform: "web", browser: "Firefox" },
      }),
    );
  });

  it("rejects a non-object client descriptor", async () => {
    const { handler, handlers } = makeHarness();

    const res = await handler(
      request("callback", {
        body: {
          code: "code-1",
          state: "state-1",
          redirectUri: `${APP_ORIGIN}/callback`,
          client: "Firefox",
        },
      }),
    );

    expect(res.status).toBe(400);
    expect(handlers.callback).not.toHaveBeenCalled();
  });
});

describe("browser transport session management", () => {
  const transportWith = (
    fetchMock: ReturnType<typeof vi.fn<typeof globalThis.fetch>>,
  ) =>
    createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: fetchMock,
    });

  it("proxies listSessions through the sessions route", async () => {
    const fetchMock = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        sessions: [
          {
            sessionId: "session-id-1",
            current: true,
            createdAt: 1,
            lastRefreshedAt: 2,
            label: "Laptop",
            client: { browser: "Firefox" },
            deviceBound: false,
          },
        ],
        truncated: true,
      }),
    );

    const result = await transportWith(fetchMock).action(api.listSessions!, {
      sessionToken: COOKIE_SESSION_MARKER,
    });

    expect(result).toEqual({
      sessions: [
        {
          sessionId: "session-id-1",
          current: true,
          createdAt: 1,
          lastRefreshedAt: 2,
          label: "Laptop",
          client: { browser: "Firefox" },
          deviceBound: false,
        },
      ],
      truncated: true,
    });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url).endsWith(`${BASE_PATH}/sessions`)).toBe(true);
    expect(JSON.parse(String(init?.body))).toEqual({ op: "list" });
  });

  it("forwards an empty label as an omitted one, so the route clears it", async () => {
    const fetchMock = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ renamed: true }));

    await transportWith(fetchMock).action(api.renameSession!, {
      sessionToken: COOKIE_SESSION_MARKER,
      targetSessionId: "session-id-2",
      label: "",
    });

    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body))).toEqual({
      op: "rename",
      targetSessionId: "session-id-2",
    });
  });

  it("never forwards the session-token argument, only the op payload", async () => {
    const fetchMock = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ renamed: true }));

    await expect(
      transportWith(fetchMock).action(api.renameSession!, {
        sessionToken: "a-real-token",
        targetSessionId: "session-id-2",
        label: "Phone",
      }),
    ).resolves.toBe(true);

    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body))).toEqual({
      op: "rename",
      targetSessionId: "session-id-2",
      label: "Phone",
    });
  });

  it("proxies a revoke and unwraps the boolean", async () => {
    const fetchMock = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ revoked: false }));

    await expect(
      transportWith(fetchMock).action(api.revokeSession!, {
        sessionToken: COOKIE_SESSION_MARKER,
        targetSessionId: "session-id-2",
      }),
    ).resolves.toBe(false);
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body))).toEqual({
      op: "revoke",
      targetSessionId: "session-id-2",
    });
  });

  it.each([
    ["a non-array sessions field", { sessions: {}, truncated: false }],
    [
      "a summary missing deviceBound",
      { sessions: [{ sessionId: "s", current: true }], truncated: false },
    ],
    [
      "a non-string label",
      {
        sessions: [
          {
            sessionId: "s",
            current: true,
            createdAt: 1,
            lastRefreshedAt: 2,
            deviceBound: false,
            label: 7,
          },
        ],
        truncated: false,
      },
    ],
    ["a missing truncated flag", { sessions: [] }],
  ])("rejects %s from a hostile handler response", async (_name, payload) => {
    const fetchMock = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json(payload));

    await expect(
      transportWith(fetchMock).action(api.listSessions!, {
        sessionToken: COOKIE_SESSION_MARKER,
      }),
    ).rejects.toThrow(/convex-logto/);
  });

  it("rejects a mutation response that is not a boolean", async () => {
    const fetchMock = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ renamed: "yes" }));

    await expect(
      transportWith(fetchMock).action(api.renameSession!, {
        sessionToken: COOKIE_SESSION_MARKER,
        targetSessionId: "session-id-2",
      }),
    ).rejects.toThrow(/convex-logto/);
  });
});
