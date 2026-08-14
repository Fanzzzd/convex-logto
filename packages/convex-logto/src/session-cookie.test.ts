import { ConvexError } from "convex/values";
import { describe, expect, it, vi } from "vitest";
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

const api = {
  signIn: { fn: "signIn" },
  callback: { fn: "callback" },
  refresh: { fn: "refresh" },
  signOut: { fn: "signOut" },
  sessionValid: { fn: "sessionValid" },
} as unknown as LogtoSessionApi;

type HandlerName = "signIn" | "callback" | "refresh" | "signOut";
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
  };
  const action = vi.fn((reference: unknown, args: unknown) => {
    const name = (reference as { fn: HandlerName }).fn;
    return handlers[name](args);
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

function request(
  route: "sign-in" | "callback" | "token" | "sign-out",
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
      `${LOGTO_SESSION_COOKIE_NAME}=session-token-1; Path=/; HttpOnly; Secure; SameSite=Lax`,
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
      `${LOGTO_SESSION_COOKIE_NAME}=session-token-2; Path=/; HttpOnly; Secure; SameSite=Lax`,
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

  it("clears the cookie and returns an empty seed after a terminal error", async () => {
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
    expect(seed.headers.get("set-cookie")).toContain("Max-Age=0");
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
  it("sends credentials + CSRF header and exposes only a non-secret marker", async () => {
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/callback")) {
        return Response.json({
          idToken: "id-token-1",
          sessionId: "session-id-1",
          returnTo: "/dashboard",
        });
      }
      throw new Error(`unexpected route ${url}`);
    }) as typeof globalThis.fetch;
    const transport = createLogtoSessionCookieTransport(api, {
      endpoint: BASE_PATH,
      fetch: fetcher,
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
    const [, init] = fetcher.mock.calls[0]!;
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(new Headers(init?.headers).get(LOGTO_SESSION_CSRF_HEADER)).toBe(
      LOGTO_SESSION_CSRF_VALUE,
    );
  });
});

describe("Safari device-binding exclusion", () => {
  const safari =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15";

  it("throws loudly instead of degrading either protection", () => {
    expect(() =>
      assertLogtoSessionCookieCompatibility({
        deviceBinding: true,
        userAgent: safari,
      }),
    ).toThrow(/cannot be enabled together on Safari/);
  });

  it("also enforces the exclusion in the fetch handler", async () => {
    const { handler, action } = makeHarness({ deviceBinding: true });
    await expect(
      handler(
        request("token", {
          cookie: cookie("session-token-1"),
          userAgent: safari,
        }),
      ),
    ).rejects.toThrow(/cannot be enabled together on Safari/);
    expect(action).not.toHaveBeenCalled();
  });
});
