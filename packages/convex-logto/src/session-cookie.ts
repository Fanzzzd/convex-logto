import type { FunctionReference } from "convex/server";
import { ConvexError } from "convex/values";
import { isSafeReturnTo } from "./callback";
import type { SessionTransport } from "./session-client";
import type { LogtoSessionApi } from "./session";

/** Fixed host-only cookie used by the session cookie transport. */
export const LOGTO_SESSION_COOKIE_NAME = "__Host-convex-logto-session";

/** Fixed non-simple request header required on every state-changing request. */
export const LOGTO_SESSION_CSRF_HEADER = "x-convex-logto-csrf";

/** Fixed value for {@link LOGTO_SESSION_CSRF_HEADER}. */
export const LOGTO_SESSION_CSRF_VALUE = "1";

/** Default mount point for the four cookie transport routes. */
export const LOGTO_SESSION_COOKIE_BASE_PATH = "/api/logto-session";

/**
 * The cookie credential never enters JavaScript. The existing session engine
 * still needs a non-secret marker so it knows a cookie-backed session exists.
 */
export const COOKIE_SESSION_MARKER = "cookie-session";

type SessionAction = FunctionReference<"action">;

/** The action-calling slice shared by ConvexHttpClient and an HTTP action ctx. */
export type LogtoSessionAction = <Action extends SessionAction>(
  action: Action,
  args: Action["_args"],
) => Promise<Action["_returnType"]>;

export type LogtoSessionCookieHandlerOptions = {
  /** The module re-exporting `logtoSessionApi(...)`, e.g. `api.auth`. */
  sessionApi: LogtoSessionApi;
  /** Call a public Convex action (usually `client.action` or `ctx.runAction`). */
  action: LogtoSessionAction;
  /** Exact browser origins allowed to call the handler. Wildcards are rejected. */
  allowedOrigins: readonly string[];
  /** Mount point containing `sign-in`, `callback`, `token`, and `sign-out`. */
  basePath?: string;
  /**
   * Mirror the session provider's future device-binding flag. Safari cannot
   * safely combine its ITP storage behavior with this cookie transport.
   */
  deviceBinding?: boolean;
};

export type LogtoSessionCookieSeed = {
  /** Fresh ID token to pass to `ConvexLogtoSessionProvider`. */
  initialToken: string | null;
  /** Stable session id for reactive revocation. */
  initialSessionId: string | null;
  /** Forward these headers to the SSR response so the rotated cookie lands. */
  headers: Headers;
};

/** A web-standard fetch handler plus a server-only SSR seeding helper. */
export type LogtoSessionCookieHandler = {
  (request: Request): Promise<Response>;
  getInitialToken(request: Request): Promise<LogtoSessionCookieSeed>;
};

export type LogtoSessionCookieTransportOptions = {
  /** Handler mount point (relative or absolute). Default `/api/logto-session`. */
  endpoint?: string;
  /** Injectable Fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** See `LogtoSessionCookieHandlerOptions.deviceBinding`. */
  deviceBinding?: boolean;
};

type SessionError = {
  kind: "terminal" | "transient";
  code: string;
  message: string;
};

type CookieRoute = "sign-in" | "callback" | "token" | "sign-out";

const COOKIE_ROUTES = new Set<CookieRoute>([
  "sign-in",
  "callback",
  "token",
  "sign-out",
]);

const NO_STORE_HEADERS = { "Cache-Control": "no-store" } as const;

function normalizeBasePath(basePath: string): string {
  const value = basePath.trim();
  if (!value.startsWith("/") || value.includes("?") || value.includes("#")) {
    throw new Error(
      `convex-logto: session cookie basePath must be an absolute path (got "${basePath}").`,
    );
  }
  return value.length > 1 ? value.replace(/\/+$/, "") : value;
}

function normalizeEndpoint(endpoint: string): string {
  const value = endpoint.trim().replace(/\/+$/, "");
  if (!value) {
    throw new Error("convex-logto: session cookie endpoint cannot be empty.");
  }
  if (value.startsWith("/")) return value;
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(
      "convex-logto: session cookie endpoint must use http or https.",
    );
  }
  return url.toString().replace(/\/+$/, "");
}

function normalizeAllowedOrigins(origins: readonly string[]): Set<string> {
  if (origins.length === 0) {
    throw new Error(
      "convex-logto: allowedOrigins must contain at least one exact browser origin.",
    );
  }
  return new Set(
    origins.map((origin) => {
      const value = origin.trim();
      const url = new URL(value);
      if (
        (url.protocol !== "https:" && url.protocol !== "http:") ||
        url.username !== "" ||
        url.password !== "" ||
        url.pathname !== "/" ||
        url.search !== "" ||
        url.hash !== ""
      ) {
        throw new Error(
          `convex-logto: allowedOrigins entries must be exact http(s) origins (got "${origin}").`,
        );
      }
      return url.origin;
    }),
  );
}

function cookieHeader(sessionToken: string): string {
  return (
    `${LOGTO_SESSION_COOKIE_NAME}=${encodeURIComponent(sessionToken)}; ` +
    "Path=/; HttpOnly; Secure; SameSite=Lax"
  );
}

function clearCookieHeader(): string {
  return (
    `${LOGTO_SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; ` +
    "SameSite=Lax; Max-Age=0"
  );
}

function readCookie(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    if (name !== LOGTO_SESSION_COOKIE_NAME) continue;
    try {
      return decodeURIComponent(part.slice(index + 1).trim()) || null;
    } catch {
      return null;
    }
  }
  return null;
}

function routeFor(request: Request, basePath: string): CookieRoute | null {
  const pathname = new URL(request.url).pathname;
  const prefix = basePath === "/" ? "/" : `${basePath}/`;
  if (!pathname.startsWith(prefix)) return null;
  const route = pathname.slice(prefix.length);
  return COOKIE_ROUTES.has(route as CookieRoute)
    ? (route as CookieRoute)
    : null;
}

function corsHeaders(origin: string): Headers {
  return new Headers({
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
  });
}

function responseWithCors(response: Response, origin: string | null): Response {
  if (origin === null) return response;
  for (const [name, value] of corsHeaders(origin)) {
    response.headers.set(name, value);
  }
  return response;
}

function jsonResponse(
  value: unknown,
  init: ResponseInit = {},
  origin: string | null = null,
): Response {
  const headers = new Headers(init.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Type", "application/json");
  return responseWithCors(
    new Response(JSON.stringify(value), { ...init, headers }),
    origin,
  );
}

function errorData(error: unknown): SessionError | null {
  const data =
    error instanceof ConvexError
      ? error.data
      : typeof error === "object" && error !== null && "data" in error
        ? (error as { data?: unknown }).data
        : undefined;
  if (typeof data !== "object" || data === null) return null;
  const { kind, code, message } = data as Record<string, unknown>;
  return (kind === "terminal" || kind === "transient") &&
    typeof code === "string" &&
    typeof message === "string"
    ? { kind, code, message }
    : null;
}

function actionErrorResponse(
  error: unknown,
  origin: string,
  headers?: HeadersInit,
): Response {
  const data = errorData(error);
  if (data) {
    return jsonResponse(
      { error: data },
      {
        status: data.kind === "terminal" ? 401 : 503,
        headers,
      },
      origin,
    );
  }
  console.error("convex-logto: session cookie action failed.", error);
  return jsonResponse(
    {
      error: {
        kind: "transient",
        code: "session_transport_failed",
        message: "The session service is temporarily unavailable.",
      } satisfies SessionError,
    },
    { status: 500, headers },
    origin,
  );
}

async function readJsonObject(
  request: Request,
): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (text === "") return {};
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("request body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function requiredString(body: Record<string, unknown>, name: string): string {
  const value = body[name];
  if (typeof value !== "string" || value === "") {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

function optionalString(
  body: Record<string, unknown>,
  name: string,
): string | undefined {
  const value = body[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value === "") {
    throw new Error(`${name} must be a non-empty string when provided`);
  }
  return value;
}

function validateRedirectUri(value: string, requestOrigin: string): string {
  const url = new URL(value);
  if (url.origin !== requestOrigin || url.protocol === "javascript:") {
    throw new Error("redirectUri must use the calling browser origin");
  }
  return value;
}

function isSafari(userAgent: string): boolean {
  return (
    /Safari\//.test(userAgent) &&
    !/(?:Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|OPiOS|FxiOS|Firefox)\//.test(
      userAgent,
    )
  );
}

/**
 * Throw when Safari would combine cookie transport with software device
 * binding. Exported so future non-React adapters can enforce the same rule.
 */
export function assertLogtoSessionCookieCompatibility(options: {
  deviceBinding?: boolean;
  userAgent?: string | null;
}): void {
  if (options.deviceBinding && isSafari(options.userAgent ?? "")) {
    throw new Error(
      "convex-logto: session cookie transport and device binding cannot be enabled together on Safari because ITP can evict the bound key while retaining the cookie. Disable one of them; silent fallback is not allowed.",
    );
  }
}

/**
 * Build the same-site cookie transport's four-route standard-fetch handler.
 * The returned function can be exported directly as a Next.js POST/OPTIONS
 * handler or called from TanStack Start and Convex HTTP actions.
 */
export function createLogtoSessionCookieHandler(
  options: LogtoSessionCookieHandlerOptions,
): LogtoSessionCookieHandler {
  const basePath = normalizeBasePath(
    options.basePath ?? LOGTO_SESSION_COOKIE_BASE_PATH,
  );
  const allowedOrigins = normalizeAllowedOrigins(options.allowedOrigins);

  const refreshFromCookie = async (request: Request) => {
    const sessionToken = readCookie(request);
    if (sessionToken === null) {
      throw new ConvexError({
        kind: "terminal" as const,
        code: "session_cookie_missing",
        message: "No session cookie is present. Sign in again.",
      });
    }
    return await options.action(options.sessionApi.refresh, { sessionToken });
  };

  const handleRoute = async (
    route: CookieRoute,
    request: Request,
    origin: string,
  ): Promise<Response> => {
    let body: Record<string, unknown>;
    try {
      body = await readJsonObject(request);
    } catch {
      return jsonResponse(
        { error: "Malformed JSON request body" },
        { status: 400 },
        origin,
      );
    }

    try {
      switch (route) {
        case "sign-in": {
          const redirectUri = validateRedirectUri(
            requiredString(body, "redirectUri"),
            origin,
          );
          const returnTo = optionalString(body, "returnTo");
          if (returnTo !== undefined && !isSafeReturnTo(returnTo)) {
            return jsonResponse(
              { error: "returnTo must be a same-origin path" },
              { status: 400 },
              origin,
            );
          }
          const result = await options.action(options.sessionApi.signIn, {
            redirectUri,
            returnTo,
          });
          return jsonResponse(result, {}, origin);
        }
        case "callback": {
          const result = await options.action(options.sessionApi.callback, {
            code: requiredString(body, "code"),
            state: requiredString(body, "state"),
            redirectUri: validateRedirectUri(
              requiredString(body, "redirectUri"),
              origin,
            ),
          });
          return jsonResponse(
            {
              idToken: result.idToken,
              sessionId: result.sessionId,
              returnTo: result.returnTo,
            },
            { headers: { "Set-Cookie": cookieHeader(result.sessionToken) } },
            origin,
          );
        }
        case "token": {
          const result = await refreshFromCookie(request);
          return jsonResponse(
            { idToken: result.idToken, sessionId: result.sessionId },
            { headers: { "Set-Cookie": cookieHeader(result.sessionToken) } },
            origin,
          );
        }
        case "sign-out": {
          const headers = new Headers({
            "Set-Cookie": clearCookieHeader(),
          });
          const sessionToken = readCookie(request);
          if (sessionToken === null)
            return jsonResponse({}, { headers }, origin);
          try {
            const result = await options.action(options.sessionApi.signOut, {
              sessionToken,
              postLogoutRedirectUri: optionalString(
                body,
                "postLogoutRedirectUri",
              ),
            });
            return jsonResponse(result, { headers }, origin);
          } catch (error) {
            return actionErrorResponse(error, origin, headers);
          }
        }
      }
    } catch (error) {
      const data = errorData(error);
      const headers =
        route === "token" && data?.kind === "terminal"
          ? { "Set-Cookie": clearCookieHeader() }
          : undefined;
      return actionErrorResponse(error, origin, headers);
    }
  };

  const handle = async (request: Request): Promise<Response> => {
    const route = routeFor(request, basePath);
    if (route === null) {
      return new Response("Not found", {
        status: 404,
        headers: NO_STORE_HEADERS,
      });
    }

    const rawOrigin = request.headers.get("origin");
    const origin =
      rawOrigin !== null && allowedOrigins.has(rawOrigin) ? rawOrigin : null;

    if (request.method === "OPTIONS") {
      if (origin === null) {
        return new Response("Origin is not allowed", {
          status: 403,
          headers: NO_STORE_HEADERS,
        });
      }
      const requestedMethod = request.headers.get(
        "access-control-request-method",
      );
      const requestedHeaders = (
        request.headers.get("access-control-request-headers") ?? ""
      )
        .toLowerCase()
        .split(",")
        .map((value) => value.trim());
      if (
        requestedMethod !== "POST" ||
        !requestedHeaders.includes(LOGTO_SESSION_CSRF_HEADER)
      ) {
        return responseWithCors(
          new Response("Invalid preflight", {
            status: 403,
            headers: NO_STORE_HEADERS,
          }),
          origin,
        );
      }
      const headers = corsHeaders(origin);
      headers.set(
        "Access-Control-Allow-Headers",
        `${LOGTO_SESSION_CSRF_HEADER}, content-type`,
      );
      headers.set("Access-Control-Allow-Methods", "POST");
      headers.set("Cache-Control", "no-store");
      return new Response(null, { status: 204, headers });
    }

    if (request.method !== "POST") {
      return responseWithCors(
        new Response("Method not allowed", {
          status: 405,
          headers: { ...NO_STORE_HEADERS, Allow: "POST, OPTIONS" },
        }),
        origin,
      );
    }
    if (origin === null) {
      return new Response("Origin is not allowed", {
        status: 403,
        headers: NO_STORE_HEADERS,
      });
    }
    if (
      request.headers.get(LOGTO_SESSION_CSRF_HEADER) !==
      LOGTO_SESSION_CSRF_VALUE
    ) {
      return responseWithCors(
        new Response("Missing or invalid CSRF header", {
          status: 403,
          headers: NO_STORE_HEADERS,
        }),
        origin,
      );
    }
    assertLogtoSessionCookieCompatibility({
      deviceBinding: options.deviceBinding,
      userAgent: request.headers.get("user-agent"),
    });
    return await handleRoute(route, request, origin);
  };

  return Object.assign(handle, {
    getInitialToken: async (
      request: Request,
    ): Promise<LogtoSessionCookieSeed> => {
      assertLogtoSessionCookieCompatibility({
        deviceBinding: options.deviceBinding,
        userAgent: request.headers.get("user-agent"),
      });
      const headers = new Headers(NO_STORE_HEADERS);
      if (readCookie(request) === null) {
        return {
          initialToken: null,
          initialSessionId: null,
          headers,
        };
      }
      try {
        const result = await refreshFromCookie(request);
        headers.set("Set-Cookie", cookieHeader(result.sessionToken));
        return {
          initialToken: result.idToken,
          initialSessionId: result.sessionId,
          headers,
        };
      } catch (error) {
        if (errorData(error)?.kind !== "terminal") throw error;
        headers.set("Set-Cookie", clearCookieHeader());
        return {
          initialToken: null,
          initialSessionId: null,
          headers,
        };
      }
    },
  });
}

function browserUserAgent(): string | null {
  return typeof navigator === "undefined" ? null : navigator.userAgent;
}

function endpointRoute(endpoint: string, route: CookieRoute): string {
  return `${endpoint}/${route}`;
}

async function parseFetchResponse(response: Response): Promise<unknown> {
  const body = (await response.json().catch(() => ({}))) as {
    error?: unknown;
  };
  if (response.ok) return body;
  if (typeof body.error === "object" && body.error !== null) {
    const { kind, code, message } = body.error as Record<string, unknown>;
    if (
      (kind === "terminal" || kind === "transient") &&
      typeof code === "string" &&
      typeof message === "string"
    ) {
      throw new ConvexError({ kind, code, message });
    }
  }
  throw new Error(
    `convex-logto: session cookie handler responded ${response.status}.`,
  );
}

/**
 * Browser adapter for `SessionAuthEngine`. Session-token arguments are ignored:
 * the browser can only present the HttpOnly cookie through Fetch credentials.
 */
export function createLogtoSessionCookieTransport(
  sessionApi: LogtoSessionApi,
  options: LogtoSessionCookieTransportOptions = {},
): SessionTransport {
  assertLogtoSessionCookieCompatibility({
    deviceBinding: options.deviceBinding,
    userAgent: browserUserAgent(),
  });
  const endpoint = normalizeEndpoint(
    options.endpoint ?? LOGTO_SESSION_COOKIE_BASE_PATH,
  );
  const fetcher = options.fetch ?? globalThis.fetch;

  const post = async (route: CookieRoute, body: unknown): Promise<unknown> => {
    const response = await fetcher(endpointRoute(endpoint, route), {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        [LOGTO_SESSION_CSRF_HEADER]: LOGTO_SESSION_CSRF_VALUE,
      },
      body: JSON.stringify(body),
    });
    return await parseFetchResponse(response);
  };

  return {
    action: async <Action extends SessionAction>(
      action: Action,
      args: Action["_args"],
    ): Promise<Action["_returnType"]> => {
      if (action === sessionApi.signIn) {
        return (await post("sign-in", args)) as Action["_returnType"];
      }
      if (action === sessionApi.callback) {
        const result = (await post("callback", args)) as {
          idToken: string;
          sessionId: string;
          returnTo?: string;
        };
        return {
          ...result,
          sessionToken: COOKIE_SESSION_MARKER,
        } as Action["_returnType"];
      }
      if (action === sessionApi.refresh) {
        const result = (await post("token", {})) as {
          idToken: string;
          sessionId: string;
        };
        return {
          ...result,
          sessionToken: COOKIE_SESSION_MARKER,
        } as Action["_returnType"];
      }
      if (action === sessionApi.signOut) {
        return (await post("sign-out", {
          postLogoutRedirectUri: (args as { postLogoutRedirectUri?: string })
            .postLogoutRedirectUri,
        })) as Action["_returnType"];
      }
      throw new Error(
        "convex-logto: the cookie transport received an unknown session action.",
      );
    },
  };
}
