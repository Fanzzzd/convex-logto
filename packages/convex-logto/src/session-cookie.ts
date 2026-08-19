import { getFunctionName, type FunctionReference } from "convex/server";
import { ConvexError } from "convex/values";
import { isSafeReturnTo } from "./callback";
import { SESSION_GC_AFTER_MS } from "./component/core.js";
import { normalizeHttpNavigationUrl } from "./component/endpoint.js";
import { readBoundedBody } from "./component/http_body.js";
import type { SessionTransport, StoredSession } from "./session-client";
import type {
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "./session";

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

/**
 * Replace a JavaScript-visible session credential with the cookie marker while
 * retaining the stable id used by reactive revocation checks.
 */
export function createCookieSessionMarker(
  existingSession: StoredSession | null,
  initialSessionId?: string | null,
): StoredSession {
  return {
    token: COOKIE_SESSION_MARKER,
    sessionId: initialSessionId ?? existingSession?.sessionId ?? "",
  };
}

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
   * Mirror the session provider's device-binding flag so incompatible
   * non-React configurations fail through the same assertion.
   */
  deviceBinding?: boolean;
};

export type LogtoSessionCookieSeed = {
  /** Fresh ID token to pass to `ConvexLogtoSessionProvider`. */
  initialToken: string | null;
  /** Stable session id for reactive revocation. */
  initialSessionId: string | null;
  /** Always forward these headers to the SSR response so the rotated cookie lands. */
  headers: Headers;
};

/** A web-standard fetch handler plus a server-only SSR seeding helper. */
export type LogtoSessionCookieHandler = {
  (request: Request): Promise<Response>;
  /**
   * Best-effort SSR seed. Call at most once per incoming document request and
   * always forward the returned headers. Concurrent requests that contend for
   * refresh return an empty seed. Only a successful rotation emits Set-Cookie;
   * every failure leaves the incoming cookie untouched for browser recovery.
   */
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

type CookieRoute = "sign-in" | "callback" | "token" | "sign-out" | "sessions";

const NO_STORE_HEADERS = { "Cache-Control": "no-store" } as const;
const MAX_COOKIE_BODY_BYTES = 64 * 1024;
const MAX_COOKIE_RESPONSE_BYTES = 256 * 1024;
const COOKIE_TRANSPORT_TIMEOUT_MS = 10 * 1000;

function isRecord(value: unknown): value is Record<PropertyKey, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCookieRoute(value: string): value is CookieRoute {
  return (
    value === "sign-in" ||
    value === "callback" ||
    value === "token" ||
    value === "sign-out" ||
    value === "sessions"
  );
}

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
    `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_GC_AFTER_MS / 1000}`
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
  return isCookieRoute(route) ? route : null;
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
  const data: unknown =
    error instanceof ConvexError
      ? error.data
      : isRecord(error)
        ? error.data
        : undefined;
  if (!isRecord(data)) return null;
  const { kind, code, message } = data;
  return (kind === "terminal" || kind === "transient") &&
    typeof code === "string" &&
    typeof message === "string"
    ? { kind, code, message }
    : null;
}

function isMissingSignOutEverywhereAction(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes("signOutEverywhere") &&
    /(?:function.*not found|could not find.*function)/i.test(message)
  );
}

class RequestValidationError extends Error {}

/**
 * Same 409 shape `signOutEverywhere` uses, so a deployment whose app module
 * predates these actions gets actionable guidance instead of a bare failure.
 */
function sessionManagementUnavailable(name: string, origin: string): Response {
  return jsonResponse(
    {
      error: {
        kind: "terminal",
        code: "session_management_unavailable",
        message: `convex-logto: sessionApi must re-export ${name} from logtoSessionApi(components.logto), then deploy the Convex functions.`,
      } satisfies SessionError,
    },
    { status: 409 },
    origin,
  );
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
): Promise<
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; reason: "too_large" | "malformed" }
> {
  const bodyResult = await readBoundedBody(request, MAX_COOKIE_BODY_BYTES);
  if (!bodyResult.ok) {
    return {
      ok: false,
      reason: bodyResult.reason === "too_large" ? "too_large" : "malformed",
    };
  }
  const text = new TextDecoder().decode(bodyResult.bytes);
  if (text === "") return { ok: true, body: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!isRecord(parsed)) return { ok: false, reason: "malformed" };
  return { ok: true, body: parsed };
}

function requiredString(body: Record<string, unknown>, name: string): string {
  const value = body[name];
  if (typeof value !== "string" || value === "") {
    throw new RequestValidationError(`${name} must be a non-empty string`);
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
    throw new RequestValidationError(
      `${name} must be a non-empty string when provided`,
    );
  }
  return value;
}

/**
 * Like `optionalString`, but blank means "not provided" instead of an error.
 * Use it for display fields the component itself treats that way — an emptied
 * rename box must clear a label, not fail the request in cookie mode only.
 */
function optionalDisplayString(
  body: Record<string, unknown>,
  name: string,
): string | undefined {
  const value = body[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new RequestValidationError(`${name} must be a string when provided`);
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function optionalBoolean(
  body: Record<string, unknown>,
  name: string,
): boolean | undefined {
  const value = body[name];
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") {
    throw new RequestValidationError(`${name} must be a boolean when provided`);
  }
  return value;
}

/**
 * The advisory, app-supplied client descriptor. Unknown keys are dropped rather
 * than rejected: it is display data, and the component normalizes and truncates
 * it again server-side.
 */
function optionalClientDescriptor(
  body: Record<string, unknown>,
): { platform?: string; os?: string; browser?: string } | undefined {
  const value = body.client;
  if (value === undefined) return undefined;
  if (!isRecord(value)) {
    throw new RequestValidationError("client must be an object when provided");
  }
  const fields = (["platform", "os", "browser"] as const).flatMap((key) => {
    // Blank is "absent" here so the handler and the browser engine agree on
    // what it means; the component normalizes and truncates again either way.
    // A blank field must never fail a sign-in that is otherwise fine.
    const field = optionalDisplayString(value, key);
    return field === undefined ? [] : [[key, field] as const];
  });
  return fields.length === 0 ? undefined : Object.fromEntries(fields);
}

function validateRedirectUri(value: string, requestOrigin: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RequestValidationError(
      "redirectUri must use the calling browser origin",
    );
  }
  if (url.origin !== requestOrigin) {
    throw new RequestValidationError(
      "redirectUri must use the calling browser origin",
    );
  }
  return value;
}

/**
 * Throw when cookie transport would combine with software device binding.
 * HttpOnly deliberately makes the token unavailable to the JavaScript key
 * that must sign it, so the guarantees cannot be composed without weakening
 * one. Exported so non-React adapters enforce the same rule.
 */
export function assertLogtoSessionCookieCompatibility(options: {
  deviceBinding?: boolean;
  /** Retained for source compatibility; the exclusion now applies everywhere. */
  userAgent?: string | null;
}): void {
  if (options.deviceBinding) {
    throw new Error(
      "convex-logto: session cookie transport and device binding cannot be enabled together. Cookie transport already keeps the session token out of JavaScript, while device binding requires JavaScript to sign that token. Disable one of them; silent fallback is not allowed. On Safari this also avoids ITP retaining the cookie after evicting its IndexedDB key.",
    );
  }
}

/**
 * Build the same-site cookie transport's five-route standard-fetch handler.
 * The returned function can be exported directly as a Next.js POST/OPTIONS
 * handler or called from TanStack Start and Convex HTTP actions.
 */
export function createLogtoSessionCookieHandler(
  options: LogtoSessionCookieHandlerOptions,
): LogtoSessionCookieHandler {
  assertLogtoSessionCookieCompatibility({
    deviceBinding: options.deviceBinding,
  });
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
    // Sign-out must expire the cookie on *every* exit. It is the only credential
    // in this mode and JavaScript cannot delete it, so a response without this
    // header leaves the caller signed in while reporting a failure it cannot act
    // on. Rejecting the request is not a reason to keep the session alive.
    const clearing =
      route === "sign-out" ? { "Set-Cookie": clearCookieHeader() } : undefined;

    const bodyResult = await readJsonObject(request);
    if (!bodyResult.ok) {
      return jsonResponse(
        {
          error:
            bodyResult.reason === "too_large"
              ? "Request body is too large"
              : "Malformed JSON request body",
        },
        {
          status: bodyResult.reason === "too_large" ? 413 : 400,
          ...(clearing === undefined ? {} : { headers: clearing }),
        },
        origin,
      );
    }
    const body = bodyResult.body;

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
            client: optionalClientDescriptor(body),
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
          const postLogoutRedirectUri = optionalString(
            body,
            "postLogoutRedirectUri",
          );
          const everywhere = optionalBoolean(body, "everywhere") ?? false;
          const sessionToken = readCookie(request);
          // Nothing to sign out of, but the answer still has to match the call:
          // the client validates `signOutEverywhere` responses on `count`, and
          // a bare `{}` fails that check, retries twice and then throws — a
          // hard error for what is a clean no-op.
          if (sessionToken === null)
            return jsonResponse(
              everywhere ? { count: 0 } : {},
              { headers },
              origin,
            );
          try {
            const signOutEverywhere = options.sessionApi.signOutEverywhere;
            if (everywhere && signOutEverywhere === undefined) {
              // Same 409 the deployed-but-missing case returns, so the client
              // gets the upgrade guidance either way.
              return jsonResponse(
                {
                  error: {
                    kind: "terminal",
                    code: "sign_out_everywhere_unavailable",
                    message:
                      "convex-logto: sessionApi must re-export signOutEverywhere from logtoSessionApi(components.logto), then deploy the Convex functions.",
                  } satisfies SessionError,
                },
                { status: 409, headers },
                origin,
              );
            }
            const result =
              everywhere && signOutEverywhere !== undefined
                ? await options.action(signOutEverywhere, {
                    sessionToken,
                    postLogoutRedirectUri,
                  })
                : await options.action(options.sessionApi.signOut, {
                    sessionToken,
                    postLogoutRedirectUri,
                  });
            return jsonResponse(result, { headers }, origin);
          } catch (error) {
            if (error instanceof RequestValidationError) throw error;
            if (everywhere && isMissingSignOutEverywhereAction(error)) {
              return jsonResponse(
                {
                  error: {
                    kind: "terminal",
                    code: "sign_out_everywhere_unavailable",
                    message:
                      "convex-logto: sessionApi must re-export signOutEverywhere from logtoSessionApi(components.logto), then deploy the Convex functions.",
                  } satisfies SessionError,
                },
                { status: 409, headers },
                origin,
              );
            }
            return actionErrorResponse(error, origin, headers);
          }
        }
        case "sessions": {
          const sessionToken = readCookie(request);
          if (sessionToken === null) {
            throw new ConvexError({
              kind: "terminal" as const,
              code: "session_cookie_missing",
              message: "No session cookie is present. Sign in again.",
            });
          }
          const op = requiredString(body, "op");
          if (op === "list") {
            const listSessions = options.sessionApi.listSessions;
            if (listSessions === undefined) {
              return sessionManagementUnavailable("listSessions", origin);
            }
            return jsonResponse(
              await options.action(listSessions, { sessionToken }),
              {},
              origin,
            );
          }
          if (op === "rename") {
            const renameSession = options.sessionApi.renameSession;
            if (renameSession === undefined) {
              return sessionManagementUnavailable("renameSession", origin);
            }
            return jsonResponse(
              {
                renamed: await options.action(renameSession, {
                  sessionToken,
                  targetSessionId: requiredString(body, "targetSessionId"),
                  // Absent means "clear it" — the op itself carries the intent.
                  label: optionalDisplayString(body, "label"),
                }),
              },
              {},
              origin,
            );
          }
          if (op === "revoke") {
            const revokeSession = options.sessionApi.revokeSession;
            if (revokeSession === undefined) {
              return sessionManagementUnavailable("revokeSession", origin);
            }
            return jsonResponse(
              {
                revoked: await options.action(revokeSession, {
                  sessionToken,
                  targetSessionId: requiredString(body, "targetSessionId"),
                }),
              },
              {},
              origin,
            );
          }
          throw new RequestValidationError(
            "op must be one of list, rename, revoke",
          );
        }
      }
      throw new Error("convex-logto: unsupported cookie route.");
    } catch (error) {
      if (error instanceof RequestValidationError) {
        return jsonResponse(
          {
            // Structured so the client can classify it instead of seeing a bare
            // "responded 400" — that is how the signOutEverywhere upgrade hint
            // used to get lost.
            error: {
              kind: "terminal",
              code: "invalid_request",
              message: error.message,
            } satisfies SessionError,
          },
          {
            status: 400,
            ...(clearing === undefined ? {} : { headers: clearing }),
          },
          origin,
        );
      }
      const data = errorData(error);
      const headers =
        clearing ??
        (route === "token" && data?.kind === "terminal"
          ? { "Set-Cookie": clearCookieHeader() }
          : undefined);
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
    return await handleRoute(route, request, origin);
  };

  return Object.assign(handle, {
    getInitialToken: async (
      request: Request,
    ): Promise<LogtoSessionCookieSeed> => {
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
      } catch {
        // Every failed seed returns empty without changing the cookie —
        // including an error this transport cannot classify, which is what an
        // unreachable Logto looks like (the component rethrows a raw `fetch`
        // failure unclassified on purpose, so that an outage does not force a
        // reauthentication). Rethrowing would turn that outage into a 500
        // document for every signed-in visitor, while the browser `/token`
        // route — the authoritative one — treats the same failure as transient
        // and keeps the session. A genuine misconfiguration still surfaces
        // there, loudly, on the first request after hydration.
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

async function parseFetchResponse(
  response: Response,
  signal: AbortSignal,
): Promise<unknown> {
  const bodyResult = await readBoundedBody(
    response,
    MAX_COOKIE_RESPONSE_BYTES,
    signal,
  );
  if (!bodyResult.ok) {
    throw new Error(
      bodyResult.reason === "too_large"
        ? "convex-logto: session cookie handler response is too large."
        : "convex-logto: could not read the session cookie handler response.",
    );
  }
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(bodyResult.bytes));
  } catch {
    body = {};
  }
  if (response.ok) return body;
  if (isRecord(body) && isRecord(body.error)) {
    const { kind, code, message } = body.error;
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

function invalidCookieResponse(): Error {
  return new Error(
    "convex-logto: session cookie handler returned an invalid response.",
  );
}

function parseNavigationUrl(value: unknown, description: string): string {
  if (typeof value !== "string") throw invalidCookieResponse();
  try {
    return normalizeHttpNavigationUrl(value, description);
  } catch {
    // Do not expose whether the same-site handler returned a malformed URL,
    // credentials, or an unsafe scheme. The transport boundary has one public
    // malformed-success error contract.
    throw invalidCookieResponse();
  }
}

function parseSignInResponse(value: unknown): { url: string } {
  if (!isRecord(value)) throw invalidCookieResponse();
  return { url: parseNavigationUrl(value.url, "authorization") };
}

function parseCallbackResponse(value: unknown): {
  idToken: string;
  sessionId: string;
  returnTo?: string;
} {
  if (
    !isRecord(value) ||
    typeof value.idToken !== "string" ||
    value.idToken === "" ||
    typeof value.sessionId !== "string" ||
    value.sessionId === "" ||
    (value.returnTo !== undefined &&
      (typeof value.returnTo !== "string" || !isSafeReturnTo(value.returnTo)))
  ) {
    throw invalidCookieResponse();
  }
  return value.returnTo === undefined
    ? { idToken: value.idToken, sessionId: value.sessionId }
    : {
        idToken: value.idToken,
        sessionId: value.sessionId,
        returnTo: value.returnTo,
      };
}

function parseTokenResponse(value: unknown): {
  idToken: string;
  sessionId: string;
} {
  if (
    !isRecord(value) ||
    typeof value.idToken !== "string" ||
    value.idToken === "" ||
    typeof value.sessionId !== "string" ||
    value.sessionId === ""
  ) {
    throw invalidCookieResponse();
  }
  return { idToken: value.idToken, sessionId: value.sessionId };
}

function parseSignOutResponse(value: unknown): {
  endSessionUrl?: string;
} {
  if (!isRecord(value)) throw invalidCookieResponse();
  return value.endSessionUrl === undefined
    ? {}
    : {
        endSessionUrl: parseNavigationUrl(value.endSessionUrl, "end-session"),
      };
}

function parseSignOutEverywhereResponse(value: unknown): {
  count: number;
  endSessionUrl?: string;
} {
  const result = parseSignOutResponse(value);
  if (
    !isRecord(value) ||
    typeof value.count !== "number" ||
    !Number.isSafeInteger(value.count) ||
    value.count < 0
  ) {
    throw invalidCookieResponse();
  }
  return { count: value.count, ...result };
}

function readTargetSessionId(args: unknown): string {
  if (!isRecord(args)) throw invalidCookieResponse();
  const value = args.targetSessionId;
  if (typeof value !== "string" || value === "") throw invalidCookieResponse();
  return value;
}

function readOptionalLabel(args: unknown): string | undefined {
  if (!isRecord(args)) throw invalidCookieResponse();
  const value = args.label;
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw invalidCookieResponse();
  // "" clears the label on every other transport, so it must not be forwarded
  // as a value this route would then reject.
  return value.trim() === "" ? undefined : value;
}

function parseSessionListResponse(value: unknown): {
  sessions: LogtoSessionSummary[];
  truncated: boolean;
} {
  if (!isRecord(value) || typeof value.truncated !== "boolean") {
    throw invalidCookieResponse();
  }
  const sessions: unknown = value.sessions;
  if (!Array.isArray(sessions)) throw invalidCookieResponse();
  return {
    sessions: sessions.map((entry) => parseSessionSummary(entry)),
    truncated: value.truncated,
  };
}

function parseSessionSummary(value: unknown): LogtoSessionSummary {
  if (
    !isRecord(value) ||
    typeof value.sessionId !== "string" ||
    typeof value.current !== "boolean" ||
    typeof value.createdAt !== "number" ||
    typeof value.lastRefreshedAt !== "number" ||
    typeof value.deviceBound !== "boolean" ||
    (value.label !== undefined && typeof value.label !== "string")
  ) {
    throw invalidCookieResponse();
  }
  const client = parseSessionClient(value.client);
  return {
    sessionId: value.sessionId,
    current: value.current,
    createdAt: value.createdAt,
    lastRefreshedAt: value.lastRefreshedAt,
    deviceBound: value.deviceBound,
    ...(value.label === undefined ? {} : { label: value.label }),
    ...(client === undefined ? {} : { client }),
  };
}

function parseSessionClient(
  value: unknown,
): LogtoSessionClientDescriptor | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw invalidCookieResponse();
  const fields = (["platform", "os", "browser"] as const).flatMap((key) => {
    const field = value[key];
    if (field === undefined) return [];
    if (typeof field !== "string") throw invalidCookieResponse();
    return [[key, field] as const];
  });
  return fields.length === 0 ? undefined : Object.fromEntries(fields);
}

function parseSessionMutationResponse(
  value: unknown,
  field: "renamed" | "revoked",
): boolean {
  if (!isRecord(value) || typeof value[field] !== "boolean") {
    throw invalidCookieResponse();
  }
  return value[field];
}

function readPostLogoutRedirectUri(args: unknown): string | undefined {
  if (!isRecord(args)) throw invalidCookieResponse();
  const value = args.postLogoutRedirectUri;
  if (value === undefined || typeof value === "string") return value;
  throw invalidCookieResponse();
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
  const actionNames = {
    signIn: getFunctionName(sessionApi.signIn),
    callback: getFunctionName(sessionApi.callback),
    refresh: getFunctionName(sessionApi.refresh),
    signOut: getFunctionName(sessionApi.signOut),
    signOutEverywhere:
      sessionApi.signOutEverywhere === undefined
        ? undefined
        : getFunctionName(sessionApi.signOutEverywhere),
    listSessions:
      sessionApi.listSessions === undefined
        ? undefined
        : getFunctionName(sessionApi.listSessions),
    renameSession:
      sessionApi.renameSession === undefined
        ? undefined
        : getFunctionName(sessionApi.renameSession),
    revokeSession:
      sessionApi.revokeSession === undefined
        ? undefined
        : getFunctionName(sessionApi.revokeSession),
  };

  const post = async (route: CookieRoute, body: unknown): Promise<unknown> => {
    const controller = new AbortController();
    const timeoutError = new Error(
      "convex-logto: session cookie handler request timed out.",
    );
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timeoutId = setTimeout(() => {
        // Settle the caller even when an injected Fetch implementation ignores
        // AbortSignal. Standard Fetch also observes the abort and cancels IO.
        reject(timeoutError);
        controller.abort(timeoutError);
      }, COOKIE_TRANSPORT_TIMEOUT_MS);
    });
    const operation = (async () => {
      const response = await fetcher(endpointRoute(endpoint, route), {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          [LOGTO_SESSION_CSRF_HEADER]: LOGTO_SESSION_CSRF_VALUE,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (controller.signal.aborted) throw timeoutError;
      return await parseFetchResponse(response, controller.signal);
    })();
    try {
      return await Promise.race([operation, timeout]);
    } finally {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
    }
  };

  return {
    action: async <Action extends SessionAction>(
      action: Action,
      args: Action["_args"],
    ): Promise<Action["_returnType"]> => {
      const actionName = getFunctionName(action);
      if (actionName === actionNames.signIn) {
        return parseSignInResponse(await post("sign-in", args));
      }
      if (actionName === actionNames.callback) {
        const result = parseCallbackResponse(await post("callback", args));
        return {
          ...result,
          sessionToken: COOKIE_SESSION_MARKER,
        };
      }
      if (actionName === actionNames.refresh) {
        const result = parseTokenResponse(await post("token", {}));
        return {
          ...result,
          sessionToken: COOKIE_SESSION_MARKER,
        };
      }
      if (actionName === actionNames.signOut) {
        return parseSignOutResponse(
          await post("sign-out", {
            postLogoutRedirectUri: readPostLogoutRedirectUri(args),
          }),
        );
      }
      if (
        actionNames.signOutEverywhere !== undefined &&
        actionName === actionNames.signOutEverywhere
      ) {
        return parseSignOutEverywhereResponse(
          await post("sign-out", {
            postLogoutRedirectUri: readPostLogoutRedirectUri(args),
            everywhere: true,
          }),
        );
      }
      if (
        actionNames.listSessions !== undefined &&
        actionName === actionNames.listSessions
      ) {
        return parseSessionListResponse(await post("sessions", { op: "list" }));
      }
      if (
        actionNames.renameSession !== undefined &&
        actionName === actionNames.renameSession
      ) {
        const label = readOptionalLabel(args);
        return parseSessionMutationResponse(
          await post("sessions", {
            op: "rename",
            targetSessionId: readTargetSessionId(args),
            ...(label === undefined ? {} : { label }),
          }),
          "renamed",
        );
      }
      if (
        actionNames.revokeSession !== undefined &&
        actionName === actionNames.revokeSession
      ) {
        return parseSessionMutationResponse(
          await post("sessions", {
            op: "revoke",
            targetSessionId: readTargetSessionId(args),
          }),
          "revoked",
        );
      }
      throw new Error(
        "convex-logto: the cookie transport received an unknown session action.",
      );
    },
  };
}
