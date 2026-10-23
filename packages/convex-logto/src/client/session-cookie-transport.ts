import { getFunctionName } from "convex/server";
import { ConvexError } from "convex/values";
import type {
  LogtoResourceTokenClaims,
  LogtoSessionApi,
  LogtoSessionClientDescriptor,
  LogtoSessionSummary,
} from "../server/session";
import { isSafeReturnTo } from "../shared/callback";
import { isRecord } from "../shared/decode";
import { normalizeHttpNavigationUrl } from "../shared/endpoint";
import { readBoundedBody } from "../shared/http-body";
import {
  COOKIE_SESSION_MARKER,
  LOGTO_SESSION_COOKIE_BASE_PATH,
  LOGTO_SESSION_CSRF_HEADER,
  LOGTO_SESSION_CSRF_VALUE,
  assertLogtoSessionCookieCompatibility,
  type CookieRoute,
  type SessionAction,
} from "../shared/session-cookie-protocol";
import type { SessionTransport, StoredSession } from "./session-client";

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

export type LogtoSessionCookieTransportOptions = {
  /** Handler mount point (relative or absolute). Default `/api/logto-session`. */
  endpoint?: string;
  /** Injectable Fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** See `LogtoSessionCookieHandlerOptions.deviceBinding`. */
  deviceBinding?: boolean;
};

const MAX_COOKIE_RESPONSE_BYTES = 256 * 1024;
const COOKIE_TRANSPORT_TIMEOUT_MS = 10 * 1000;

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

function readExchangeArgs(args: Record<string, unknown>): {
  organizationId?: string;
  resource?: string;
  scopes?: string[];
  includeToken?: boolean;
  forceRefresh?: boolean;
} {
  const organizationId = args["organizationId"];
  const resource = args["resource"];
  const scopes = args["scopes"];
  const includeToken = args["includeToken"];
  const forceRefresh = args["forceRefresh"];
  return {
    ...(typeof organizationId === "string" ? { organizationId } : {}),
    ...(typeof resource === "string" ? { resource } : {}),
    ...(Array.isArray(scopes) &&
    scopes.every((entry) => typeof entry === "string")
      ? { scopes }
      : {}),
    ...(typeof includeToken === "boolean" ? { includeToken } : {}),
    ...(typeof forceRefresh === "boolean" ? { forceRefresh } : {}),
  };
}

function parseExchangeTokenResponse(value: unknown): {
  claims: LogtoResourceTokenClaims;
  accessToken?: string;
  minted: boolean;
} {
  if (!isRecord(value) || typeof value.minted !== "boolean") {
    throw invalidCookieResponse();
  }
  const claims: unknown = value.claims;
  if (
    !isRecord(claims) ||
    typeof claims.audience !== "string" ||
    typeof claims.expiresAt !== "number" ||
    !Array.isArray(claims.scopes)
  ) {
    throw invalidCookieResponse();
  }
  const scopes: string[] = [];
  for (const entry of claims.scopes) {
    if (typeof entry !== "string") throw invalidCookieResponse();
    scopes.push(entry);
  }
  return {
    claims: {
      audience: claims.audience,
      expiresAt: claims.expiresAt,
      scopes,
      ...(typeof claims.organizationId === "string"
        ? { organizationId: claims.organizationId }
        : {}),
      ...(typeof claims.resource === "string"
        ? { resource: claims.resource }
        : {}),
    },
    ...(typeof value.accessToken === "string"
      ? { accessToken: value.accessToken }
      : {}),
    minted: value.minted,
  };
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
 * Browser adapter for `SessionAuthEngine`. It ignores session-token arguments,
 * because the browser can only present the HttpOnly cookie through Fetch
 * credentials.
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
    exchangeToken:
      sessionApi.exchangeToken === undefined
        ? undefined
        : getFunctionName(sessionApi.exchangeToken),
    fetchUserInfo:
      sessionApi.fetchUserInfo === undefined
        ? undefined
        : getFunctionName(sessionApi.fetchUserInfo),
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
      if (
        actionNames.exchangeToken !== undefined &&
        actionName === actionNames.exchangeToken
      ) {
        return parseExchangeTokenResponse(
          await post("tokens", { op: "exchange", ...readExchangeArgs(args) }),
        );
      }
      if (
        actionNames.fetchUserInfo !== undefined &&
        actionName === actionNames.fetchUserInfo
      ) {
        const forceRefresh = args["forceRefresh"];
        return await post("tokens", {
          op: "userinfo",
          ...(typeof forceRefresh === "boolean" ? { forceRefresh } : {}),
        });
      }
      throw new Error(
        "convex-logto: the cookie transport received an unknown session action.",
      );
    },
  };
}
