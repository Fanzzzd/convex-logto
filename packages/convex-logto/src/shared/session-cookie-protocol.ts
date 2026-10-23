// The wire contract between the same-site cookie handler (server) and the
// cookie transport (browser): route names, the CSRF header, the default mount
// point, and the rule both halves enforce about device binding.
import type { FunctionReference } from "convex/server";

/** Fixed non-simple request header required on every state-changing request. */
export const LOGTO_SESSION_CSRF_HEADER = "x-convex-logto-csrf";

/** Fixed value for {@link LOGTO_SESSION_CSRF_HEADER}. */
export const LOGTO_SESSION_CSRF_VALUE = "1";

/** Default mount point for the six cookie transport routes. */
export const LOGTO_SESSION_COOKIE_BASE_PATH = "/api/logto-session";

/**
 * The cookie credential never enters JavaScript. The existing session engine
 * still needs a non-secret marker so it knows a cookie-backed session exists.
 */
export const COOKIE_SESSION_MARKER = "cookie-session";

export type SessionAction = FunctionReference<"action">;

/** The action-calling slice shared by ConvexHttpClient and an HTTP action ctx. */
export type LogtoSessionAction = <Action extends SessionAction>(
  action: Action,
  args: Action["_args"],
) => Promise<Action["_returnType"]>;

export type CookieRoute =
  | "sign-in"
  | "callback"
  | "token"
  | "sign-out"
  | "sessions"
  | "tokens";

export function isCookieRoute(value: string): value is CookieRoute {
  return (
    value === "sign-in" ||
    value === "callback" ||
    value === "token" ||
    value === "sign-out" ||
    value === "sessions" ||
    value === "tokens"
  );
}

/**
 * Throw when cookie transport would combine with software device binding.
 * HttpOnly deliberately makes the token unavailable to the JavaScript key
 * that must sign it, so the two guarantees cannot combine without weakening
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
