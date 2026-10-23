// Classifies the URL after a Logto sign-in redirect. Only a real OIDC redirect
// carries a `state` param, so this ignores a stray `?error=`/`?code=` on an
// ordinary app route rather than mistaking it for a sign-in result.

const OAUTH_ERROR_HINTS = new Map<string, string>([
  [
    "invalid_scope",
    "This usually means a requested scope isn't allowed. Check any extra `scopes` " +
      "you passed, and that LOGTO_APP_ID points at a Single-page app (not a Third-party app).",
  ],
]);

// OAuth errors that only mean "no session" (e.g. the user cancelled). Return to
// the app.
const BENIGN_OAUTH_ERRORS = new Set([
  "access_denied",
  "login_required",
  "interaction_required",
  "consent_required",
]);

export type SignInOutcome =
  | { kind: "none" } // not a sign-in redirect
  | { kind: "pending" } // a redirect with no error; the SDK is exchanging the code
  | { kind: "benign" } // the user cancelled / no session; return to the app
  | { kind: "error"; message: string }; // a setup error worth showing

export function classifySignInSearch(search: string): SignInOutcome {
  const params = new URLSearchParams(search);
  // Every OIDC redirect carries `state`; without it, this isn't a sign-in result.
  if (!params.has("state")) return { kind: "none" };
  const error = params.get("error");
  if (error) {
    if (BENIGN_OAUTH_ERRORS.has(error)) return { kind: "benign" };
    const description = params.get("error_description");
    // A Map, not an object, because `error` is straight off the query string,
    // and an object lookup would resolve `?error=constructor` through the
    // prototype chain and splice a function's source into the message the app
    // displays.
    const hint = OAUTH_ERROR_HINTS.get(error);
    return {
      kind: "error",
      message:
        `Logto sign-in failed with "${error}"` +
        (description ? ` (${description})` : "") +
        (hint ? `. ${hint}` : "."),
    };
  }
  // A successful redirect carries both `code` and `state`.
  return params.has("code") ? { kind: "pending" } : { kind: "none" };
}

/**
 * Should a `/callback` landing stop waiting and return to the app? The URL only
 * tells us a redirect *looks* pending; `@logto/react` exchanges the code only
 * when `!isAuthenticated && isSignInRedirected(url)`. When that's false,
 * because the user is already authenticated (a stale/replayed callback URL) or
 * the sign-in session was lost, the exchange never runs and its callback never
 * fires, so we must resolve from observable state instead of waiting forever
 * (#14):
 *
 * - `isAuthenticated` covers both a successful exchange (the SDK flips it true
 *   as it finishes) AND an already-authenticated replay (true on entry, no
 *   exchange).
 * - `timedOut` is the rare `!isAuthenticated && !isSignInRedirected` case (no
 *   session, no error ever arrives), a safety net so the page can't spin
 *   forever.
 * - `errored` means the exchange ran and failed: a state mismatch on a
 *   stale/replayed callback URL, a spent code, or a lost sign-in session. The
 *   popular auto-callback providers (`react-oidc-context`,
 *   `@auth0/auth0-react`) put such a failure into state and never throw during
 *   render, so a stale callback can't crash the app; we mirror that by
 *   treating it as resolved (return to the app) rather than fatal.
 */
export function callbackResolved(state: {
  isAuthenticated: boolean;
  timedOut: boolean;
  errored: boolean;
}): boolean {
  return state.isAuthenticated || state.timedOut || state.errored;
}

/**
 * The URL parser *removes a raw ASCII tab, LF, or CR before it parses
 * anything*, so `/<TAB>/evil.com` inspects as a same-origin path and then
 * resolves to `//evil.com`. This refuses the rest of the C0 range and DEL with
 * them, because a legitimate path carries a control character percent-encoded,
 * never raw.
 */
function hasControlCharacter(returnTo: string): boolean {
  for (let index = 0; index < returnTo.length; index += 1) {
    const code = returnTo.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Is `returnTo` a safe post-sign-in destination? Only same-origin path
 * navigation is allowed: a single leading `/`, not `//host`
 * (protocol-relative), no `\` (some URL parsers fold `\` into `/`, turning
 * `/\evil.com` into `//evil.com`), and no raw control character (see above).
 * Anything else would let a crafted link turn the sign-in flow into an open
 * redirect (RFC 9700 §4.11.1 forbids client-side open redirectors).
 *
 * This is the only gate. Every caller navigates with the string unmodified.
 */
export function isSafeReturnTo(returnTo: string): boolean {
  return (
    returnTo.startsWith("/") &&
    !returnTo.startsWith("//") &&
    !returnTo.includes("\\") &&
    !hasControlCharacter(returnTo)
  );
}
