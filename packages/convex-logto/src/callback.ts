// Classifies the URL after a Logto sign-in redirect. Only a real OIDC redirect
// carries a `state` param, so a stray `?error=`/`?code=` on an ordinary app route
// is ignored rather than mistaken for a sign-in result.

const OAUTH_ERROR_HINTS: Record<string, string> = {
  invalid_scope:
    "This usually means a requested scope isn't allowed — check any extra `scopes` " +
    "you passed, and that LOGTO_APP_ID points at a Single-page app (not a Third-party app).",
};

// OAuth errors that just mean "no session" (e.g. the user cancelled): return to the app.
const BENIGN_OAUTH_ERRORS = new Set([
  "access_denied",
  "login_required",
  "interaction_required",
  "consent_required",
]);

export type SignInOutcome =
  | { kind: "none" } // not a sign-in redirect
  | { kind: "pending" } // a redirect with no error — the SDK is exchanging the code
  | { kind: "benign" } // the user cancelled / no session — return to the app
  | { kind: "error"; message: string }; // a setup error worth surfacing

export function classifySignInSearch(search: string): SignInOutcome {
  const params = new URLSearchParams(search);
  // Every OIDC redirect carries `state`; without it, this isn't a sign-in result.
  if (!params.has("state")) return { kind: "none" };
  const error = params.get("error");
  if (error) {
    if (BENIGN_OAUTH_ERRORS.has(error)) return { kind: "benign" };
    const description = params.get("error_description");
    const hint = OAUTH_ERROR_HINTS[error];
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
 * tells us a redirect *looks* pending; `@logto/react` actually exchanges the code
 * only when `!isAuthenticated && isSignInRedirected(url)`. When that's false — the
 * user is already authenticated (a stale/replayed callback URL), or the sign-in
 * session was lost — the exchange never runs and its callback never fires, so we
 * must resolve from observable state instead of waiting forever (#14):
 *
 * - `isAuthenticated`: covers both a successful exchange (the SDK flips it true as
 *   it finishes) AND an already-authenticated replay (true on entry, no exchange).
 * - `timedOut`: the rare `!isAuthenticated && !isSignInRedirected` case (no session,
 *   no error ever arrives) — a safety net so the page can't spin indefinitely.
 * - `errored`: the exchange ran and failed — a state mismatch on a stale/replayed
 *   callback URL, a spent code, or a lost sign-in session. The popular auto-callback
 *   providers (`react-oidc-context`, `@auth0/auth0-react`) put such a failure into
 *   state and never throw during render, so a stale callback can't crash the app; we
 *   mirror that by treating it as resolved (return to the app) rather than fatal.
 */
export function callbackResolved(state: {
  isAuthenticated: boolean;
  timedOut: boolean;
  errored: boolean;
}): boolean {
  return state.isAuthenticated || state.timedOut || state.errored;
}
