---
"convex-logto": minor
---

New **session mode**: keep the Logto refresh token out of the browser entirely.

A Convex component (`convex-logto/convex.config`, installed with
`app.use(logto)`) acts as the OAuth client for a Logto **Traditional Web** app:
it performs the code exchange server-side (client secret + PKCE), stores the
refresh token in component-isolated tables, and gives the browser only a
short-lived ID token plus a one-time session token that rotates on every
refresh (hash-stored, reuse-detected — presenting a spent token outside a 10s
multi-tab grace window kills the session and revokes the Logto grant, RFC 7009).

- `logtoSessionApi(components.logto)` (from `convex-logto`) builds the five
  public auth functions — `signIn` / `callback` / `refresh` / `signOut` /
  `sessionValid` — reading `LOGTO_ENDPOINT` / `LOGTO_APP_ID` /
  `LOGTO_CLIENT_SECRET` from the deployment env. The secret never reaches the
  browser; scopes/resources are server-configured.
- New entry `convex-logto/react-session`: `ConvexLogtoSessionProvider` +
  `useLogtoAuth()` with the same shape as the bridge hook — and **no
  `@logto/react` dependency**, no Logto config in the bundle. Sign-in state is
  pinned to the initiating tab (login-CSRF refusal), the callback completes
  without a callback component, reloads authenticate with zero round-trips
  while the cached ID token is fresh, and multi-tab refreshes are
  single-flighted (Web Locks + in-flight merge + a server-side claim).
- **Reactive revocation**: every session's liveness is a Convex subscription —
  sign-out elsewhere, theft detection, or a webhook suspension drops auth live,
  not at token expiry. `assertUserHasActiveSession(ctx, components.logto)`
  enforces the same server-side for sensitive functions.
- Runnable example: `examples/vite-react-session`; docs at `/docs/session-mode`.

Bridge mode is unchanged and remains the default.
