# convex-logto

## 0.4.0

### Minor Changes

- [#22](https://github.com/Fanzzzd/convex-logto/pull/22) [`75b3ed8`](https://github.com/Fanzzzd/convex-logto/commit/75b3ed8499c346b0c985ba9806d87f6971167ec3) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Bridge hardening: static config by default, exact-callback handling, and safer sign-in redirects.

  - **Static `config` prop (new default).** Pass `config={{ endpoint, appId }}` (both public values) from build-time env instead of `configQuery` — no config round-trip, no loading phase; sign-in is interactive on first paint. `configQuery` remains supported for runtime-resolved config (multi-tenant), now rendering the new `fallback` prop while it loads and mounting children exactly once when ready. The internal inert-client + keyed-remount machinery is gone.
  - **Callback handling is gated to `callbackPath`** (new prop, default `/callback`). A stray `?code=&state=` on any other route no longer triggers a pending auth state (previously a 10s spinner). The [#11](https://github.com/Fanzzzd/convex-logto/issues/11)/[#14](https://github.com/Fanzzzd/convex-logto/issues/14) protections (loading latch through the exchange, stale-callback resolution) are unchanged — only their trigger is now the exact callback route.
  - **`signIn({ returnTo })`.** The post-sign-in destination must be a same-origin path starting with `/`; full URLs and protocol-relative values are rejected (open-redirect guard, RFC 9700 §4.11.1). `signIn(redirectUri: string)` is deprecated but still works; if its path can't match `callbackPath`, a console error explains the fix.
  - **`onAuthError` prop.** Recoverable sign-in failures (stale/replayed callback, setup errors like `invalid_scope`) no longer throw during render — they're reported to `onAuthError` (and the console) and the user is returned to the app logged out.
  - **OIDC discovery/JWKS cache on by default** (`discoveryCache={false}` to opt out), so the sign-in and callback pages don't each pay a discovery round-trip.
  - **Concurrent token fetches merge** into one in-flight request per kind; a forced refresh is never satisfied by a stale in-flight fetch.
  - **Peer dependency: `@logto/react >= 4`** (was `>= 3` — already de-facto required since the `/react` entry went ESM-only).
  - Native (`convex-logto/native`): the same `config` XOR `configQuery` union; behavior otherwise unchanged.

- [#23](https://github.com/Fanzzzd/convex-logto/pull/23) [`ff08337`](https://github.com/Fanzzzd/convex-logto/commit/ff0833732268735d8b3a555357142c806af0a174) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - New **session mode**: keep the Logto refresh token out of the browser entirely.

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

## 0.3.6

### Patch Changes

- [#20](https://github.com/Fanzzzd/convex-logto/pull/20) [`8d9506d`](https://github.com/Fanzzzd/convex-logto/commit/8d9506d7c0f4cd857211c96743967c91d975705d) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix the app hanging on a loading spinner when `signIn()` is called before the backend config has finished loading (the "stuck on the login button" symptom). During config load the provider mounts an inert Logto client; a `signIn()` in that window poisoned `@logto/react`'s `loadingCount` (its `signIn` increments but never resets, and the inert method never navigates away), and that count survived the swap to the real client — pinning `isLoading` true forever. The `LogtoProvider` is now remounted across the loading→ready transition, so any state built against the inert client is discarded.

## 0.3.5

### Patch Changes

- [#18](https://github.com/Fanzzzd/convex-logto/pull/18) [`be970e8`](https://github.com/Fanzzzd/convex-logto/commit/be970e83d21334c10df8b50b794c955e2d1c679c) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Don't crash the app on a stale or replayed `/callback` URL whose code exchange fails.

  When a sign-in session was still in storage (an abandoned or earlier sign-in) and the page landed on a stale/replayed `/callback?code=…&state=…` — a bookmark, the Back button, or a link from a previous deploy — `@logto/react` ran the exchange and it failed with a state mismatch. The provider surfaced that by **throwing during render**, which blanked any app whose error boundary sits inside `<ConvexLogtoProvider>` (or that has none).

  Following how `react-oidc-context` and `@auth0/auth0-react` handle the redirect callback, a failed exchange is now treated as recoverable, not fatal: it is logged (`console.error`) and the provider returns to the app — the user lands logged-out and can start sign-in again — instead of throwing. Genuine OIDC setup errors (an `error=` in the callback URL) still surface loudly as before.

## 0.3.4

### Patch Changes

- [#15](https://github.com/Fanzzzd/convex-logto/pull/15) [`edca280`](https://github.com/Fanzzzd/convex-logto/commit/edca2808d907380e6290dc6d1709d4937804106d) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix the Logto sign-in callback hanging forever on a stale or already-authenticated `/callback` URL.

  `ConvexLogtoProvider` decided "a code exchange is in progress, keep waiting" purely from the URL (`?code=&state=`), but `@logto/react` only runs the exchange when `!isAuthenticated && isSignInRedirected(url)`. Re-opening an already-consumed callback URL — by refresh, Back button, or a bookmark, most often while already signed in — left the page stuck on the loading state with no navigation, because the SDK's exchange callback never fires. The provider now resolves the callback from the SDK's observable auth state (with a timeout safety net for a lost sign-in session) instead of waiting for an exchange that will never happen ([#14](https://github.com/Fanzzzd/convex-logto/issues/14)).

## 0.3.3

### Patch Changes

- [#12](https://github.com/Fanzzzd/convex-logto/pull/12) [`0f2e2d5`](https://github.com/Fanzzzd/convex-logto/commit/0f2e2d55d57778582ef44711a155f3aa2afe2bcc) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix a transient `{ isLoading: false, isAuthenticated: false }` window right after
  sign-in that made `useLogtoAuth()` look logged-out while Convex was still
  validating the freshly-issued ID token. A TanStack Router `beforeLoad` guard (or
  any auth gate that acts on that tick) would redirect the just-signed-in user away
  — and bounce into an infinite loop if the sign-in route auto-restarts `signIn()`
  (issue [#11](https://github.com/Fanzzzd/convex-logto/issues/11)).

  Both entries are fixed:

  - **Web (`convex-logto/react`):** the bridge keeps reporting `isLoading: true`
    while a sign-in callback is in flight (an unconsumed `code` in the URL and Logto
    not yet authenticated), so guards wait the validation window out instead of
    seeing a state indistinguishable from a clean logout.
  - **Native (`convex-logto/native`):** `@logto/rn` flips `isAuthenticated` true the
    instant `signIn()` resolves, with no loading signal of its own. The bridge now
    emits one loading frame on that transition — reported as not-yet-authenticated —
    so Convex resets cleanly to "validating" instead of surfacing the logged-out
    tick, with no auth churn once the token validates.

  Post-login token refreshes still don't flicker the identity, and a genuine
  logged-out visit still settles to signed-out as before.

## 0.3.2

### Patch Changes

- [#9](https://github.com/Fanzzzd/convex-logto/pull/9) [`5857537`](https://github.com/Fanzzzd/convex-logto/commit/5857537bcb3b881213371d43e5237f1aaa3aec49) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Docs: the README install command now covers React Native / Expo. The npm front
  page only showed `pnpm add convex-logto @logto/react`, which installs the wrong
  Logto peer for native apps — they need `@logto/rn`. Added a one-line note pointing
  native users at `@logto/rn` (everything else is identical). No code change.

## 0.3.1

### Patch Changes

- [#7](https://github.com/Fanzzzd/convex-logto/pull/7) [`1daaf39`](https://github.com/Fanzzzd/convex-logto/commit/1daaf3931a55f0f85dd98973d4ef4b80d8de79b0) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Clarify the `convex-logto/native` `fallback` JSDoc: it renders during the one-time
  config fetch, before the Convex provider mounts, so Convex's `<AuthLoading>` belongs
  in your app's children — not inside `fallback`.

## 0.3.0

### Minor Changes

- [#5](https://github.com/Fanzzzd/convex-logto/pull/5) [`0296a82`](https://github.com/Fanzzzd/convex-logto/commit/0296a82f00bd269dc205e4d9fb786089e59f429a) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add React Native / Expo support via a new `convex-logto/native` entry.

  `ConvexLogtoProvider` and `useLogtoAuth` now have native counterparts built on
  `@logto/rn` (added as an optional peer dependency). The server APIs
  (`logtoAuthConfig`, `logtoConfigQuery`, the webhook sync) are unchanged and fully
  shared. On native, `signIn` opens the system browser and resolves on the deep-link
  return — there's no callback route to add, and `signIn()` defaults to the
  provider's `redirectUri`. See the new React Native guide and the `examples/expo` app.

## 0.2.0

### Minor Changes

- [#2](https://github.com/Fanzzzd/convex-logto/pull/2) [`8f80719`](https://github.com/Fanzzzd/convex-logto/commit/8f80719269523e812023a6e929159178d5f4db1c) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - SSR-safe, config-only provider (breaking API slim).

  - **`ConvexLogtoProvider` is now safe to render anywhere, including on the server.** It mounts the Logto + Convex tree from the first render using an inert loading client, so children render immediately (under Convex's `<AuthLoading>`) while config loads, and nothing touches `window` on the server. SSR frameworks (Next.js App Router, TanStack Start) no longer need a hand-written client boundary — a single `<ConvexLogtoProvider>` is enough everywhere.
  - **Breaking — the provider is configured by `configQuery` only.** The literal `endpoint`/`appId` props (and their discriminated union) are removed; `{ endpoint, appId }` is served from the Convex deployment via `logtoConfigQuery()`, so config lives in exactly one place per environment.
  - **Breaking — removed the `callbackPath` prop.** `/callback` is the fixed convention; to use a different path, pass it explicitly: ``signIn(`${origin}/your-path`)``.
  - **Breaking — removed the `fallback` prop.** Children render during config load (gated by `<AuthLoading>`), so a separate fallback is no longer needed.
  - Auth no longer flickers on load or reload: the bridge latches on the first settle and sources `isAuthenticated`/`isLoading` from Convex, verified across repeated authenticated reloads.
  - A failed sign-in code exchange (a stale callback URL or a lost sign-in session) now throws a clear error instead of leaving the callback page stuck on "finishing sign in".

  Note: Convex's OIDC verifier accepts only RS256/EdDSA, but Logto signs with ES384 by default. Rotate your tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → rotate private key → RSA), or `getUserIdentity()` returns `null`.

## 0.1.1

### Patch Changes

- [`a5d6c31`](https://github.com/Fanzzzd/convex-logto/commit/a5d6c31da7dc97ffe3808c20c92bcf4d129fdc0d) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Robustness and packaging fixes:

  - **`convex-logto/react` is now ESM-only.** It previously advertised a CommonJS build, but `@logto/react@4` is ESM-only, so `require("convex-logto/react")` was a runtime trap for CJS/Node consumers. The root `convex-logto` entry stays dual ESM+CJS.
  - **Sign-in callback now handles all OIDC redirects**, not just `?code=` on the callback path — OAuth `?error=…` responses and `signIn(customRedirectUri)` landings are handled too. The handler keys off Logto's stored sign-in session, so it stays a no-op on ordinary navigation.
  - **Webhook handler is stricter**: malformed (non-hex) signatures and unknown event types are now rejected (401/400) instead of being silently accepted.
  - **Token refresh no longer returns a stale ID token** — if the refresh exchange fails, the bridge returns `null` and Convex drives re-authentication.
  - **`LOGTO_ENDPOINT` is trimmed and trailing-slash-normalized**, so a pasted value like `https://auth.example.com/` works.
  - **Types**: `useLogtoAuth().signIn` / `signOut` are now correctly typed as returning `Promise<void>`.

## 0.1.0

### Minor Changes

- Initial release. Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for [Convex](https://convex.dev) React apps.
  - **OIDC ID-token bridge** — `logtoAuthConfig()` for `auth.config.ts` and `ConvexLogtoProvider` / `useLogtoAuth()` for React. Convex validates Logto's ID token over OIDC, so signing algorithm and JWKS are auto-discovered; no manual JWT config.
  - **Backend single-source config** — `logtoConfigQuery()` serves `{ endpoint, appId }` to the frontend, so Logto values live only in each Convex deployment's env. Switching environments is just switching `VITE_CONVEX_URL`; the frontend carries zero Logto config.
  - **Signed webhook user-sync** — `logtoSync()` + `registerLogtoWebhook()` keep your `users` table in sync with Logto, with `verifyLogtoSignature()` doing constant-time HMAC-SHA256 verification over the raw request bytes.
