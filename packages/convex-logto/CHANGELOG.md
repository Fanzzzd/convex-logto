# convex-logto

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
