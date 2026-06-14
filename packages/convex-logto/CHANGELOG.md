# convex-logto

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
