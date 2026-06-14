# convex-logto

## 0.1.0

### Minor Changes

- Initial release. Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for [Convex](https://convex.dev) React apps.
  - **OIDC ID-token bridge** — `logtoAuthConfig()` for `auth.config.ts` and `ConvexLogtoProvider` / `useLogtoAuth()` for React. Convex validates Logto's ID token over OIDC, so signing algorithm and JWKS are auto-discovered; no manual JWT config.
  - **Backend single-source config** — `logtoConfigQuery()` serves `{ endpoint, appId }` to the frontend, so Logto values live only in each Convex deployment's env. Switching environments is just switching `VITE_CONVEX_URL`; the frontend carries zero Logto config.
  - **Signed webhook user-sync** — `logtoSync()` + `registerLogtoWebhook()` keep your `users` table in sync with Logto, with `verifyLogtoSignature()` doing constant-time HMAC-SHA256 verification over the raw request bytes.
