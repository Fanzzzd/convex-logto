---
"convex-logto": minor
---

Static JWKS: `logtoAuthConfig({ jwks: process.env.LOGTO_JWKS })` returns a Convex `customJwt` provider with Logto's keys inlined, so Convex stops fetching Logto's discovery document and JWKS on every WebSocket that authenticates (870 ms to 300 ms to auth confirmation on a self-hosted Logto in another region). The issuer stays `${endpoint}/oidc`, so `tokenIdentifier` does not change. It throws naming `LOGTO_JWKS` when the value is not JSON, not a JWKS, or holds no RS256 key. Without `jwks` nothing changes, and the package never reads `LOGTO_JWKS` unless you pass it.

New bin: `npx convex-logto sync-jwks` copies the deployment's own Logto keys into `LOGTO_JWKS`, and `npx convex-logto check-jwks` exits 1 when Logto serves a key the copy lacks. Every other flag goes to `convex env` unchanged (`--prod`, `--deployment-name`, `--preview-name`, `--url`, `--admin-key`, `--env-file`, `CONVEX_DEPLOY_KEY`). After rotating keys in Logto, run `sync-jwks` on every deployment, or every new sign-in is rejected.

New exported types: `LogtoConnectionOptions`, `LogtoStaticJwksProvider`, `LogtoAuthProvider`. One type-level change: `logtoAuthConfig(options)` with a variable typed `LogtoAuthConfigOptions` now returns the union `LogtoAuthProvider`, because that type has the optional `jwks`. A call with no argument, or with an inline object without `jwks`, still returns `LogtoOidcProvider`, and every return type satisfies Convex's `AuthConfig`.
