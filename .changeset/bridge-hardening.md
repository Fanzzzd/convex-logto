---
"convex-logto": minor
---

Bridge hardening: static config by default, exact-callback handling, and safer sign-in redirects.

- **Static `config` prop (new default).** Pass `config={{ endpoint, appId }}` (both public values) from build-time env instead of `configQuery` — no config round-trip, no loading phase; sign-in is interactive on first paint. `configQuery` remains supported for runtime-resolved config (multi-tenant), now rendering the new `fallback` prop while it loads and mounting children exactly once when ready. The internal inert-client + keyed-remount machinery is gone.
- **Callback handling is gated to `callbackPath`** (new prop, default `/callback`). A stray `?code=&state=` on any other route no longer triggers a pending auth state (previously a 10s spinner). The #11/#14 protections (loading latch through the exchange, stale-callback resolution) are unchanged — only their trigger is now the exact callback route.
- **`signIn({ returnTo })`.** The post-sign-in destination must be a same-origin path starting with `/`; full URLs and protocol-relative values are rejected (open-redirect guard, RFC 9700 §4.11.1). `signIn(redirectUri: string)` is deprecated but still works; if its path can't match `callbackPath`, a console error explains the fix.
- **`onAuthError` prop.** Recoverable sign-in failures (stale/replayed callback, setup errors like `invalid_scope`) no longer throw during render — they're reported to `onAuthError` (and the console) and the user is returned to the app logged out.
- **OIDC discovery/JWKS cache on by default** (`discoveryCache={false}` to opt out), so the sign-in and callback pages don't each pay a discovery round-trip.
- **Concurrent token fetches merge** into one in-flight request per kind; a forced refresh is never satisfied by a stale in-flight fetch.
- **Peer dependency: `@logto/react >= 4`** (was `>= 3` — already de-facto required since the `/react` entry went ESM-only).
- Native (`convex-logto/native`): the same `config` XOR `configQuery` union; behavior otherwise unchanged.
