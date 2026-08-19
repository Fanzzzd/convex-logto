---
"convex-logto": patch
---

Session mode: re-seeding SSR state or passing an inline `cookieTransport.fetch`
no longer rebuilds the auth engine. `getInitialToken()` mints a fresh ID token on
every call, so any `router.invalidate()` handed the provider a new seed and
restarted the mount state machine — flashing signed-out, orphaning an in-flight
callback exchange, and leaving the `convex_authenticated` span open forever.
