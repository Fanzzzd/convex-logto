---
"convex-logto": patch
---

Fix a transient `{ isLoading: false, isAuthenticated: false }` window right after
sign-in that made `useLogtoAuth()` look logged-out while Convex was still
validating the freshly-issued ID token. A TanStack Router `beforeLoad` guard (or
any auth gate that acts on that tick) would redirect the just-signed-in user away
— and bounce into an infinite loop if the sign-in route auto-restarts `signIn()`
(issue #11).

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
