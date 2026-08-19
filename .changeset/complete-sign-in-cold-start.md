---
"convex-logto": patch
---

Native session mode: `completeSignIn(url)` now works on the cold start it was
added for. It waits for SecureStore to hydrate before touching the OIDC stash —
the deep link normally arrives before the provider's mount effect, and reading
the stash too early deleted the transaction it came to spend. A duplicate
delivery of the same URL now completes once instead of reporting a replayed
callback, and a link that matches the redirect prefix but carries no OIDC
response leaves an in-flight sign-in alone.
