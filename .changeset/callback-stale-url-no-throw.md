---
"convex-logto": patch
---

Don't crash the app on a stale or replayed `/callback` URL whose code exchange fails.

When a sign-in session was still in storage (an abandoned or earlier sign-in) and the page landed on a stale/replayed `/callback?code=…&state=…` — a bookmark, the Back button, or a link from a previous deploy — `@logto/react` ran the exchange and it failed with a state mismatch. The provider surfaced that by **throwing during render**, which blanked any app whose error boundary sits inside `<ConvexLogtoProvider>` (or that has none).

Following how `react-oidc-context` and `@auth0/auth0-react` handle the redirect callback, a failed exchange is now treated as recoverable, not fatal: it is logged (`console.error`) and the provider returns to the app — the user lands logged-out and can start sign-in again — instead of throwing. Genuine OIDC setup errors (an `error=` in the callback URL) still surface loudly as before.
