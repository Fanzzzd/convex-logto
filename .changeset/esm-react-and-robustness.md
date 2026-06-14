---
"convex-logto": patch
---

Robustness and packaging fixes:

- **`convex-logto/react` is now ESM-only.** It previously advertised a CommonJS build, but `@logto/react@4` is ESM-only, so `require("convex-logto/react")` was a runtime trap for CJS/Node consumers. The root `convex-logto` entry stays dual ESM+CJS.
- **Sign-in callback now handles all OIDC redirects**, not just `?code=` on the callback path — OAuth `?error=…` responses and `signIn(customRedirectUri)` landings are handled too. The handler keys off Logto's stored sign-in session, so it stays a no-op on ordinary navigation.
- **Webhook handler is stricter**: malformed (non-hex) signatures and unknown event types are now rejected (401/400) instead of being silently accepted.
- **Token refresh no longer returns a stale ID token** — if the refresh exchange fails, the bridge returns `null` and Convex drives re-authentication.
- **`LOGTO_ENDPOINT` is trimmed and trailing-slash-normalized**, so a pasted value like `https://auth.example.com/` works.
- **Types**: `useLogtoAuth().signIn` / `signOut` are now correctly typed as returning `Promise<void>`.
