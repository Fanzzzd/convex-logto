---
"convex-logto": patch
---

Document that `resources` on `logtoSessionApi()` currently buys nothing. Session
mode keeps the refresh token in the component and hands the browser only the ID
token, so the resource-scoped access token the option requests is discarded —
while a resource indicator Logto does not have registered breaks sign-in
outright. Leave it unset for now. Bridge mode's `resources` is unaffected: there
the Logto SDK owns the tokens and exposes `getAccessToken()`.
