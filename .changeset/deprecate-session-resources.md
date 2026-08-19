---
"convex-logto": patch
---

Deprecate `resources` on `logtoSessionApi()`. Session mode keeps the refresh
token in the component and hands the browser only the ID token, so the
resource-scoped access token the option buys is discarded — and a resource
indicator Logto does not have registered breaks sign-in outright. Bridge mode's
`resources` is unaffected: there the Logto SDK owns the tokens and exposes
`getAccessToken()`.
