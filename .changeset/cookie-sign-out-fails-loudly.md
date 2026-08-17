---
"convex-logto": minor
---

Make cookie-transport sign-out honest. The session credential in cookie mode is
an HttpOnly cookie that only the server can expire, so a failed revoke is a
failed sign-out: `signOut()` now rejects instead of resolving while the user
stays signed in, and a revoke failure always reaches `onAuthError` even in
localStorage mode, where sign-out remains locally complete. Every sign-out
response from the cookie route now carries the clear-cookie header, including
the request-validation and malformed-body paths, and validation errors are
returned in the structured `{ kind, code, message }` shape so the client can
classify them — an `everywhere: true` call against a handler without
`signOutEverywhere` gets the 409 upgrade guidance rather than an opaque 400.
An empty `postLogoutRedirectUri` is treated as absent instead of being
forwarded to a validator that rejects it.
