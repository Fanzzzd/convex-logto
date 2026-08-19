---
"convex-logto": minor
---

Surface sign-out failures instead of swallowing them, on web and native.

A failed sign-out is not cosmetic: `@logto/client` reaches OIDC discovery
**before** it clears tokens, so an unreachable Logto leaves the user signed in
with a live ID token while the button looks like it worked.

On the web, `@logto/react` caught that failure into its own state and resolved
the promise, and the bridge only registered sign-*in* attempts — so nothing
reported it and `onAuthError` never fired. Sign-out now registers an attempt the
same way, so the swallowed error is reported once, and a direct rejection is
reported and rethrown.

The native bridge had no error surface at all: `@logto/rn` rejects rather than
storing the error, and the documented pattern is `void signIn()` in an
`onPress`, so a dismissed system browser or an offline sign-out became an
unhandled rejection and *nothing else*. The native `<ConvexLogtoProvider>` now
takes `onAuthError`, matching the web provider and native session mode, and both
`signIn()` and `signOut()` report through it before rejecting. Reporting is not
handling: a promise that rejects still does, so a fire-and-forget caller wants
`.catch(() => {})` alongside `onAuthError` — the docs now say so instead of
calling `void signIn()` safe.
