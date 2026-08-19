---
"convex-logto": patch
---

Native: a failed token refresh no longer wedges the app.

Convex stops asking for a token after one `null`, and re-arms only when the `isAuthenticated` the bridge reports goes false→true. `@logto/rn` latches its own flag true and never moves it, so one failed refresh — an expired refresh token, a tunnel hiccup on resume — disarmed Convex for the life of the process, and tapping Sign in changed nothing the provider was watching. The bridge now folds the token failure into what it reports, and clears it once `signIn()` resolves (after, never before: clearing on the way in would re-arm Convex against tokens that are still broken) or when the SDK genuinely goes unauthenticated and back.

Native session storage got two fixes as well. One unreadable SecureStore key no longer fails the whole store — a locked device, or an entry written under a stricter keychain accessibility class, fails only its own read, so it is treated as absent for now and left in place rather than costing the user their session. And a credential delete SecureStore refused is now reported until a later delete actually lands, instead of being consumed by the first `flush()` that saw it: the credential is still on the device, so sign-out has not happened.
