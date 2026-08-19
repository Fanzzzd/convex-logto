---
"convex-logto": patch
---

Fix three bridge-mode defects that all trace to reading `window.location` during
render.

**A callback that resolved without authenticating could pin Convex at
`isLoading` forever.** The loading veto was derived from the URL, which is not a
reactive source, and it has absolute priority over the settle latch. In the
layout every SPA example ships — provider mounted above the router — the soft
navigation out of `/callback` re-renders only the router subtree, so the veto
stayed frozen at "still on /callback" for the rest of the page session. A spent
or replayed code, a lost sign-in session, a state mismatch, or the documented
10-second stale-callback timeout would leave the app showing a loading state
with no Sign in button, recoverable only by reloading. The callback flow is now
provider state that ends when the callback resolves, whatever the outcome.

**The sign-in error observer never mounted for a page session that began on the
callback route.** Same frozen read, so a later sign-in whose failure
`@logto/react` swallows into its own state — the case `onAuthError` exists for —
went unreported and the button appeared to do nothing.

**A cancelled sign-in could lose its `returnTo`.** The benign/error branch had no
idempotence guard, so React's StrictMode double-invoke (every shipped example
wraps the provider in it) ran it twice: the first pass consumed the destructive
`returnTo` stash and navigated correctly, the second found it empty and
redirected to `afterSignIn` instead. A setup error was reported twice for the
same reason.
