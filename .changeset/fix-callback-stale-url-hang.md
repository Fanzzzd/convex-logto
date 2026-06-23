---
"convex-logto": patch
---

Fix the Logto sign-in callback hanging forever on a stale or already-authenticated `/callback` URL.

`ConvexLogtoProvider` decided "a code exchange is in progress, keep waiting" purely from the URL (`?code=&state=`), but `@logto/react` only runs the exchange when `!isAuthenticated && isSignInRedirected(url)`. Re-opening an already-consumed callback URL — by refresh, Back button, or a bookmark, most often while already signed in — left the page stuck on the loading state with no navigation, because the SDK's exchange callback never fires. The provider now resolves the callback from the SDK's observable auth state (with a timeout safety net for a lost sign-in session) instead of waiting for an exchange that will never happen (#14).
