---
"convex-logto": patch
---

Expire the SSR ID token cookie on every exit that expires the session cookie.

`idTokenCookie: true` writes the ID token to `__Host-convex-logto-id-token`, and
sign-out cleared it — but only on the success path. Three exits cleared the
session cookie and left the ID token behind: a sign-out the deployment could not
complete, a sign-out whose body never parsed, and a terminal `/token` refresh,
which is what a revoked, reused or deleted session looks like.

Neither cookie is reachable from JavaScript, so nothing on the client could
finish the job. The browser went on handing a signed-in identity to every server
render until the token's own `Max-Age` ran out — up to its full lifetime, and on
a shared computer that is the previous user's identity rendered into the next
visitor's HTML. Both cookies are now expired together, whatever the exit.

`readLogtoIdTokenCookie` also checks `exp` itself now. The cookie's `Max-Age`
already comes from the token's `exp`, but that is the browser's guarantee, and a
`Cookie` header replayed from a cache or a proxy does not arrive behind one.
