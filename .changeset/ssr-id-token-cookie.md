---
"convex-logto": minor
---

Server-side rendering with session mode, in any framework.

`getInitialToken()` rotates the session cookie, and a framework that forbids writing cookies during render — the Next.js App Router's Server Components, notably — cannot persist that rotation. Dropping it leaves the browser holding a superseded token that later reads as reuse and kills the session, so the documented advice has been "do not seed SSR there", which in practice means no server-side identity at all.

`idTokenCookie: true` on `createLogtoSessionCookieHandler` makes the route handler also write the ID token to an `HttpOnly` `__Host-convex-logto-id-token` cookie, with `Max-Age` taken from the token's own `exp`. Read it with `readLogtoIdTokenCookie(source)`, which accepts a `Request`, a raw `Cookie` header, or a store shaped like Next's `cookies()` — so there is no framework entry point to keep in step:

```tsx
const token = readLogtoIdTokenCookie(await cookies());
const preloaded = await preloadQuery(api.me.me, {}, token ? { token } : {});
```

Nothing is minted and nothing is rotated, so the session token's reuse detection is untouched. It is opt-in because the trade-off is custody: a cookie rides on every same-origin request, reaching access logs and proxies an `Authorization` header does not. A token read this way is a bearer Convex validates, not a claim to trust — revocation is enforced by `assertSubjectHasActiveSession` inside the function you call, exactly as it is everywhere else.

An ID token that is expired, malformed, or too large for a cookie is skipped rather than cleared, so a size problem cannot become a sign-out; sign-out clears the cookie unconditionally, even when the option is off, so turning it off never strands a live token.
