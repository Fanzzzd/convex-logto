# Next.js App Router, session mode

The example that exercises the parts of session mode a single-page app cannot:
the **HttpOnly cookie transport** and **server-side rendering** with a real
identity.

Compared with [`examples/nextjs`](../nextjs), which is bridge mode, nothing about
Logto is in the bundle here: no SDK, no endpoint, no app id. The Convex
deployment holds the refresh token, and the browser holds a cookie it cannot
read.

## What it demonstrates

| | |
|---|---|
| `app/api/logto/[route]/route.ts` | The five-line catch-all mount. App Router handlers are standard `Request`/`Response`, so the handler needs no adapter. |
| `server/logto-cookie.ts` | One handler configuration shared by the route and the middleware, with `idTokenCookie: true`. |
| `app/page.tsx` | `readLogtoIdTokenCookie` + `preloadQuery`; the server renders the real identity instead of a spinner. |
| `proxy.ts` | Where `getInitialToken()` belongs, because a proxy can set cookies; gated to document requests. |
| `app/dashboard.tsx` | Device list, live revocation, organization permissions, and the live Logto profile. |

## The one rule worth reading before you copy this

**Never call `getInitialToken()` from a layout or a page.** It rotates the
session cookie, and a Server Component cannot set cookies; Next.js allows that
only in Route Handlers, Server Actions, and the proxy. The rotated cookie would
be dropped, the browser would keep presenting a superseded token, and once it
fell outside the reuse window the component would read it as theft and kill the
session.

Read `readLogtoIdTokenCookie` in a page; call `getInitialToken()` in the proxy.
This example does exactly that, and `proxy.ts` says why inline.

Two consequences worth understanding before you copy the wiring:

- **Rotate once per document request.** Every `getInitialToken()` call is a real
  Logto round trip that rotates the session token. A matcher that also catches
  `/favicon.ico`, images and RSC prefetches fires several for one page view, and
  whichever `Set-Cookie` the browser keeps last may be an older generation than
  the server's, which the next client refresh presents outside its reuse window
  and the component correctly reads as theft. `proxy.ts` gates on
  `Sec-Fetch-Dest: document`.
- **The provider gets no SSR seed here.** It takes `initialToken` and
  `initialSessionId` as a pair, and the session id comes only from
  `getInitialToken()`, which cannot run in a render. So the server renders the
  identity itself (`app/page.tsx`) and the client establishes its own auth on
  mount; the first paint is authenticated, and the client catches up a moment
  later without the page changing shape.

## Setup

You need a **Traditional Web** application in Logto (not an SPA; session mode
uses a client secret), with `http://localhost:3000/callback` as a redirect URI
and `http://localhost:3000` as a post-sign-out redirect URI.

```bash
pnpm install
npx convex dev            # writes NEXT_PUBLIC_CONVEX_URL into .env.local

npx convex env set LOGTO_ENDPOINT      https://auth.example.com
npx convex env set LOGTO_APP_ID        your-traditional-web-app-id
npx convex env set LOGTO_CLIENT_SECRET your-traditional-web-app-secret

pnpm dev
```

To see the organization buttons do anything, ask for the organization scopes on
the Convex side; they are server-configured, because the browser cannot request
its own:

```ts title="convex/auth.ts"
import { ORGANIZATIONS_SCOPE, ORGANIZATION_ROLES_SCOPE, logtoSessionApi } from "convex-logto";

export const { /* ...the eleven exports... */ } = logtoSessionApi(
  components.logto,
  { scopes: [ORGANIZATIONS_SCOPE, ORGANIZATION_ROLES_SCOPE] },
);
```

**Sign out and back in afterwards.** Scopes are fixed at authorization time and
a grant cannot be widened in place, so an existing session's ID token keeps its
old claims and the buttons stay disabled until a new sign-in.

## Going to production

- `APP_ORIGIN` must be your real origin, and it is deliberately *not* a
  `NEXT_PUBLIC_` name: Next inlines those at build time, so a public one set in
  the production environment would be ignored in favour of the build machine's
  and every request to the handler would be answered `403`. `allowedOrigins`
  takes exact origins and rejects wildcards.
- The cookies are `__Host-` prefixed and `Secure`, so everything except
  `localhost` needs HTTPS.
- A cookie rides on **every** same-origin request, so the ID token reaches
  access logs and proxies that an `Authorization` header would not. That is the
  trade-off `idTokenCookie` exists to let you make deliberately; see
  [ADR 0002](../../docs/adr/0002-token-custody.md).

Full walkthrough: [Session mode](https://convex-logto-docs.vercel.app/docs/session-mode)
and [Next.js](https://convex-logto-docs.vercel.app/docs/nextjs).
