# Next.js App Router — session mode

The example that exercises the parts of session mode a single-page app cannot:
the **HttpOnly cookie transport** and **server-side rendering** with a real
identity.

Compared with [`examples/nextjs`](../nextjs), which is bridge mode, nothing about
Logto is in the bundle here — no SDK, no endpoint, no app id. The Convex
deployment holds the refresh token, and the browser holds a cookie it cannot
read.

## What it demonstrates

| | |
|---|---|
| `app/api/logto/[route]/route.ts` | The five-line catch-all mount. App Router handlers are standard `Request`/`Response`, so the handler needs no adapter. |
| `server/logto-cookie.ts` | One handler configuration shared by the route and the middleware, with `idTokenCookie: true`. |
| `app/layout.tsx` | A Server Component reading the ID token cookie and seeding the provider, so the first client render agrees with the server's. |
| `app/page.tsx` | `preloadQuery` with that token — authenticated HTML, no loading flash. |
| `middleware.ts` | Where `getInitialToken()` belongs, because middleware can set cookies. |
| `app/dashboard.tsx` | Device list, live revocation, organization permissions, and the live Logto profile. |

## The one rule worth reading before you copy this

**Never call `getInitialToken()` from a layout or a page.** It rotates the
session cookie, and a Server Component cannot set cookies — Next.js allows that
only in Route Handlers, Server Actions, and middleware. The rotated cookie would
be dropped, the browser would keep presenting a superseded token, and once it
fell outside the reuse window the component would read it as theft and kill the
session.

Read `readLogtoIdTokenCookie` in a page; call `getInitialToken()` in middleware.
This example does exactly that, and `middleware.ts` says why inline.

## Setup

You need a **Traditional Web** application in Logto (not an SPA — session mode
uses a client secret), with `http://localhost:3000/callback` as a redirect URI
and `http://localhost:3000` as a post sign-out redirect URI.

```bash
pnpm install
npx convex dev            # writes NEXT_PUBLIC_CONVEX_URL into .env.local

npx convex env set LOGTO_ENDPOINT      https://auth.example.com
npx convex env set LOGTO_APP_ID        your-traditional-web-app-id
npx convex env set LOGTO_CLIENT_SECRET your-traditional-web-app-secret

pnpm dev
```

To see organization permissions do anything, add the organization scopes on the
Convex side — they are server-configured, because the browser cannot request its
own:

```ts title="convex/auth.ts"
logtoSessionApi(components.logto, {
  scopes: [ORGANIZATIONS_SCOPE, ORGANIZATION_ROLES_SCOPE],
});
```

## Going to production

- `NEXT_PUBLIC_APP_ORIGIN` must be your real origin. `allowedOrigins` takes
  exact origins and rejects wildcards.
- The cookies are `__Host-` prefixed and `Secure`, so everything except
  `localhost` needs HTTPS.
- A cookie rides on **every** same-origin request, so the ID token reaches
  access logs and proxies that an `Authorization` header would not. That is the
  trade-off `idTokenCookie` exists to let you make deliberately — see
  [ADR 0002](../../docs/adr/0002-token-custody.md).

Full walkthrough: [Session mode](https://convex-logto-docs.vercel.app/docs/session-mode)
and [Next.js](https://convex-logto-docs.vercel.app/docs/nextjs).
