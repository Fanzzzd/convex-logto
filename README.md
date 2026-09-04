# convex-logto

[![npm](https://img.shields.io/npm/v/convex-logto.svg)](https://www.npmjs.com/package/convex-logto)
[![CI](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/convex-logto.svg)](./LICENSE)

Use [Logto](https://logto.io), self-hosted or cloud, as the auth provider for a
[Convex](https://convex.dev) app. React, React Native and Expo, on the web and on
device.

```bash
npm i convex-logto
```

**[Documentation](https://convex-logto-docs.vercel.app)** · **[Quick
start](https://convex-logto-docs.vercel.app/docs/quick-start)** · **[Why this
package](https://convex-logto-docs.vercel.app/docs/why)** (including when to use
something else)

## What you get

- **One provider on the frontend.** `<ConvexLogtoSessionProvider>` signs in,
  finishes the callback, refreshes, and signs out. No Logto SDK in the bundle
  and no hand-rolled `useAuth` bridge.
- **One line on the backend.** `logtoAuthConfig()` reads your environment. No JWT
  template, no signing algorithm, no JWKS URL; it validates Logto's **ID token**
  over OIDC, so Convex discovers the key itself.
- **Every Logto value on the Convex deployment.** Endpoint, app id, and app
  secret live in `npx convex env`. The frontend build carries none of them, so
  one artifact serves every environment.
- **Revocation lands live.** Sign-out on another device, "sign out everywhere",
  a suspended user, or an admin ending the session drops the open tab at once.

## Two modes, one identity model

**[Session mode](https://convex-logto-docs.vercel.app/docs/session-mode)**, the
recommended path and the quick start. A Convex component holds the Logto
refresh token in tables your app code cannot read, and rotates a short-lived
application session token with the browser. Live revocation, a "where am I
signed in" device list, and nothing long-lived in browser storage, including on
a static CDN deploy, where no same-site HttpOnly cookie is reachable at all.
Optional same-site cookie transport and non-extractable device binding on top.

**[Bridge mode](https://convex-logto-docs.vercel.app/docs/bridge-mode).**
Logto's SDK (`@logto/react`) signs in from the browser and the package bridges
its ID token into Convex. Zero server-side state; the refresh token lives in
`localStorage`. Supported, for apps that want no server state or already run it.

Both present the same ID token to Convex, so identity, webhook sync and
environment handling are the same, and moving between them is a new Logto app
and a provider swap.

## Also included

- **[Webhook user sync](https://convex-logto-docs.vercel.app/docs/webhook-sync)**:
  signature-verified Logto events into a queryable Convex `users` table, and
  live session revocation for deleted or suspended users.
- **[Back-channel logout](https://convex-logto-docs.vercel.app/docs/backchannel-logout)**:
  the OIDC endpoint, JWKS-verified, bounded and deduplicated.
- **Organization authorization**: membership and organization roles read
  straight out of the ID token, so `assertOrganizationRole(ctx, orgId, "admin")`
  costs no extra round trip.

## Examples

Runnable apps, one per integration. Each is a full wiring you can copy.

| | |
|---|---|
| [Vite + React, session mode](examples/vite-react-session) | The quick start as an app: server-held refresh token, device list, live revocation |
| [Next.js App Router, session mode](examples/nextjs-session) | HttpOnly cookie transport, SSR with a real identity, document-only refresh in the proxy |
| [Expo, session mode](examples/expo-session) | SecureStore credentials, reclaimed-sign-in recovery |
| [Vite + React, bridge mode](examples/vite-react) | One provider, static config, declarative gating |
| [TanStack Router (SPA), bridge mode](examples/tanstack-router-spa) | Route guards in `beforeLoad`, webhook-synced users + RBAC |
| [TanStack Start (SSR), bridge mode](examples/tanstack-start) | One SSR-safe provider, `beforeLoad` guards |
| [Next.js App Router, bridge mode](examples/nextjs) | Client provider boundary + callback route |
| [Expo, bridge mode](examples/expo) | `convex-logto/native` on `@logto/rn`, deep-link sign-in, no callback route |

## Status

Pre-1.0. Breaking changes land in minor versions until 1.0; [issue
#35](https://github.com/Fanzzzd/convex-logto/issues/35) tracks what 1.0 means and
what is still missing.

## Repository

A pnpm + Turborepo monorepo.

- **[`packages/convex-logto`](packages/convex-logto)**: the published library
  (the only published package). Its [README](packages/convex-logto/README.md) is
  the full reference.
- **[`examples/`](examples)**: the apps in the table above.
- **[`docs/`](docs)**: the documentation site (Fumadocs).
- **[`CONTEXT.md`](CONTEXT.md)**: the vocabulary this codebase is written in.
- **[`docs/adr/`](docs/adr)**: the decisions that are hard to reverse, and why.

Contributor and agent guidance lives in [`AGENTS.md`](./AGENTS.md).

## License

[MIT](./LICENSE)
