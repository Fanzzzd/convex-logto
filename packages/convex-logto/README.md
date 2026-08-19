# convex-logto

[![npm](https://img.shields.io/npm/v/convex-logto.svg)](https://www.npmjs.com/package/convex-logto)
[![CI](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/convex-logto.svg)](./LICENSE)

Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for a [Convex](https://convex.dev) React app — with the least setup possible.

- **One provider on the frontend.** `<ConvexLogtoProvider>` wires Logto + Convex + the sign-in callback. No hand-rolled `useAuth` bridge.
- **One line on the backend.** `logtoAuthConfig()` reads your env. No JWT template, no algorithm, no JWKS URL to copy.
- **One source of truth across environments.** The frontend can pull its Logto config from the backend, so you configure Logto in exactly one place per environment — the Convex deployment.

It uses Logto's **ID token** over OIDC, so Convex auto-discovers the signing key and JWKS — no JWT template, no algorithm, no JWKS URL to configure. (One Logto-side requirement: the OIDC signing key must be RSA/RS256 — see [step 1](#1-create-a-logto-app).)

Two modes share the same backend identity model:

- **Bridge mode** (the default, shown below): Logto's SPA SDK signs in the browser; the package bridges its ID token into Convex. Zero server-side state.
- **[Session mode](#session-mode)**: a Convex component holds the Logto refresh token server-side and rotates an application session token with the browser — smallest browser attack surface, live session revocation, and no Logto SDK in the bundle.

Whichever mode you choose, apply the [SPA security baseline][security-baseline-docs] to the scripts and dependencies that share its browser origin.

## Install

```bash
pnpm add convex-logto @logto/react
```

`convex` and `react` are peers you already have. For **React Native / Expo**, install
`@logto/rn` in place of `@logto/react` — everything else is the same (see
[React Native / Expo](#react-native--expo)). **[Session mode](#session-mode)** needs
no Logto package at all — `pnpm add convex-logto` is the whole install.

## Quick start

The snippets below use **Vite**. For the exact env var, provider placement, and
callback wiring for each framework — Vite, TanStack Router, TanStack Start, and
Next.js — see the [Next.js note](#nextjs-note) and the runnable
[examples](https://github.com/Fanzzzd/convex-logto/tree/main/examples).

### 1. Create a Logto app

In Logto Console → **Applications** → **Create application** → under **Single page app** pick your framework (e.g. **React**) — **not** a **Third-party app**. A third-party app is for letting *other people's* apps sign in through your Logto; it withholds the `profile` / `email` scopes this package requests, so sign-in fails with `invalid_scope`. The app type can't be changed after creation.

Note the **endpoint** (e.g. `https://auth.example.com`) and the **App ID**, and add two URLs on the app (for each environment):

- **Redirect URIs** → `http://localhost:5173/callback` (and your prod callback)
- **Post sign-out redirect URIs** → `http://localhost:5173` (your app's origin, and your prod origin)

`signIn()` returns to the redirect URI and `signOut()` to the post-sign-out URI, so remember to add both.

**Required — use an RSA signing key.** Convex only accepts ID tokens signed with **RS256** (or EdDSA); Logto signs with **ES384** by default, which Convex silently rejects (sign-in looks fine, but `ctx.auth.getUserIdentity()` returns `null`). Rotate it once per tenant: in the Logto Console, open **Tenant settings → OIDC configs**, click **Rotate private keys**, and choose **RSA** as the signing algorithm. Logto keeps the old key during a transition, so existing sessions stay signed in.

### 2. Set the config

On your Convex deployment (used by `auth.config.ts` to validate tokens):

```bash
npx convex env set LOGTO_ENDPOINT https://auth.example.com
npx convex env set LOGTO_APP_ID   your-app-id
```

And in your frontend env (`.env.local`) — both are **public** OAuth values (the app id is a client id, not a secret), safe in the bundle:

```bash
VITE_LOGTO_ENDPOINT=https://auth.example.com
VITE_LOGTO_APP_ID=your-app-id
```

The endpoint may include a reverse-proxy path prefix, but it must be the Logto
base URL (not the `/oidc` issuer URL) and may not contain credentials, a query,
or a fragment. HTTPS is required except for loopback development. An existing
HTTP-only, non-loopback self-hosted deployment can explicitly opt in with
`allowInsecureHttp: true` on `logtoAuthConfig`, the frontend `config` (or
`logtoConfigQuery`), and `logtoSessionApi` where applicable; terminating TLS is
strongly preferred.

### 3. Wire Convex

```ts
// convex/auth.config.ts
import { logtoAuthConfig } from "convex-logto";
export default { providers: [logtoAuthConfig()] };
```

### 4. Wrap your app

```tsx
// src/main.tsx
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider } from "convex-logto/react";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL);

root.render(
  <ConvexLogtoProvider
    client={convex}
    config={{
      endpoint: import.meta.env.VITE_LOGTO_ENDPOINT,
      appId: import.meta.env.VITE_LOGTO_APP_ID,
    }}
  >
    <App />
  </ConvexLogtoProvider>,
);
```

Prefer runtime-resolved config (multi-tenant, one artifact for many environments)? Export `logtoConfigQuery()` from a Convex file and pass `configQuery={api.logto.config}` instead of `config` — the frontend then carries no Logto values at all.

### 5. Add a callback route

The provider finishes the OIDC code exchange automatically — the route just needs to render. With TanStack Router:

```tsx
// src/routes/callback.tsx
import { createFileRoute } from "@tanstack/react-router";
export const Route = createFileRoute("/callback")({ component: () => null });
```

### 6. Sign in, and read the user

```tsx
import { useLogtoAuth } from "convex-logto/react";

function Header() {
  const { isAuthenticated, isLoading, user, signIn, signOut } = useLogtoAuth();
  if (isLoading) return null;
  return isAuthenticated ? (
    <button onClick={() => void signOut()}>Sign out ({user?.email ?? user?.sub})</button>
  ) : (
    <button onClick={() => void signIn()}>Sign in</button>
  );
}
```

The `void signIn()` handler is safe: initiation failures are logged and routed
to the provider's `onAuthError`, even when the underlying Logto SDK catches the
rejection into its own error state.

In any Convex function, the Logto identity is already there:

```ts title="convex/me.ts"
import { query } from "./_generated/server";

export const me = query({
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;
    // identity.subject = Logto user id, plus email/name/etc. from the ID token
    return { id: identity.subject, email: identity.email, name: identity.name };
  },
});
```

That is the whole auth setup. Many apps need nothing more.

## Multiple environments

When you use the runtime `configQuery` mode described above, **the only thing
that varies per environment is the Convex deployment the frontend points at**
(which you already set via `VITE_CONVEX_URL`). In that mode the frontend has no
Logto env vars to manage. With the default static `config`, keep the two public
Logto values in each frontend environment as shown in the quick start.

Create one Logto app per environment (dev / staging / prod — best practice, so tokens can't cross environments), then set each deployment's env once:

```bash
# dev deployment
npx convex env set LOGTO_ENDPOINT https://your-logto.example.com
npx convex env set LOGTO_APP_ID   <dev-app-id>
# production deployment
npx convex env set --prod LOGTO_ENDPOINT https://your-logto.example.com
npx convex env set --prod LOGTO_APP_ID   <prod-app-id>
# staging: target that deployment the same way
```

With `configQuery`, the same frontend artifact works everywhere: only the
deployment selected by `VITE_CONVEX_URL` changes, and each deployment serves its
own public Logto configuration.

## Session mode

Keep the Logto refresh token out of the browser entirely: a Convex component
becomes the OAuth client (a Logto **Traditional web** app — client secret stays
on the server), and the browser holds only a short-lived ID token plus a
**rotating session token** issued in generations (the server stores only hashes;
the current generation and a bounded set of recently superseded generations may
be accepted during the reuse window). Presenting a superseded token after that
window triggers reuse containment. Session liveness is a Convex subscription, so
sign-out elsewhere, token-theft detection, or a webhook suspension drops auth
**live**, not at token expiry. Works on any static host — no cookie domain, no
server for the frontend, no `@logto/react`.

```ts
// convex/convex.config.ts — install the component
import { defineApp } from "convex/server";
import logto from "convex-logto/convex.config";

const app = defineApp();
app.use(logto);
export default app;
```

```ts
// convex/auth.ts — the whole server surface
import { logtoSessionApi } from "convex-logto";
import { components } from "./_generated/api";

export const {
  signIn,
  callback,
  refresh,
  signOut,
  signOutEverywhere,
  listSessions,
  renameSession,
  revokeSession,
  sessionValid,
} = logtoSessionApi(components.logto);
```

```tsx
// src/main.tsx — no Logto SDK, no Logto config in the bundle
import { ConvexLogtoSessionProvider } from "convex-logto/react-session";
import { api } from "../convex/_generated/api";

root.render(
  <ConvexLogtoSessionProvider client={convex} sessionApi={api.auth}>
    <App />
  </ConvexLogtoSessionProvider>,
);
```

Config lives on the deployment (`LOGTO_ENDPOINT`, `LOGTO_APP_ID`,
`LOGTO_CLIENT_SECRET`); `useLogtoAuth()` from `convex-logto/react-session` has
the bridge actions plus `signOutEverywhere()` and the session list
(`listSessions()` / `renameSession()` / `revokeSession()`). Full guide — threat model, token
dance, subject-level revocation enforcement with
`assertSubjectHasActiveSession` — in the
[Session mode docs][session-mode-docs] and the runnable
[`vite-react-session`][session-example] example.

`signOutEverywhere()` derives the caller subject from its rotating session token
and atomically records subject-wide logical revocation. `sessionValid` rejects
the affected sessions immediately; physical rows are then removed in bounded
batches. Other devices drop through reactive revocation, while their separate
Logto browser cookies cannot be erased by the RP and can be used to start a new
sign-in. The returned `count` is the number of physical session rows removed by
the completed cleanup, not the moment at which revocation became effective.

`listSessions()` returns the caller's own sessions for a "where am I signed in"
screen — `{ sessionId, current, createdAt, lastRefreshedAt, label?, client?,
deviceBound }`, newest first — with `renameSession()` and `revokeSession()` for
naming a device or signing one out. The subject always comes from the presented
token, so another user's `sessionId` resolves to `session_not_found`. The optional
`clientDescriptor` provider prop supplies the advisory device description; the
library never reads a User-Agent or IP.

`revokeSession()` is an RP-level boundary, like `signOutEverywhere()`: it deletes
that session and its server-held refresh token, but it cannot erase the Logto SSO
cookie in the other device's browser. A device that still holds one can start a
new sign-in and may be authenticated without another credential prompt — revoke a
genuinely lost device in Logto itself (or suspend the user) as well.

Apps with a same-site server endpoint can additionally mount
`createLogtoSessionCookieHandler()` and pass
`cookieTransport={{ endpoint: "/api/logto" }}` to the provider. That moves the
rotating credential into a persistent rolling `__Host-` HttpOnly cookie whose
190-day lifetime matches server-side idle GC. It enforces fixed POST +
custom-header + Origin CSRF checks and supports SSR seeding through
`handler.getInitialToken(request)`. See the session-mode guide for Next.js,
TanStack Start, and Convex custom-domain mounts, plus the cookie/device-binding
exclusion.

Alternatively, opt into `deviceBinding` on the provider to require an ECDSA
proof from a non-extractable IndexedDB-held key whenever the rotating token is
used for refresh or revocation. A copied session token alone cannot refresh or
force sign-out from another device. Device binding is intentionally off by
default, fails loudly without IndexedDB, and cannot be combined with cookie
transport; key eviction causes a clean re-authentication. See the session-mode
guide for the exact threat model and the cross-browser DBSC re-evaluation
trigger.

For Expo, import `ConvexLogtoSessionProvider` from
`convex-logto/native-session` and install `expo-secure-store` plus
`expo-web-browser`. It reuses the same component and session actions, completes
sign-in through the system browser/deep link (no callback route), keeps the
rotating session token and short-lived ID token in the OS keystore, and retains
reactive revocation. Native intentionally has no cookie-transport or software
`deviceBinding` option.

Register `registerLogtoBackchannelLogout(http, { sessions: components.logto })`
to verify Logto OIDC Logout Tokens and propagate IdP-side sign-out through the
same reactive revocation path (every component Session mapped to the Logout
Token's `sid`, or subject-wide revocation for `sub` when `sid` is absent).

[session-mode-docs]: https://github.com/Fanzzzd/convex-logto/blob/main/docs/content/docs/session-mode.mdx
[session-example]: https://github.com/Fanzzzd/convex-logto/tree/main/examples/vite-react-session
[security-baseline-docs]: https://github.com/Fanzzzd/convex-logto/blob/main/docs/content/docs/security-baseline.mdx

## Optional: sync Logto users into a table

You don't need a table to authenticate — identity comes from the token, so attach
your data to your own tables keyed by `identity.subject`. Add a `users` table only
when you need to query users (an admin list, another user's name) or store fields
the token doesn't carry (a per-app **role**). The table is **yours**; the package
just provides the webhook glue.

```ts
// convex/schema.ts — fields grouped by who owns them
users: defineTable({
  authId: v.string(), // == identity.subject
  email: v.optional(v.string()), // Logto-owned (synced)
  name: v.optional(v.string()), // Logto-owned (synced)
  role: v.union(v.literal("user"), v.literal("admin")), // app-owned (RBAC)
  status: v.union(v.literal("active"), v.literal("suspended"), v.literal("deleted")),
}).index("by_authId", ["authId"]),
```

Three rules keep it correct:

- **The webhook writes only Logto-owned fields (`email`, `name`, `status`), never
  `role`** — otherwise a Logto profile edit would reset everyone's role.
- **The webhook never creates rows — it only syncs existing ones.** `User.Created`
  doesn't fire for users who already existed in Logto, so create rows from an
  authenticated mutation on first load (get-or-create) and let the webhook keep them
  in sync. (Webhook-only creation is the bug that bites component-owned auth tables.)
- **Soft-delete on `User.Deleted`** — scrub PII but keep a tombstone row, so authz
  fails closed and nothing referencing the user by id dangles.

Full walkthrough — `logtoSync` handlers, `registerLogtoWebhook`, signing-key setup,
and `requireRole` authz — in the [Webhook sync guide][webhook-sync] and the runnable
[`tanstack-router-spa`][spa-example] example.

[webhook-sync]: https://github.com/Fanzzzd/convex-logto/blob/main/docs/content/docs/webhook-sync.mdx
[spa-example]: https://github.com/Fanzzzd/convex-logto/tree/main/examples/tanstack-router-spa

## Why the ID token (and why there's no JWT config)

Convex validates an OIDC **ID token**. Logto's access tokens are typed `at+jwt`, which Convex does not accept ([convex#75](https://github.com/get-convex/convex-backend/issues/75)), so this package returns the ID token. Because it goes through Convex's **OIDC** provider (not Custom JWT), Convex reads the issuer's discovery document and JWKS itself, so you never set an algorithm or a JWKS URL — with one catch: Convex's OIDC verifier accepts only **RS256**/**EdDSA**, while Logto signs with **ES384** by default, so you rotate the Logto OIDC signing key to **RSA** once (step 1). A mismatch is rejected silently (`getUserIdentity()` returns `null`). Sessions refresh via Logto's refresh token, which is why `ConvexLogtoProvider` requests the `offline_access` scope by default.

## API

| Export | From | Purpose |
| --- | --- | --- |
| `logtoAuthConfig(opts?)` | `convex-logto` | Provider entry for `auth.config.ts`. Reads `LOGTO_ENDPOINT` / `LOGTO_APP_ID`. |
| `logtoConfigQuery(opts?)` | `convex-logto` | Public query serving `{ endpoint, appId, allowInsecureHttp? }` to the frontend. |
| `logtoSync<DataModel>(handlers)` | `convex-logto` | Returns `{ sync }`, an internal mutation mapping user events to your tables. |
| `registerLogtoWebhook(http, sync, opts?)` | `convex-logto` | Registers the verified webhook route. Reads `LOGTO_WEBHOOK_SIGNING_KEY`; `sessions` option adds dedupe + session revocation. |
| `registerLogtoBackchannelLogout(http, opts)` | `convex-logto` | Session mode: registers a verified OIDC back-channel logout route with `sid` / `sub` revocation. |
| `createLogtoBackchannelLogoutHandler(opts)` | `convex-logto` | Builds the back-channel Convex HTTP action for custom route composition. |
| `verifyLogtoLogoutToken(token, opts?)` | `convex-logto` | Low-level RS256/PS256 Logout Token verification against Logto's JWKS. |
| `verifyLogtoSignature(key, body, sig)` | `convex-logto` | Low-level signature check, for custom routing. |
| `logtoSessionApi(component, opts?)` | `convex-logto` | [Session mode](#session-mode): builds the nine public auth functions backed by the session component. |
| `assertSubjectHasActiveSession(ctx, component)` | `convex-logto` | Session mode: throw unless the authenticated subject has at least one active component Session; this does not bind the current bearer to one Session. A bounded scan can transiently throw `session_liveness_scan_incomplete` while bulk cleanup progresses. |
| `assertUserHasActiveSession(ctx, component)` | `convex-logto` | Deprecated compatibility alias for `assertSubjectHasActiveSession`. |
| `createLogtoSessionCookieHandler(opts)` | `convex-logto` | Five-route standard-fetch handler for the optional same-site HttpOnly cookie transport. |
| `ConvexLogtoProvider` | `convex-logto/react` | Logto + Convex + auto sign-in callback in one provider. Static `config` or backend `configQuery`. |
| `useLogtoAuth()` | `convex-logto/react` | `{ isAuthenticated, isLoading, user, signIn, signOut }`. |
| default | `convex-logto/convex.config` | The session component, for `app.use(logto)`. |
| `ConvexLogtoSessionProvider` | `convex-logto/react-session` | Session mode's provider — no Logto SDK; talks to your `logtoSessionApi` functions. |
| `useLogtoAuth()` | `convex-logto/react-session` | Session auth actions, including `signOutEverywhere({ postLogoutRedirectUri? })` and `listSessions()` / `renameSession()` / `revokeSession()`. |
| `ConvexLogtoProvider` | `convex-logto/native` | React Native / Expo provider (on `@logto/rn`). Same `configQuery` model; no callback route. |
| `useLogtoAuth()` | `convex-logto/native` | Native `{ isAuthenticated, isLoading, user, signIn, signOut }`; `signIn()` defaults to the provider's `redirectUri`. |
| `ConvexLogtoSessionProvider` | `convex-logto/native-session` | Expo session mode via SecureStore + system-browser deep links; same server component and actions. |
| `useLogtoAuth()` | `convex-logto/native-session` | Native session auth/actions, including federated `signOutEverywhere(opts?)` and the same session list. |

### Next.js note

`ConvexLogtoProvider` and `useLogtoAuth` use React hooks (and `window` for sign-in / sign-out), so in the Next.js App Router render them from a `"use client"` component — the provider is SSR-safe within that boundary.

### React Native / Expo

For Expo bridge mode, import from **`convex-logto/native`** (built on [`@logto/rn`](https://github.com/logto-io/react-native)) instead of `convex-logto/react`. For server-held session mode, use **`convex-logto/native-session`** with `expo-secure-store` and `expo-web-browser`. Neither native entry needs a callback route — `signIn` opens the system browser and resolves on the deep-link return. See the [React Native guide](https://github.com/Fanzzzd/convex-logto/blob/main/docs/content/docs/react-native.mdx) and the two runnable apps: bridge-mode [`examples/expo`](https://github.com/Fanzzzd/convex-logto/tree/main/examples/expo) and session-mode [`examples/expo-session`](https://github.com/Fanzzzd/convex-logto/tree/main/examples/expo-session).

## License

MIT
