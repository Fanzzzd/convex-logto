# convex-logto

[![npm](https://img.shields.io/npm/v/convex-logto.svg)](https://www.npmjs.com/package/convex-logto)
[![CI](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/convex-logto.svg)](./LICENSE)

Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for a [Convex](https://convex.dev) React app — with the least setup possible.

- **One provider on the frontend.** `<ConvexLogtoProvider>` wires Logto + Convex + the sign-in callback. No hand-rolled `useAuth` bridge.
- **One line on the backend.** `logtoAuthConfig()` reads your env. No JWT template, no algorithm, no JWKS URL to copy.
- **One source of truth across environments.** The frontend can pull its Logto config from the backend, so you configure Logto in exactly one place per environment — the Convex deployment.

It uses Logto's **ID token** over OIDC, so Convex auto-discovers the signing key and JWKS — no JWT template, no algorithm, no JWKS URL to configure. (One Logto-side requirement: the OIDC signing key must be RSA/RS256 — see [step 1](#1-create-a-logto-app).)

## Install

```bash
pnpm add convex-logto @logto/react
```

`convex` and `react` are peers you already have. For **React Native / Expo**, install
`@logto/rn` in place of `@logto/react` — everything else is the same (see
[React Native / Expo](#react-native--expo)).

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

### 2. Set the config on your Convex deployment (only place needed)

```bash
npx convex env set LOGTO_ENDPOINT https://auth.example.com
npx convex env set LOGTO_APP_ID   your-app-id
```

These are public OAuth values, but keeping them as deployment env vars means each environment (dev / staging / prod) carries its own — see [Multiple environments](#multiple-environments).

### 3. Wire Convex

```ts
// convex/auth.config.ts
import { logtoAuthConfig } from "convex-logto";
export default { providers: [logtoAuthConfig()] };
```

```ts
// convex/logto.ts  — serves the public { endpoint, appId } to the frontend
import { logtoConfigQuery } from "convex-logto";
export const config = logtoConfigQuery();
```

### 4. Wrap your app

The frontend carries **no Logto config** — it asks the backend:

```tsx
// src/main.tsx
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider } from "convex-logto/react";
import { api } from "../convex/_generated/api";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL);

root.render(
  <ConvexLogtoProvider client={convex} configQuery={api.logto.config}>
    <App />
  </ConvexLogtoProvider>,
);
```

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

In any Convex function, the Logto identity is already there:

```ts
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

Because the frontend pulls config from the backend, **the only thing that varies per environment is the Convex deployment it points at** (which you already set via `VITE_CONVEX_URL`). The frontend has no Logto env vars to manage.

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

Same code everywhere. The only thing that changes per environment is which Convex deployment `VITE_CONVEX_URL` points at — there's no Logto config to duplicate or keep in sync.

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
| `logtoConfigQuery()` | `convex-logto` | Public query serving `{ endpoint, appId }` to the frontend. |
| `logtoSync<DataModel>(handlers)` | `convex-logto` | Returns `{ sync }`, an internal mutation mapping user events to your tables. |
| `registerLogtoWebhook(http, sync, opts?)` | `convex-logto` | Registers the verified webhook route. Reads `LOGTO_WEBHOOK_SIGNING_KEY`. |
| `verifyLogtoSignature(key, body, sig)` | `convex-logto` | Low-level signature check, for custom routing. |
| `ConvexLogtoProvider` | `convex-logto/react` | Logto + Convex + auto sign-in callback in one provider. Pulls Logto config from the backend via `configQuery`. |
| `useLogtoAuth()` | `convex-logto/react` | `{ isAuthenticated, isLoading, user, signIn, signOut }`. |
| `ConvexLogtoProvider` | `convex-logto/native` | React Native / Expo provider (on `@logto/rn`). Same `configQuery` model; no callback route. |
| `useLogtoAuth()` | `convex-logto/native` | Native `{ isAuthenticated, isLoading, user, signIn, signOut }`; `signIn()` defaults to the provider's `redirectUri`. |

### Next.js note

`ConvexLogtoProvider` and `useLogtoAuth` use React hooks (and `window` for sign-in / sign-out), so in the Next.js App Router render them from a `"use client"` component — the provider is SSR-safe within that boundary.

### React Native / Expo

For Expo, import from **`convex-logto/native`** (built on [`@logto/rn`](https://github.com/logto-io/react-native)) instead of `convex-logto/react`. The backend (`logtoAuthConfig` / `logtoConfigQuery`) is identical. There's no callback route on native — `signIn` opens the system browser and resolves on the deep-link return. See the [React Native guide](https://github.com/Fanzzzd/convex-logto/blob/main/docs/content/docs/react-native.mdx) and the runnable [`examples/expo`](https://github.com/Fanzzzd/convex-logto/tree/main/examples/expo) app.

## License

MIT
