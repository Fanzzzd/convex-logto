# convex-logto

[![npm](https://img.shields.io/npm/v/convex-logto.svg)](https://www.npmjs.com/package/convex-logto)
[![CI](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/convex-logto.svg)](./LICENSE)

Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for a [Convex](https://convex.dev) React app — with the least setup possible.

- **One provider on the frontend.** `<ConvexLogtoProvider>` wires Logto + Convex + the sign-in callback. No hand-rolled `useAuth` bridge.
- **One line on the backend.** `logtoAuthConfig()` reads your env. No JWT template, no algorithm, no JWKS URL to copy.
- **One source of truth across environments.** The frontend can pull its Logto config from the backend, so you configure Logto in exactly one place per environment — the Convex deployment.

It uses Logto's **ID token** over OIDC, so Convex auto-discovers the signing key and algorithm (Logto signs with ES384). There is nothing about JWTs for you to configure.

## Install

```bash
pnpm add convex-logto @logto/react
```

`convex` and `react` are peers you already have.

## Quick start

### 1. Create a Logto app

In Logto Console → **Applications** → create a **Single Page App**. Note the **endpoint** (e.g. `https://auth.example.com`) and the **App ID**. Under **Redirect URIs** add `http://localhost:5173/callback` (and your prod URL); under **Post sign-out redirect URIs** add your origin.

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
    <button onClick={() => signOut()}>Sign out ({user?.email})</button>
  ) : (
    <button onClick={() => signIn()}>Sign in</button>
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
npx convex env set LOGTO_APP_ID <dev-app-id>
# production deployment
npx convex env set --prod LOGTO_APP_ID <prod-app-id>
# staging: target that deployment the same way
```

Same code everywhere. Switching environments = pointing `VITE_CONVEX_URL` at a different deployment. Nothing to recompile, nothing to copy twice.

### Prefer literal values instead?

If you'd rather not add the config query, pass the values directly (e.g. from `import.meta.env`). Then the frontend needs its own `VITE_LOGTO_*` vars per environment:

```tsx
<ConvexLogtoProvider
  client={convex}
  endpoint={import.meta.env.VITE_LOGTO_ENDPOINT}
  appId={import.meta.env.VITE_LOGTO_APP_ID}
>
```

## Optional: sync Logto users into a table

If you want a queryable `users` table (to list users, store roles, or join app data), add a webhook sync. It mirrors `@convex-dev/workos-authkit`'s ergonomics.

### 1. Schema

```ts
// convex/schema.ts
users: defineTable({
  authId: v.string(),            // Logto user id (== identity.subject)
  email: v.string(),
  name: v.string(),
  role: v.string(),              // for RBAC, if you want it
}).index("authId", ["authId"]),
```

### 2. Map events to your table

```ts
// convex/logto.ts  (alongside `config` from above)
import { logtoSync } from "convex-logto";
import type { DataModel } from "./_generated/dataModel";

const upsert = async (ctx, u) => {
  const existing = await ctx.db
    .query("users")
    .withIndex("authId", (q) => q.eq("authId", u.id))
    .unique();
  const fields = { email: u.primaryEmail ?? "", name: u.name ?? "" };
  if (existing) await ctx.db.patch(existing._id, fields);
  else await ctx.db.insert("users", { authId: u.id, role: "user", ...fields });
};

export const { sync } = logtoSync<DataModel>({
  "User.Created": upsert,
  "User.Data.Updated": upsert,
  "User.Deleted": async (ctx, u) => {
    const row = await ctx.db
      .query("users")
      .withIndex("authId", (q) => q.eq("authId", u.id))
      .unique();
    if (row) await ctx.db.delete(row._id);
  },
});
```

### 3. Register the route

```ts
// convex/http.ts
import { httpRouter } from "convex/server";
import { registerLogtoWebhook } from "convex-logto";
import { internal } from "./_generated/api";

const http = httpRouter();
registerLogtoWebhook(http, internal.logto.sync); // serves POST /logto/webhook
export default http;
```

### 4. Create the webhook in Logto

Logto Console → **Webhooks** → new webhook pointed at `<your-convex-site-url>/logto/webhook` (your Convex **HTTP Actions** URL, e.g. `https://happy-otter-123.convex.site/logto/webhook`). Subscribe to `User.Created`, `User.Data.Updated`, `User.Deleted`, and copy the **Signing key** — the one Logto value that *is* a secret:

```bash
npx convex env set LOGTO_WEBHOOK_SIGNING_KEY <signing-key>
```

The signature is verified with Web Crypto (HMAC-SHA256) inside the Convex runtime; bad signatures get a 401.

### RBAC

Store a `role` on the synced user (above), then gate in Convex by loading the row via `identity.subject`:

```ts
const user = await ctx.db
  .query("users")
  .withIndex("authId", (q) => q.eq("authId", identity.subject))
  .unique();
if (user?.role !== "admin") throw new Error("forbidden");
```

Keep the ability map in your app — the package stays out of your authorization policy.

## Why the ID token (and why there's no JWT config)

Convex validates an OIDC **ID token**. Logto's access tokens are typed `at+jwt`, which Convex does not accept ([convex#75](https://github.com/get-convex/convex-backend/issues/75)), so this package returns the ID token. Because it goes through Convex's **OIDC** provider (not Custom JWT), Convex reads the issuer's discovery document and JWKS itself — including the signing algorithm (Logto uses **ES384**). That is why you never set an algorithm or a JWKS URL. Sessions refresh via Logto's refresh token, which is why `ConvexLogtoProvider` requests the `offline_access` scope by default.

## API

| Export | From | Purpose |
| --- | --- | --- |
| `logtoAuthConfig(opts?)` | `convex-logto` | Provider entry for `auth.config.ts`. Reads `LOGTO_ENDPOINT` / `LOGTO_APP_ID`. |
| `logtoConfigQuery()` | `convex-logto` | Public query serving `{ endpoint, appId }` to the frontend. |
| `logtoSync<DataModel>(handlers)` | `convex-logto` | Returns `{ sync }`, an internal mutation mapping user events to your tables. |
| `registerLogtoWebhook(http, sync, opts?)` | `convex-logto` | Registers the verified webhook route. Reads `LOGTO_WEBHOOK_SIGNING_KEY`. |
| `verifyLogtoSignature(key, body, sig)` | `convex-logto` | Low-level signature check, for custom routing. |
| `ConvexLogtoProvider` | `convex-logto/react` | Logto + Convex + auto callback in one provider. Takes `configQuery` or `endpoint`+`appId`. |
| `useLogtoAuth()` | `convex-logto/react` | `{ isAuthenticated, isLoading, user, signIn, signOut }`. |

### Next.js note

`ConvexLogtoProvider` and `useLogtoAuth` are client-only (they use React hooks and `window`). In the Next.js App Router, render them inside a `"use client"` component.

## License

MIT
