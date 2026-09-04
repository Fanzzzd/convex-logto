# convex-logto

[![npm](https://img.shields.io/npm/v/convex-logto.svg)](https://www.npmjs.com/package/convex-logto)
[![CI](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/convex-logto.svg)](./LICENSE)

Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for a [Convex](https://convex.dev) React app.

- **One provider on the frontend.** `<ConvexLogtoSessionProvider>` signs in, finishes the callback, refreshes, and signs out. No Logto SDK in the bundle and no hand-rolled `useAuth` bridge.
- **One line on the backend.** `logtoAuthConfig()` reads your env. No JWT template, no algorithm, no JWKS URL to copy.
- **Every Logto value on the Convex deployment.** Endpoint, app id, and app secret live in `npx convex env`. The frontend build carries none of them, so one artifact serves dev, staging, and prod.
- **Revocation lands live.** Sign-out on another device, "sign out everywhere", a suspended user, or an admin ending the session drops the open tab at once, not when the token expires.

It hands Convex Logto's **ID token** over OIDC, so Convex discovers the signing key and JWKS itself. The one Logto-side requirement is an RSA signing key; see [step 1](#1-create-a-logto-app).

Two modes share the same backend identity model:

- **Session mode** (recommended, shown below): your Convex deployment is the OAuth client. A Convex component holds the Logto refresh token server-side; the browser holds a short-lived ID token and a rotating application session token.
- **[Bridge mode](#bridge-mode)**: Logto's SPA SDK (`@logto/react`) signs in from the browser and owns the refresh token; the package bridges its ID token into Convex. Zero server-side state.

Whichever mode you choose, apply the [SPA security baseline][security-baseline-docs] to the scripts and dependencies that share its browser origin.

Full documentation: [convex-logto-docs.vercel.app](https://convex-logto-docs.vercel.app).

## Install

```bash
pnpm add convex-logto
```

`convex` and `react` are peers you already have. Bridge mode adds `@logto/react`
(`@logto/rn` on Expo). Expo session mode adds `expo-secure-store` and
`expo-web-browser`; see [React Native / Expo](#react-native--expo).

## Quick start

The snippets below use **Vite**. The provider placement and callback wiring for
TanStack Router, TanStack Start, Next.js, and Expo are in the
[docs](https://convex-logto-docs.vercel.app/docs/vite) and the runnable
[examples](https://github.com/Fanzzzd/convex-logto/tree/main/examples).

### 1. Create a Logto app

**Rotate the signing key to RSA first.** Convex only accepts ID tokens signed with **RS256** (or EdDSA); Logto signs with **ES384** by default, which Convex rejects without an error (sign-in looks fine, but `ctx.auth.getUserIdentity()` returns `null`). Rotate it once per tenant. In the Logto Console, open **Tenant settings → OIDC configs**, click **Rotate private keys**, and choose **RSA**. Logto keeps the old key during a transition, so existing sessions stay signed in.

Then, in Logto Console → **Applications** → **Create application** → **Traditional web**. Pick this type even though your frontend is a SPA; the Convex deployment holds the app secret, and only a Traditional web app has one. The app type can't be changed after creation.

Note the **endpoint** (e.g. `https://auth.example.com`), the **App ID**, and the **App Secret**, and add two URLs on the app (for each environment):

- **Redirect URIs** → `http://localhost:5173/callback` (and your prod callback)
- **Post sign-out redirect URIs** → `http://localhost:5173` (your app's origin, and your prod origin)

### 2. Set the config

Everything goes on the Convex deployment. The frontend has no Logto env vars:

```bash
npx convex env set LOGTO_ENDPOINT      https://auth.example.com
npx convex env set LOGTO_APP_ID        your-app-id
npx convex env set LOGTO_CLIENT_SECRET your-app-secret
```

The endpoint may include a reverse-proxy path prefix, but it must be the Logto
base URL (not the `/oidc` issuer URL) and may not contain credentials, a query,
or a fragment. The library requires HTTPS except for loopback development. An
existing HTTP-only, non-loopback self-hosted deployment can opt in with
`allowInsecureHttp: true` on `logtoAuthConfig` and `logtoSessionApi` (and on
the bridge-mode `config` / `logtoConfigQuery`); prefer terminating TLS.

### 3. Wire Convex

```ts
// convex/convex.config.ts: install the session component
import { defineApp } from "convex/server";
import logto from "convex-logto/convex.config";

const app = defineApp();
app.use(logto);
export default app;
```

```ts
// convex/auth.config.ts
import { logtoAuthConfig } from "convex-logto";
export default { providers: [logtoAuthConfig()] };
```

```ts
// convex/auth.ts: every server function session mode needs
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
  exchangeToken,
  fetchUserInfo,
  sessionValid,
} = logtoSessionApi(components.logto);
```

Re-export all eleven with these exact names; the provider looks them up on the module you pass it. Run `npx convex dev` once after adding `convex.config.ts` so `_generated/api` gains `components.logto`.

### 4. Wrap your app

```tsx
// src/main.tsx: no Logto SDK, no Logto config in the bundle
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoSessionProvider } from "convex-logto/react-session";
import { api } from "../convex/_generated/api";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL, {
  // Without this, Convex confirms the cached token and then refetches a fresh
  // one at once. That is a Logto refresh grant and a session-token rotation
  // on every page load. Convex still marks the option experimental.
  initialAuthTokenReuse: true,
});

root.render(
  <ConvexLogtoSessionProvider
    client={convex}
    sessionApi={api.auth}
    onAuthError={(error) => console.error("auth error", error)}
  >
    <App />
  </ConvexLogtoSessionProvider>,
);
```

With a router, pass `navigate={(to) => void router.navigate({ to, replace: true })}` so the post-sign-in landing is a soft navigation and the callback URL leaves history.

### 5. Add a callback route

`signIn()` lands on `/callback`. The provider owns that path: it POSTs the code to your `callback` action and replace-navigates to `afterSignIn` (default `/`), so the route only needs to render. With TanStack Router:

```tsx
// src/routes/callback.tsx
import { createFileRoute } from "@tanstack/react-router";
export const Route = createFileRoute("/callback")({ component: () => null });
```

### 6. Sign in, and read the user

```tsx
import { useLogtoAuth } from "convex-logto/react-session";

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

The `void signIn()` handler is fine. The provider reports a failure to `onAuthError` and the console before the promise rejects. `signOut()` clears this browser, deletes the server session, then ends the Logto session and returns to your origin; don't follow it with a hard navigation of your own, which would supersede the request that ends the Logto session.

In any Convex function, the Logto identity is already there:

```ts
// convex/me.ts
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

That is the whole auth setup. Many apps need nothing more. The runnable version is [`examples/vite-react-session`][session-example].

## What session mode adds

`useLogtoAuth()` from `convex-logto/react-session` has the five fields above plus `signOutEverywhere()` and a device list (`listSessions()` / `renameSession()` / `revokeSession()`). The [Session mode docs][session-mode-docs] cover the threat model, the token dance, and each of the following.

**Sign out everywhere.** `signOutEverywhere()` derives the caller's subject from its rotating session token, records subject-wide logical revocation in one transaction, then removes rows in bounded batches. Other devices drop through reactive revocation. The RP cannot erase their separate Logto browser cookies, which can start a new sign-in; revoke a lost device in Logto itself (or suspend the user) as well.

**Where am I signed in.** `listSessions()` returns the caller's own sessions, newest first, each `{ sessionId, current, createdAt, lastRefreshedAt, label?, client?, deviceBound }`. The subject always comes from the presented token, so another user's `sessionId` resolves to `session_not_found`. The optional `clientDescriptor` provider prop supplies the advisory device description; the library never reads a User-Agent or IP.

**Revocation enforced server-side.** `assertSubjectHasActiveSession(ctx, components.logto)` makes a function fail the moment the subject's sessions are revoked, rather than when the ID token expires. `registerLogtoWebhook(http, internal.logto.sync, { sessions: components.logto })` kills a deleted or suspended user's sessions within seconds, and `registerLogtoBackchannelLogout(http, { sessions: components.logto })` propagates Logto-side sign-out through the same path.

**HttpOnly cookie transport.** Apps with a same-site server endpoint can mount `createLogtoSessionCookieHandler()` and pass `cookieTransport={{ endpoint: "/api/logto" }}` to the provider. The rotating credential moves into a rolling `__Host-` HttpOnly cookie whose 190-day lifetime matches server-side idle GC. `handler.getInitialToken(request)` seeds an authenticated first paint; it *rotates* the cookie, so call it where the framework can set cookies (a middleware or route handler, never a Server Component). Where render cannot set cookies, set `idTokenCookie: true` and read the ID token back with `readLogtoIdTokenCookie(request | cookieHeader | cookieStore)`, which mints and rotates nothing.

**Device binding.** `deviceBinding` on the provider requires an ECDSA proof from a non-extractable IndexedDB-held key whenever the client presents the rotating token, so a copied token cannot refresh or sign out from another device. Off by default; cannot be combined with the cookie transport.

**Configuration faults never delete sessions.** A wrong `LOGTO_CLIENT_SECRET` or a moved `LOGTO_ENDPOINT` is reported as transient and the session survives, so fixing the env var is the whole recovery. Only Logto rejecting the grant itself deletes a session.

Runnable apps: [`examples/vite-react-session`][session-example] for the SPA shape and [`examples/nextjs-session`](https://github.com/Fanzzzd/convex-logto/tree/main/examples/nextjs-session) for the cookie transport and server rendering with a real identity.

## Bridge mode

Bridge mode keeps `@logto/react` in the browser, with the refresh token in `localStorage`, and needs nothing on the server beyond `auth.config.ts`. Pick it for zero server-side state, or if you already run it. It stays supported.

```bash
pnpm add convex-logto @logto/react
```

Create a **Single page app** in Logto (not a Third-party app; that withholds the `profile` / `email` scopes), register the same two URIs as above, and set `LOGTO_ENDPOINT` / `LOGTO_APP_ID` on the deployment. `auth.config.ts` is the same one line. The provider takes the two public values from the frontend env:

```tsx
// src/main.tsx
import { ConvexLogtoProvider } from "convex-logto/react";

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

`useLogtoAuth()` from `convex-logto/react` has the same five fields. To keep the two values out of the bundle, export `logtoConfigQuery()` from a Convex file and pass `configQuery={api.logto.config}` instead of `config`. Revocation in bridge mode waits for the ID token to expire; there is no session for the webhook to revoke. Full page: [Bridge mode](https://convex-logto-docs.vercel.app/docs/bridge-mode).

## Multiple environments

Create one Logto app per environment (dev / staging / prod, so tokens can't cross environments), then set each deployment's env once:

```bash
# dev deployment
npx convex env set LOGTO_ENDPOINT      https://your-logto.example.com
npx convex env set LOGTO_APP_ID        <dev-app-id>
npx convex env set LOGTO_CLIENT_SECRET <dev-app-secret>
# production deployment
npx convex env set --prod LOGTO_ENDPOINT      https://your-logto.example.com
npx convex env set --prod LOGTO_APP_ID        <prod-app-id>
npx convex env set --prod LOGTO_CLIENT_SECRET <prod-app-secret>
```

In session mode **the only thing that varies per environment is the Convex deployment the frontend points at** (`VITE_CONVEX_URL`). The same build serves every environment. In bridge mode with static `config`, set the two public Logto values in each frontend environment as well, or use `configQuery` to get the same single-source property.

[session-mode-docs]: https://convex-logto-docs.vercel.app/docs/session-mode
[session-example]: https://github.com/Fanzzzd/convex-logto/tree/main/examples/vite-react-session
[security-baseline-docs]: https://convex-logto-docs.vercel.app/docs/security-baseline

## Organization authorization

Logto maps `urn:logto:scope:organizations` to an `organizations` claim and
`urn:logto:scope:organization_roles` to an `organization_roles` claim **in the ID
token**, and Convex passes claims it does not recognise through to
`ctx.auth.getUserIdentity()`. So membership and roles are already inside the
request Convex authenticated. No token exchange, no second round trip:

```ts
import { assertOrganizationRole } from "convex-logto";

export const deleteInvoice = mutation({
  args: { organizationId: v.string(), id: v.id("invoices") },
  handler: async (ctx, { organizationId, id }) => {
    await assertOrganizationRole(ctx, organizationId, ["admin", "billing"]);
    await ctx.db.delete(id);
  },
});
```

Add both scopes to `logtoSessionApi({ scopes })` in session mode or to the
provider's `scopes` in bridge mode; they are independent, and neither implies
the other. `assertOrganizationMember`, `logtoOrganizations` and
`logtoOrganizationRoles` are exported too. A role check matches on the
organization **and** the role, so one organization's `viewer` cannot authorize
another's, and a missing scope authorizes nothing rather than everything.

These claims are a **snapshot**, frozen until Logto issues the next ID token, at
most its own lifetime. Removing someone from an organization does not take effect
at once; when it has to, keep membership in your own table and check that
instead. Deleting or suspending the *user* is different; the webhook revokes
their sessions within seconds.

Fine-grained organization **permissions** are the exception; Logto puts those
only in an organization token, which Convex cannot accept as a request
credential. Session mode can mint one for you with `getOrganizationTokenClaims()`
and hand back what it authorizes rather than the token itself.

## Optional: sync Logto users into a table

You don't need a table to authenticate; identity comes from the token, so attach
your data to your own tables keyed by `identity.subject`. Add a `users` table only
when you need to query users (an admin list, another user's name) or store fields
the token doesn't carry (a per-app **role**). The table is **yours**; the package
just provides the webhook glue.

```ts
// convex/schema.ts: fields grouped by who owns them
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
  `role`**; otherwise a Logto profile edit would reset everyone's role.
- **The webhook never creates rows; it only syncs existing ones.** `User.Created`
  doesn't fire for users who already existed in Logto, so create rows from an
  authenticated mutation on first load (get-or-create) and let the webhook keep them
  in sync. Webhook-only creation is the bug that bites component-owned auth tables.
- **Soft-delete on `User.Deleted`.** Scrub PII but keep a tombstone row, so authz
  fails closed and nothing referencing the user by id dangles.

The full walkthrough, covering `logtoSync` handlers, `registerLogtoWebhook`,
signing-key setup, and `requireRole` authz, is in the
[Webhook sync guide][webhook-sync] and the runnable
[`tanstack-router-spa`][spa-example] example.

[webhook-sync]: https://convex-logto-docs.vercel.app/docs/webhook-sync
[spa-example]: https://github.com/Fanzzzd/convex-logto/tree/main/examples/tanstack-router-spa

## Why the ID token (and why there's no JWT config)

Convex validates an OIDC **ID token**. Logto's access tokens are typed `at+jwt`, which Convex does not accept ([convex#75](https://github.com/get-convex/convex-backend/issues/75)), so this package returns the ID token. Because it goes through Convex's **OIDC** provider (not Custom JWT), Convex reads the issuer's discovery document and JWKS itself, so you never set an algorithm or a JWKS URL. There is one catch. Convex's OIDC verifier accepts only **RS256**/**EdDSA**, while Logto signs with **ES384** by default, so you rotate the Logto OIDC signing key to **RSA** once (step 1). Convex rejects a mismatch without an error (`getUserIdentity()` returns `null`). Sessions refresh via Logto's refresh token, which is why both modes request the `offline_access` scope by default.

## API

| Export | From | Purpose |
| --- | --- | --- |
| `logtoAuthConfig(opts?)` | `convex-logto` | Provider entry for `auth.config.ts`. Reads `LOGTO_ENDPOINT` / `LOGTO_APP_ID`. |
| `logtoSessionApi(component, opts?)` | `convex-logto` | [Session mode](#quick-start): builds the eleven public auth functions backed by the session component. Reads `LOGTO_CLIENT_SECRET` too. |
| `assertSubjectHasActiveSession(ctx, component)` | `convex-logto` | Session mode: throw unless the authenticated subject has at least one active component Session; this does not bind the current bearer to one Session. Its bounded scan can throw the transient `session_liveness_scan_incomplete` while bulk cleanup is in progress. |
| `assertUserHasActiveSession(ctx, component)` | `convex-logto` | Deprecated compatibility alias for `assertSubjectHasActiveSession`. |
| `logtoConfigQuery(opts?)` | `convex-logto` | Bridge mode: public query serving `{ endpoint, appId, allowInsecureHttp? }` to a frontend that resolves its config at runtime. |
| `logtoSync<DataModel>(handlers)` | `convex-logto` | Returns `{ sync }`, an internal mutation mapping user events to your tables. |
| `registerLogtoWebhook(http, sync, opts?)` | `convex-logto` | Registers the verified webhook route. Reads `LOGTO_WEBHOOK_SIGNING_KEY`; `sessions` option adds dedupe + session revocation. |
| `registerLogtoBackchannelLogout(http, opts)` | `convex-logto` | Session mode: registers a verified OIDC back-channel logout route with `sid` / `sub` revocation. |
| `createLogtoBackchannelLogoutHandler(opts)` | `convex-logto` | Builds the back-channel Convex HTTP action for custom route composition. |
| `verifyLogtoLogoutToken(token, opts?)` | `convex-logto` | Low-level RS256/PS256 Logout Token verification against Logto's JWKS. |
| `verifyLogtoSignature(key, body, sig)` | `convex-logto` | Low-level signature check, for custom routing. |
| `createLogtoSessionCookieHandler(opts)` | `convex-logto` | Six-route standard-fetch handler for the optional same-site HttpOnly cookie transport. |
| `createLogtoSessionCookieTransport(api, opts?)` | `convex-logto` | Framework-free browser adapter behind the provider's `cookieTransport` prop. |
| `assertLogtoSessionCookieCompatibility(opts)` | `convex-logto` | Loud guard for the cookie/device-binding exclusion on non-React mounts. |
| `readLogtoIdTokenCookie(source)` | `convex-logto` | Reads the opt-in SSR ID token cookie from a `Request`, a `Cookie` header, or a Next-style store. |
| `LOGTO_SESSION_COOKIE_*`, `LOGTO_ID_TOKEN_COOKIE_NAME`, `LOGTO_SESSION_CSRF_*` | `convex-logto` | Fixed cookie names/base path and CSRF header/value constants. |
| `assertOrganizationMember` / `assertOrganizationRole` | `convex-logto` | [Organization authorization](#organization-authorization) from the ID token Convex already validated. |
| `logtoOrganizations` / `logtoOrganizationRoles` / `parseOrganizationRole` | `convex-logto` | The same claims, read rather than asserted. |
| `ORGANIZATIONS_SCOPE` / `ORGANIZATION_ROLES_SCOPE` | `convex-logto` | The two scope strings those claims need. They are independent; request both if you read both. |
| `LogtoUserClaims` | `convex-logto` | The type of `user` in all four entries: standard claims named, everything else through an index signature. |
| default | `convex-logto/convex.config` | The session component, for `app.use(logto)`. |
| `ConvexLogtoSessionProvider` | `convex-logto/react-session` | Session mode's provider. No Logto SDK; talks to your `logtoSessionApi` functions. |
| `useLogtoAuth()` | `convex-logto/react-session` | Session auth actions, including `signOutEverywhere({ postLogoutRedirectUri? })`, `listSessions()` / `renameSession()` / `revokeSession()`, and `getIdToken()` / `getOrganizationTokenClaims()` / `getAccessTokenClaims()` / `fetchUserInfo()`. |
| `SessionSignOutError` | `convex-logto/react-session`, `convex-logto/native-session` | What `signOut()` rejects with when local credential cleanup fails twice; `serverSessionStatus` says whether the server session survived. |
| `ConvexLogtoProvider` | `convex-logto/react` | [Bridge mode](#bridge-mode)'s provider, on `@logto/react`. Static `config` or backend `configQuery`. |
| `useLogtoAuth()` | `convex-logto/react` | `{ isAuthenticated, isLoading, user, signIn, signOut }`. |
| `ConvexLogtoSessionProvider` | `convex-logto/native-session` | Expo session mode via SecureStore + system-browser deep links; same server component and actions. |
| `useLogtoAuth()` | `convex-logto/native-session` | Native session auth/actions, including federated `signOutEverywhere(opts?)` and the same session list. |
| `ConvexLogtoProvider` | `convex-logto/native` | Expo bridge mode (on `@logto/rn`). Same `config` / `configQuery` model; no callback route. |
| `useLogtoAuth()` | `convex-logto/native` | Native `{ isAuthenticated, isLoading, user, signIn, signOut }`; `signIn()` defaults to the provider's `redirectUri`. |

### Next.js note

Both providers and hooks use React hooks (and `window` for sign-in / sign-out), so in the Next.js App Router render them from a `"use client"` component; each provider is SSR-safe within that boundary.

### React Native / Expo

For Expo session mode, use **`convex-logto/native-session`** with `expo-secure-store` and `expo-web-browser`; it reuses the same component and session actions, keeps the rotating session token and short-lived ID token in the OS keystore, and completes sign-in through the system browser and a deep link. For bridge mode, import from **`convex-logto/native`** (built on [`@logto/rn`](https://github.com/logto-io/react-native)). Neither native entry needs a callback route. See the [React Native guide](https://convex-logto-docs.vercel.app/docs/react-native) and the two runnable apps: session-mode [`examples/expo-session`](https://github.com/Fanzzzd/convex-logto/tree/main/examples/expo-session) and bridge-mode [`examples/expo`](https://github.com/Fanzzzd/convex-logto/tree/main/examples/expo).

## License

MIT
