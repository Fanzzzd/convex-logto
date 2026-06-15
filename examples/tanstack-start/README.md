# convex-logto + TanStack Start (SSR)

`convex-logto` on TanStack Start, following Convex's canonical Start wiring
(`ConvexQueryClient` + TanStack Query + `setupRouterSsrQueryIntegration`) with
`ConvexLogtoProvider` layered on top. Shows both auth patterns from the SPA
example: declarative `<Authenticated>` gating **and** a `beforeLoad` route guard
reading auth from router context.

## Run

1. Install from the repo root: `pnpm install`
2. In this directory, start Convex (creates a dev deployment and generates types):
   ```bash
   npx convex dev
   ```
3. In Logto, create a **Single page app** (not a third-party app) and add
   (TanStack Start's dev server defaults to port 3000):
   - **Redirect URI** → `http://localhost:3000/callback`
   - **Post sign-out redirect URI** → `http://localhost:3000`

   Also rotate the tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → rotate private key → RSA). Convex rejects Logto's default ES384, so this is required; otherwise `getUserIdentity()` returns `null`. Note its **endpoint** and **App ID** for the next step.
4. Point that deployment at your Logto app — the one place config lives:
   ```bash
   npx convex env set LOGTO_ENDPOINT https://your-logto.example.com
   npx convex env set LOGTO_APP_ID   your-spa-app-id
   ```
5. Copy `.env.example` to `.env.local` and set `VITE_CONVEX_URL` (printed by `npx convex dev`).
6. `pnpm dev`, then open http://localhost:3000.

> In this monorepo the dependency is `convex-logto: workspace:*`. Standalone, run `npm i convex-logto @logto/react`.

## How SSR is handled

The provider is **SSR-safe**: `ConvexLogtoProvider` mounts the Logto + Convex tree
from the first render using an inert loading client, so children render immediately
under Convex's `<AuthLoading>` and nothing touches `window` on the server. So this
example has **no hand-written client boundary, stub, or mount-gate** — the same
`<ConvexLogtoProvider>` you'd write for a SPA works on the server too.

- **`src/router.tsx`** is Convex's canonical Start setup; the router's `InnerWrap`
  renders `src/auth.tsx`'s `AuthBoundary`.
- **`AuthBoundary`** is just `<ConvexLogtoProvider>` plus a `RouterAuthBridge`. On
  the server and the first client paint auth reports "loading", so the
  `<AuthLoading>` shell renders; the client hydrates and auth settles. Server and
  first client render match, so there's no hydration mismatch.
- The `<Authenticated>/<Unauthenticated>/<AuthLoading>` components and the
  `useLogtoAuth()` buttons read the provider's context directly — no mount-gating,
  the same component code as the SPA example.

## The two auth patterns

1. **Declarative** (`src/DeclarativeGate.tsx`) — `<Authenticated>` /
   `<Unauthenticated>` / `<AuthLoading>` from `convex/react`, unchanged.
2. **`beforeLoad` route guard** (`src/routes/_authed.tsx`) — protects `/dashboard`
   outside of render. Start builds the router context once, so auth is carried in
   a **mutable holder** on the context that `AuthBoundary`'s `RouterAuthBridge`
   keeps pointed at the live `useLogtoAuth()` result, calling `router.invalidate()` on every auth
   change to re-run the guards. This is the Start equivalent of the SPA's
   `<RouterProvider context={{ auth }}>` + `RouterWithAuth`.

`navigate` is wired to the router (`router.navigate`), so post-sign-in is a soft
navigation rather than a full reload. The OIDC redirect lands on
`src/routes/callback.tsx`, which just renders while the provider finishes the
code exchange.
