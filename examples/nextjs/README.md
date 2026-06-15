# convex-logto + Next.js (App Router)

The smallest correct way to use `convex-logto` in the Next.js App Router. The
frontend carries **no Logto config** — it pulls `{ endpoint, appId }` from the
Convex backend via `api.logto.config`.

## Run

1. Install from the repo root: `pnpm install`
2. In this directory, start Convex (creates a deployment, writes `NEXT_PUBLIC_CONVEX_URL` to `.env.local`):
   ```bash
   npx convex dev
   ```
3. In Logto, create a **Single page app** and register (Next's default port is 3000):
   - **Redirect URI** → `http://localhost:3000/callback`
   - **Post sign-out redirect URI** → `http://localhost:3000`

   Also rotate the tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → **Rotate private keys** → choose RSA). Convex rejects Logto's default ES384, so this is required; otherwise `getUserIdentity()` returns `null`. Note its **endpoint** and **App ID** for the next step.
4. Point that deployment at your Logto app:
   ```bash
   npx convex env set LOGTO_ENDPOINT https://auth.example.com
   npx convex env set LOGTO_APP_ID   your-app-id
   ```
5. `pnpm dev`, then open http://localhost:3000.

> In this monorepo the dependency is `convex-logto: workspace:*`. Standalone, run `npm i convex-logto @logto/react`.

## Next.js gotchas this example gets right

- **The provider is a `"use client"` boundary.** `convex-logto/react`, `@logto/react`,
  and `ConvexReactClient` use React hooks and `window`, so they can't be imported
  into a Server Component. `app/layout.tsx` stays a Server Component and only
  renders the client `app/providers.tsx`.
- **The Convex client is created once at module scope** in the client component,
  never inside render.
- **Use `process.env.NEXT_PUBLIC_CONVEX_URL`** — there is no `VITE_*` / `import.meta.env`.
- **Soft navigation** after sign-in via `navigate={(to) => router.push(to)}` from
  `next/navigation`.
- **The callback route** (`app/callback/page.tsx`) is a plain Server Component (no
  `"use client"` needed) that just renders; the provider finishes the OIDC exchange.

> **Want webhook user-sync?** It's framework-agnostic — the `convex/` backend code is
> identical across examples. See the [`tanstack-router-spa`](../tanstack-router-spa) example.
