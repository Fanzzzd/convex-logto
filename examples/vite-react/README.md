# convex-logto + Vite + React

The smallest working setup: one provider, and Convex's `<Authenticated>` / `<Unauthenticated>` / `<AuthLoading>` to render on auth state.

## Run

1. Install from the repo root: `pnpm install`
2. In this directory, start Convex (creates a dev deployment and generates types):
   ```bash
   npx convex dev
   ```
3. In Logto, create a **Single page app** (not a third-party app) and add:
   - **Redirect URI** → `http://localhost:5173/callback`
   - **Post sign-out redirect URI** → `http://localhost:5173`

   Also rotate the tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → rotate private key → RSA). Convex rejects Logto's default ES384, so this is required; otherwise `getUserIdentity()` returns `null`. Note its **endpoint** and **App ID** for the next step.
4. Point that deployment at your Logto app — the one place config lives:
   ```bash
   npx convex env set LOGTO_ENDPOINT https://your-logto.example.com
   npx convex env set LOGTO_APP_ID   your-spa-app-id
   ```
5. Copy `.env.example` to `.env.local` and set `VITE_CONVEX_URL` (printed by `npx convex dev`).
6. `pnpm dev`, then open http://localhost:5173.

> In this monorepo the dependency is `convex-logto: workspace:*`. Standalone, run `npm i convex-logto @logto/react`.
