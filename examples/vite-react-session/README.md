# convex-logto session mode + Vite + React

Session mode: your Convex deployment is the OAuth client (a Logto **Traditional
Web** app). The Logto refresh token never reaches the browser — a Convex
component holds it, rotates a session token with the browser, and
pushes session revocation reactively. No `@logto/react`, no Logto config in the
bundle.

## Run

1. Install from the repo root: `pnpm install`
2. In this directory, start Convex (installs the component and generates types):
   ```bash
   npx convex dev
   ```
3. In Logto, create a **Traditional web** application and add:
   - **Redirect URI** → `http://localhost:5174/callback`
   - **Post sign-out redirect URI** → `http://localhost:5174`

   Also rotate the tenant's OIDC signing key to **RSA** (Tenant settings → OIDC
   configs → **Rotate private keys** → choose RSA). Convex rejects Logto's
   default ES384. Note the app's **endpoint**, **App ID**, and **App Secret**.
4. Point the deployment at that app — all config lives server-side:
   ```bash
   npx convex env set LOGTO_ENDPOINT      https://your-logto.example.com
   npx convex env set LOGTO_APP_ID        your-traditional-web-app-id
   npx convex env set LOGTO_CLIENT_SECRET your-traditional-web-app-secret
   ```
5. Copy `.env.example` to `.env.local` and set `VITE_CONVEX_URL` (printed by
   `npx convex dev`).
6. `pnpm dev`, then open http://localhost:5174.

## What to look at

- `convex/convex.config.ts` — installs the session component (`app.use(logto)`).
- `convex/auth.ts` — the entire server surface: one `logtoSessionApi(...)` call.
- `src/main.tsx` — `ConvexLogtoSessionProvider` pointed at `api.auth`.
- `convex/me.ts` — `assertSubjectHasActiveSession` for subject-level revocation
  enforcement on sensitive functions.

> In this monorepo the dependency is `convex-logto: workspace:*`. Standalone,
> run `npm i convex-logto` — session mode needs no other auth dependency.
