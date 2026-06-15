# convex-logto + TanStack Router (SPA)

All three ways to use auth: declarative `<Authenticated>` gating, the `useLogtoAuth()` hook, and **`beforeLoad` route guards** that protect routes outside of render — plus a webhook-synced `users` table with a per-app **role** (RBAC).

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

## Users table + roles (RBAC)

The opt-in **webhook-synced `users` table** pattern: a table you own, with a
per-app `role`. (Full write-up: [Webhook sync](../../docs/content/docs/webhook-sync.mdx).)

**Try it:**

1. Sign in. The first time, the dashboard shows an **onboarding form** — pick
   `user` or `admin`. Submitting creates your `users` row.
2. Open **Admin (admin-only)**. As a `user` you get a 403; as an `admin` you see
   the admin stats.
3. Use **Switch role (demo)** on the dashboard to flip your role and watch the gate
   allow / deny.

**How it's wired:**

- `convex/schema.ts` — the `users` table. `email`/`name`/`status` are Logto-owned
  (synced); `role` is app-owned.
- `convex/logto.ts` — the `logtoSync` webhook handlers (production sync of
  email/name + suspend/delete), registered in `convex/http.ts`.
- `convex/authz.ts` — `requireIdentity` / `getActiveUser` / `requireActiveUser` /
  `requireRole`. Reads are nullable (never throw mid-provisioning); writes and
  privileged reads throw and honor suspend + delete.
- `convex/users.ts` — `myProfile`, `completeOnboarding` (first-login row creation),
  `setMyRole` (the demo switcher, active-only), and `adminStats` (gated by
  `requireRole`).

**The rules that keep it correct** (and dodge two classic bugs):

- **The webhook writes only Logto-owned fields (email, name, status), never
  `role`.** Otherwise a Logto profile edit (`User.Data.Updated`) would reset
  everyone's role to the default.
- **The webhook never creates rows — it only syncs existing ones.** Rows are created
  by the onboarding mutation, from the logged-in state. `User.Created` does **not**
  fire for a user who already existed in Logto (or who arrived via another app on the
  same Logto), so a webhook-only approach would leave them permanently row-less.
  (That's the bug that bites component-owned auth tables.)
- **Deletion is a tombstone**, not a row removal: PII is scrubbed, but the row stays
  so authz fails closed and nothing referencing the user by id dangles.

**Demo vs production:** a real app creates everyone as `user` and grants admin out
of band — a Convex dashboard mutation, an internal mutation, or an allowlist —
never self-service. The "become admin" button exists only so you can try the gate
from both sides.

**Prove the gate:** `pnpm test` (after `npx convex dev` has generated types) runs
`convex/rbac.test.ts`, which checks that a pre-existing Logto user still gets a row
on first sign-in, non-admins are denied `adminStats`, a profile edit can't reset a
role, and a deleted user fails closed.
