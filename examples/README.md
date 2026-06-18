# Examples

Working examples of [`convex-logto`](../packages/convex-logto) across frameworks.
Each is a standalone app — see its README to run it.

| Example | What it shows |
| --- | --- |
| [`vite-react`](./vite-react) | The minimal setup: `ConvexLogtoProvider` + declarative auth gating. |
| [`tanstack-router-spa`](./tanstack-router-spa) | TanStack Router (SPA): declarative gating + `beforeLoad` route guards (auth outside render), **plus a webhook-synced users table with role-based access (RBAC)**. |
| [`tanstack-start`](./tanstack-start) | TanStack Start (SSR): one SSR-safe provider + `beforeLoad` route guards. |
| [`nextjs`](./nextjs) | Next.js App Router: client provider boundary + callback route. |
| [`expo`](./expo) | Expo (React Native): native auth via `convex-logto/native` — deep-link sign-in, no callback route. |

> The webhook user-sync and RBAC shown in `tanstack-router-spa` are **framework-agnostic** —
> the `convex/` backend code is identical everywhere, so a Vite, Next.js, or Expo app wires them the same way.

In this monorepo each example depends on the package via `convex-logto: workspace:*`.
Standalone, install it from npm with the Logto peer for your platform:

- Web (Vite / Next.js / TanStack): `npm i convex-logto @logto/react`
- React Native / Expo: `npm i convex-logto @logto/rn` (plus the Expo modules — see the [`expo`](./expo) README)
