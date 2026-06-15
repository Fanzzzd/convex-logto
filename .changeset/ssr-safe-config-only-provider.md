---
"convex-logto": minor
---

SSR-safe, config-only provider (breaking API slim).

- **`ConvexLogtoProvider` is now safe to render anywhere, including on the server.** It mounts the Logto + Convex tree from the first render using an inert loading client, so children render immediately (under Convex's `<AuthLoading>`) while config loads, and nothing touches `window` on the server. SSR frameworks (Next.js App Router, TanStack Start) no longer need a hand-written client boundary — a single `<ConvexLogtoProvider>` is enough everywhere.
- **Breaking — the provider is configured by `configQuery` only.** The literal `endpoint`/`appId` props (and their discriminated union) are removed; `{ endpoint, appId }` is served from the Convex deployment via `logtoConfigQuery()`, so config lives in exactly one place per environment.
- **Breaking — removed the `callbackPath` prop.** `/callback` is the fixed convention; to use a different path, pass it explicitly: ``signIn(`${origin}/your-path`)``.
- **Breaking — removed the `fallback` prop.** Children render during config load (gated by `<AuthLoading>`), so a separate fallback is no longer needed.
- Auth no longer flickers on load or reload: the bridge latches on the first settle and sources `isAuthenticated`/`isLoading` from Convex, verified across repeated authenticated reloads.
- A failed sign-in code exchange (a stale callback URL or a lost sign-in session) now throws a clear error instead of leaving the callback page stuck on "finishing sign in".

Note: Convex's OIDC verifier accepts only RS256/EdDSA, but Logto signs with ES384 by default. Rotate your tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → rotate private key → RSA), or `getUserIdentity()` returns `null`.
