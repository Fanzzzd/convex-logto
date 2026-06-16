---
"convex-logto": patch
---

Clarify the `convex-logto/native` `fallback` JSDoc: it renders during the one-time
config fetch, before the Convex provider mounts, so Convex's `<AuthLoading>` belongs
in your app's children — not inside `fallback`.
