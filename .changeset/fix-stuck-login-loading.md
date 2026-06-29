---
"convex-logto": patch
---

Fix the app hanging on a loading spinner when `signIn()` is called before the backend config has finished loading (the "stuck on the login button" symptom). During config load the provider mounts an inert Logto client; a `signIn()` in that window poisoned `@logto/react`'s `loadingCount` (its `signIn` increments but never resets, and the inert method never navigates away), and that count survived the swap to the real client — pinning `isLoading` true forever. The `LogtoProvider` is now remounted across the loading→ready transition, so any state built against the inert client is discarded.
