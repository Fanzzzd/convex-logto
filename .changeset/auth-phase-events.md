---
"convex-logto": minor
---

Add opt-in auth phase timings. Every provider now takes an `onAuthEvent` handler
that receives `{ phase, elapsedMs, source?, errorKind? }` for the auth bootstrap:
`bootstrap_start`, `config_loaded` (bridge mode's config fetch),
`session_restored` / `unauthenticated`, `convex_authenticated` — the point where
the first authenticated query can run — plus `refresh_started` /
`refresh_succeeded` / `refresh_failed`, `revoked` and `signed_out`.

`elapsedMs` counts from `bootstrap_start` on a monotonic clock. `source` tells a
zero-round-trip cache restore apart from one that had to refresh; `errorKind`
tells a dead session apart from an outage. Events carry no token, no user
identity and no URL, so they can be forwarded to an analytics backend as-is.

Without a handler nothing is measured and no clock is read. A handler that throws
is caught and logged — telemetry can never fail an authentication. Only the first
settle reports `session_restored` / `unauthenticated`, so a long-lived tab does
not look like it keeps re-mounting.
