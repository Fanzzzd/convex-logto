---
"convex-logto": minor
---

Webhook hardening + session revocation wiring for `registerLogtoWebhook`:

- **Freshness window**: authentic deliveries whose `createdAt` is older than 5
  minutes (or more than 1 minute in the future) are rejected with 400 — the
  signature scheme has no timestamp binding, so this is what retires replayed
  captures. Logto's own retries land within seconds.
- **1 MB body cap** (413) before any crypto or parsing.
- **New `sessions` option** — pass `components.logto` (session mode) to get:
  exactly-once handling (deliveries deduplicated by raw-body SHA-256, so a
  retry whose 200 got lost doesn't re-run your sync handlers; the claim is
  released if processing fails so retries still work), and **session
  revocation** — `User.Deleted`, and `User.SuspensionStatus.Updated` with
  `isSuspended: true`, kill all of that user's sessions before your sync
  handlers run, dropping reactive clients to signed-out live.
- Documented that `hookId` identifies the webhook configuration, not the
  delivery — it is not an idempotency key.
