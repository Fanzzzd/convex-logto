---
"convex-logto": patch
---

Fix three defects an adversarial audit of the cookie transport and device
binding confirmed.

**A Logto outage turned SSR seeding into a 500 for every signed-in visitor.**
`getInitialToken` rethrew any error it could not classify, and an unreachable
Logto is exactly that class — the component rethrows a raw `fetch` failure
unclassified on purpose, so that an outage does not force a reauthentication.
With the documented root-loader seeding path, the loader threw and the whole
document failed. The browser `/token` route had always treated the same failure
as transient and kept the session; the seed now matches both it and the
documented contract, "every failed seed returns empty without changing the
cookie".

**"Sign out everywhere" with no cookie answered a body the client rejects.** The
route parsed the `everywhere` flag and then returned a bare `{}` when the cookie
was already gone. The client validates that call on `count`, so it retried twice
and threw — a hard error for what is a clean no-op. It now answers
`{ count: 0 }`.

**A device key could be reported as persisted when its transaction aborted.**
`add()` resolved from the IndexedDB *request*, but a commit-time failure
(`QuotaExceededError`) arrives on the *transaction*, after that request has
already succeeded. The binding then lived only in the tab's memory: the next
reload generated a different key, every device proof was rejected, and the
component deleted the session — a sign-in loop that survived one page load at a
time. `add()` now settles on the transaction, so the failure reaches the loud
path the module promises instead of falling back silently.
