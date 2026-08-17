---
"convex-logto": patch
---

Fix three defects an adversarial audit of the client half confirmed.

**Non-ASCII ID token claims were garbled in session mode.** The payload was
decoded with bare `atob`, which yields one latin-1 character per byte, so a
`name` of `王小明` arrived as mojibake and `José` as `JosÃ©`. It affected every
snapshot path — cached restore, refresh, callback exchange, and the cookie
transport's SSR seed — while bridge mode rendered the same name correctly, so
migrating from bridge to session mode silently broke non-ASCII names. Both
halves now share one UTF-8 segment decoder.

**One failed durable credential removal wedged `signIn()` and refresh for the
life of the page.** A sign-out that cannot delete a credential correctly fails
loud, but the record of that failure also rejected the storage barrier every
other transition awaits — including the two ways a user recovers. Signing in
minted an authorize URL and then never navigated, and a completed refresh was
reported as `refresh_failed` while the tab held live credentials. The barrier now
waits for writes only; the surviving-credential assertion belongs to sign-out
alone.

**A refresh span could stay open.** When a sign-out, a revocation, or another
tab's sign-out landed mid-refresh, the generation fence discarded the result
without an end phase, so telemetry pairing `refresh_started` with an end event
recorded a refresh that never finished. The new `refresh_abandoned` phase closes
it: exactly one end phase now follows every `refresh_started`.
