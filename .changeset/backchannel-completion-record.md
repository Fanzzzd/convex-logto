---
"convex-logto": patch
---

Stop back-channel logout from answering 200 for a revocation that never
committed.

The endpoint claimed the logout token's `jti` *before* dispatching the
revocation, and a claim only proves that a delivery started. If the first
delivery failed after claiming and its release also failed — the release is
best-effort, since there is nothing left to do about it — every Logto retry for
the next 24 hours was answered 200 without revoking anything, and the user
stayed signed in through a completed OIDC back-channel logout.

Delivery records now carry a completion marker. A replay is answered without
work only once some delivery got as far as recording completion; an unfinished
claim is redone, which is safe because revocation is idempotent — the watermark
takes the max of what it already holds, and the drain deletes rows that are
already dead. Suppressing *completed* replays still matters and is unchanged: a
`sub`-only logout token revokes whatever the subject has at the moment it runs,
so replaying one after the user signs in again would sign them out a second
time.

The webhook route keeps answering a claimed delivery without redoing it, since
an app's sync handlers write to its own tables and are not idempotent.
