---
"convex-logto": patch
---

Session mode: a sign-in no longer dies on one bad packet.

The callback exchange is single-use, so it is never blindly retried once the deployment has answered — the component consumes the sign-in transaction before it contacts Logto, and a second attempt could only report `transaction_not_found`, burying the real diagnosis. But a failure that never reached the deployment consumed nothing, and losing a sign-in to a dropped connection or a transport timeout is worse than an attempt that finds nothing. A non-`ConvexError` failure is now retried exactly once; if that retry reports the transaction is gone, the first attempt did land after all and *its* error is the one reported.

Also: the sign-in-path error suffix no longer claims "the authorization code is spent" — a `logto_unreachable` may never have reached Logto. What is always true is that the attempt is unrepeatable. The reactive-revocation failure report is deduped against the underlying query error rather than the wrapper built inside the effect.
