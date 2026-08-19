---
"convex-logto": patch
---

Session mode: a device public key is now checked before the authorization code
is spent, and counted against the session-list scan budget. `x` and `y` were the
only caller-supplied strings the component stored without a bound of their own —
and the one field `sessionReadCost` did not count — so a hand-driven `callback`
could store near-1 MiB session rows that the list scan measured at ~512 bytes.
