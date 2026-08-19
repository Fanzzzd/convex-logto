---
"convex-logto": patch
---

Session mode: a failed sign-in now reports what actually went wrong. The
component consumes the sign-in transaction before it contacts Logto, so the
client's retry could only ever come back with `transaction_not_found` — and a
wrong `LOGTO_CLIENT_SECRET` was reported as a stale or replayed callback. The
exchange is no longer retried, and a token-endpoint failure on the sign-in path
keeps Logto's own error code and message.
