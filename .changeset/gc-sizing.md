---
"convex-logto": patch
---

Component: GC drains abandoned sign-ins 128 at a time instead of 4, and sweeps
revocation watermarks once per run rather than once per chained batch. The old
batch size was sized against a near-1 MiB `transactions` row that
`SIGN_IN_URL_MAX_LENGTH` has since made impossible, and every extra sweep
re-reads session documents.
