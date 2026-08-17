---
"convex-logto": minor
---

Session mode: add a "where am I signed in" surface. `logtoSessionApi(...)` now
returns `listSessions` / `renameSession` / `revokeSession`, and both session
providers expose them from `useLogtoAuth()` alongside a new optional
`clientDescriptor` prop that stamps an advisory, app-supplied device description
on the session at sign-in (the library never reads a User-Agent or IP).

All three authenticate exactly as `signOutEverywhere` does: the subject comes
only from the caller's presented live session token, so another subject's
`sessionId` — or one already killed by a revocation watermark — raises the normal
terminal `session_not_found`. Labels are normalized (whitespace collapsed,
control characters and bidi overrides stripped) and rejected past 64 code points
rather than truncated. The list returns at most 16 sessions, newest first, with
`truncated` when there are more.

The cookie transport gains a `sessions` route multiplexing the three operations,
and forwards the client descriptor through `callback`. Re-export the three new
functions from your `convex/auth.ts`; a deployment that has not yet fails with
the same explicit upgrade message `signOutEverywhere` uses.
