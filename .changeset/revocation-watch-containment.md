---
"convex-logto": patch
---

Session mode: a failing `sessionValid` subscription no longer blanks the app.
The revocation watcher sits above every error boundary an app can install, and
`useQuery` rethrows a query error during render — so a frontend deployed ahead
of its Convex functions took the whole page down for signed-in users. The error
is now handled as a value: reactive revocation turns off and reports through
`onAuthError`, and sessions still expire on their own schedule.
