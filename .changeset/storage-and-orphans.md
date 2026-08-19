---
"convex-logto": patch
---

Session mode: two ways a session could be left behind.

Signing in over a live session now revokes the one it replaces. Logto's SSO
cookie makes that a silent redirect, so it is how a user retries anything that
looks like a sign-out — and the replaced row kept a live Logto grant no client
could reach, showing up in the user's own device list until GC took it 190 days
later.

A rejected `localStorage` write no longer leaves the superseded value readable.
Another tab would build its own storage area, read a session token this one had
already rotated away from, and present it — killing the session for every tab
once the reuse window passed.
