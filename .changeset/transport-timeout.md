---
"convex-logto": patch
---

Session mode: bound every session request, and let a fresh transient failure
always arm a fresh recovery. A request that never answered parked the in-flight
refresh forever — every later token fetch merged into it — and a recovery loop
left over from before a sign-out could swallow the arming of a new one for up to
thirty seconds.
