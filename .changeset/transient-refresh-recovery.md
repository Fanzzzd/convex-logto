---
"convex-logto": patch
---

Session mode: a transient refresh failure no longer strands the tab signed-out
until reload. Keeping the session token only helps if something presents it
again — and nothing did, because Convex stops asking for a token after one
failure and only re-arms when `isAuthenticated` flips. The engine now retries on
its own backoff and flips its snapshot back on success, so a tunnel hiccup or a
laptop waking before its network recovers on its own.
