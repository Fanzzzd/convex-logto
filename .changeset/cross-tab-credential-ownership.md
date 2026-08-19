---
"convex-logto": patch
---

Session mode: a revoked session no longer signs every other tab out.

The session credential is shared by every tab on an origin, but the session id an engine watches is its own. When another tab signed in it replaced that credential, and a revocation of the *previous* session then cleared storage — deleting the credential the new session was reached by, signing every tab out and orphaning the row that was just created. An engine now checks the stored session id against the one it is holding and adopts a newer credential instead of destroying it.

The revoke of a session that a fresh sign-in replaced is also awaited before the post-callback navigation. With no `navigate` prop that navigation is `location.replace`, which tears down the in-flight request, so the cleanup was unreliable in exactly the default configuration; it is bounded by the transport deadline and still reported rather than thrown.
