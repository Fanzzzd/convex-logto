---
"convex-logto": minor
---

Fence refresh claims and client auth generations so stale refreshes cannot
overwrite or resurrect a signed-out session. Harden persisted-session recovery,
durable browser sign-out, runtime response validation, bounded session
revocation, and recent token generation handling. Recheck logical revocation
markers before committing refreshed credentials. Require device proof before
revoking a bound session and
avoid grant-wide RFC 7009 calls when abandoning one local Session, because
Logto grants may be shared by sibling Sessions. Validate Logto and navigation
URLs, stream-limit public request bodies, and bound JWKS fetch time, size, key
count, concurrent refreshes, token-endpoint responses, and browser
cookie-transport responses. Add
`assertSubjectHasActiveSession` as the accurately named subject-level policy
check; retain
`assertUserHasActiveSession` as a deprecated compatibility alias.
