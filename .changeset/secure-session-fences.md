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

Also fence the sign-in callback exchange against a sign-out that lands while
the authorization code is being redeemed (the minted session is revoked instead
of installed), report a durable browser-storage removal failure only when a
credential is actually still there, keep the refresh claim whenever Logto's
answer is unknown so a possibly-rotated refresh token is never spent twice,
treat `invalid_client` and the other OAuth configuration faults as transient
instead of deleting every session in the deployment, refuse a logically revoked
session's token for `signOutEverywhere`, and accept Logto's nullable
`lastSignInAt` and its `User.Deleted` payload with no `data` key.
