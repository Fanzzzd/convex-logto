---
"convex-logto": minor
---

Add `forceRefresh` to every token-exchange method, and make `fetchUserInfo`
recover from a rejected cached token on its own.

The component caches a minted Organization or Resource token until it expires,
so a token the *resource server* has stopped accepting — a revoked grant, a
clock that drifted past the skew allowance, an organization whose roles changed
— kept being served for the rest of its lifetime, and the caller had no way to
say "not that one". `getOrganizationTokenClaims`, `getAccessTokenClaims`,
`getOrganizationToken`, `getAccessToken` and `fetchUserInfo` now take a final
`{ forceRefresh: true }` that skips the cache and replaces what was there. It
costs a Logto grant, so it belongs on the failure path.

`fetchUserInfo` is the one caller inside the library that consumes a minted
token, so it does that itself: when Logto answers `401`/`403` for a token that
came from the cache it mints once and retries. A rejection of a token it just
minted is a deployment fault, and it does not spend a second grant on one.

Also: a userinfo response that is not JSON no longer reports as
`logto_unreachable`, which sent readers looking at the network for a deployment
answering wrongly.
