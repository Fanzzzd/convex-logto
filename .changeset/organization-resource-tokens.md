---
"convex-logto": minor
---

Session mode: organization and API-resource tokens, `fetchUserInfo`, `getIdToken`

`useLogtoAuth()` gains `getOrganizationTokenClaims(organizationId)`,
`getAccessTokenClaims(resource)`, `fetchUserInfo()` and `getIdToken()`, closing
the last gap against `@logto/react`'s `useLogto()`. The component mints the
token from the session's Logto refresh token and returns **what it authorizes**
— nothing long-lived enters `window`. `exposeAccessTokens: true` on
`logtoSessionApi()` opts into the token string itself, for a caller that must
reach a non-Convex API from the browser; without it the token-returning methods
reject by name rather than quietly returning nothing.

Re-export the two new actions (`exchangeToken`, `fetchUserInfo`) from your
`logtoSessionApi(...)` module to enable them. A module that has not been
updated keeps working — the methods report the missing export instead.

Organization membership and *roles* still need none of this: Logto puts them in
the ID token, so `assertOrganizationRole` costs no round trip. This is for
fine-grained organization permissions and registered API resources.

`resources` on `logtoSessionApi()` is no longer a no-op. It is the input to the
resource exchange — and it has to be set before sign-in, because Logto refuses
to issue a token for a resource the grant never named.

The exchange runs inside the same claim as `refresh`, so it can answer the
transient `refresh_in_flight` and must be retried like any other. That is not
caution: Logto rotates the refresh token on a rule blind to what the grant was
for, and only past 70% of its lifetime, so an exchange outside the claim would
look correct until real tokens aged and then start tripping reuse detection on a
grant sibling sessions share. Verified against a live deployment and against
Logto's source; `docs/adr/0003-organization-token-exchange.md` records it.
