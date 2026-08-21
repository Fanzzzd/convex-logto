---
"convex-logto": patch
---

Say what organization claims actually are, and stop claiming one scope implies
the other.

`assertOrganizationMember` / `assertOrganizationRole` read the ID token Convex
already validated, which is what makes them free — and also means they read a
**snapshot**. The claims were true when the token was issued and stay frozen
until the next one is, at most the token's own lifetime (Logto's default is an
hour), so removing someone from an organization or taking a role away does not
take effect at once. Deleting or suspending the *user* is different: the webhook
revokes their sessions immediately. Documented on the helpers and in the API
reference, with the mitigation — when a membership change has to bite
immediately, check your own table instead.

`ORGANIZATION_ROLES_SCOPE`'s doc claimed it implies `ORGANIZATIONS_SCOPE`. It
does not: Logto advertises the two separately in `scopes_supported`, maps each to
its own claim, and a grant carries exactly what was requested. A deployment that
followed that advice and requested only the roles scope has no `organizations`
claim, so every `assertOrganizationMember` call denies — for everyone, because a
missing claim is deliberately indistinguishable from a user who belongs to
nothing. The failure names the missing scope, which is the only thing separating
this from an unexplained outage.
