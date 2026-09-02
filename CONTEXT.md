# convex-logto

Vocabulary for the Logto-to-Convex authentication boundary.

## Language

### Integration shapes

**Bridge mode**:
An integration shape in which the frontend owns the Logto authorization flow and Convex receives the resulting ID token.
_Avoid_: SPA mode, legacy mode

**Session mode**:
An integration shape in which the application backend owns durable Logto authorization state and the frontend holds short-lived application credentials.
_Avoid_: BFF mode, component mode

### Session concepts

**Session component**:
The session-mode boundary that owns application Sessions and server-held Logto credentials.

**Session**:
An application sign-in context associated with a subject and Logto authorization state. Multiple Sessions may correspond to one Logto SSO session.
_Avoid_: family, token chain

**Logto SSO session**:
Logto's identity-provider login context, optionally identified by the OIDC `sid`. It is distinct from an application Session.

**Session token**:
A rotating application credential for a Session, issued as a sequence of generations. It is distinct from a Logto refresh token and is not strictly single-use during the Reuse window.
_Avoid_: refresh token, one-time token

**Session-token generation**:
One value in a Session token's rotating sequence.

**Sign-in transaction**:
A time-bounded authorization attempt that correlates sign-in initiation with callback completion.
_Avoid_: sign-in session

**Reuse window**:
The grace period in which the component treats a recently superseded Session-token generation as an honest concurrent presentation.

**Reuse handling**:
The containment policy the component applies when a client presents a superseded Session-token generation after its Reuse window.
_Avoid_: family kill

**Reactive revocation**:
Revocation state delivered to a connected client before its Short bearer expires.

**Short bearer**:
The short-lived Logto ID token Convex accepts as an application request credential.

**Subject-level active-session assertion**:
A check that an authenticated bearer's subject has at least one active Session. It does not bind the bearer to a particular Session.

### Organization concepts

**Organization**:
A Logto grouping that a Subject may belong to many of, each carrying its own roles and permissions. Orthogonal to Session. One Session can act in any Organization its Subject belongs to, and Organization membership neither creates nor ends a Session.
_Avoid_: tenant, workspace, team (those are the *application's* words for whatever it maps an Organization onto)

**Organization membership**:
The list of Organizations a Subject belongs to. It travels in the Short bearer as an `organizations` claim, so it is readable wherever the Short bearer is, including inside Convex functions, which pass unrecognised claims through. Because it travels *in* the bearer it is a Claim snapshot, not a lookup.

**Organization role**:
A named role a Subject holds within one Organization. Like membership it travels in the Short bearer, as an `organization_roles` claim. Distinct from an Organization permission, which travels only in an Organization token.

**Claim snapshot**:
A value that was true when Logto issued the Short bearer and stays frozen until it issues the next one. Organization membership and Organization roles are claim snapshots. A Subject removed from an Organization keeps the claim until Logto issues a fresh Short bearer. Distinct from Reactive revocation, which arrives *before* the Short bearer expires; nothing reactive exists for Organization membership.
_Avoid_: cached, stale (both suggest a copy that could have been refreshed; this one could not)

**Organization permission**:
A fine-grained capability within one Organization. The only part of Logto's organization model that the Short bearer cannot carry.
_Avoid_: organization scope (that is the OIDC-level word for how it is requested, not for the thing)

**Organization token**:
A resource-scoped access token for one Organization, audienced to that Organization rather than to the application. Convex cannot accept it, because it is not the Short bearer. Distinct from Organization membership, which needs no token at all.
_Avoid_: org JWT, organization credential

**Resource token**:
Any access token Logto issues for a registered API resource, of which an Organization token is one shape. Never a request credential for Convex.
_Avoid_: API token, service token

**ID token cookie**:
An opt-in companion cookie carrying the Short bearer itself, written only by a route handler and readable during a server render. It mints nothing and rotates nothing, which is what lets a renderer that cannot set cookies read an identity. Distinct from the Session-token cookie, which is a credential the server rotates.
_Avoid_: SSR token, auth cookie (the deployment has two cookies; naming either one "the" auth cookie loses the distinction that matters)

**Token custody**:
Which side of the deployment boundary a token is allowed to reach. Session mode's default custody is server-only for every token except the Short bearer; the Logto refresh token has no custody setting because it never leaves the component.

### Sign-out

**Federated sign-out**:
Sign-out that also ends the current user agent's Logto SSO session. It does not end sessions on other devices or guarantee a credential prompt on the next sign-in.
