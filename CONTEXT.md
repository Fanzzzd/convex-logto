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
The grace period in which a recently superseded Session-token generation is treated as an honest concurrent presentation.

**Reuse handling**:
The containment policy applied when a superseded Session-token generation is presented after its Reuse window.
_Avoid_: family kill

**Reactive revocation**:
Revocation state delivered to a connected client before its Short bearer expires.

**Short bearer**:
The short-lived Logto ID token Convex accepts as an application request credential.

**Subject-level active-session assertion**:
A check that an authenticated bearer's subject has at least one active Session. It does not bind the bearer to a particular Session.

**Federated sign-out**:
Sign-out that also ends the current user agent's Logto SSO session. It does not end sessions on other devices or guarantee a credential prompt on the next sign-in.
