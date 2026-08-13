# convex-logto

Bridges a Logto instance into Convex auth. Two integration shapes share one package: a browser-side OIDC bridge, and a server-side session manager running inside the user's Convex deployment.

## Language

### Integration shapes

**Bridge mode**:
The integration where `@logto/react` owns the OIDC flow and token storage in the browser, and this library only bridges the ID token into Convex.
_Avoid_: SPA mode, legacy mode

**Session mode**:
The integration where the session component owns the OIDC flow server-side (confidential client) and the browser holds only short-lived credentials.
_Avoid_: BFF mode, component mode

### Session mode concepts

**Session component**:
The Convex component that holds Logto refresh tokens, performs the code exchange and refreshes, and manages sessions in its own private tables.

**Session**:
One browser sign-in. Owns exactly one Logto grant and one rotating chain of session tokens, and is killed as a unit.
_Avoid_: family, token chain

**Session token**:
The one-time credential a browser holds for its session. Rotates on every refresh; only the current token (or the previous one inside the reuse window) is accepted.
_Avoid_: refresh token (that's Logto's, held server-side)

**Sign-in transaction**:
The server-held state + PKCE verifier record that lives between building the sign-in URL and the code exchange. Consumed exactly once.
_Avoid_: sign-in session (Logto SDK's term for its browser-side equivalent)

**Reuse window**:
The short grace period (default 10s) during which re-presenting the immediately-previous session token returns the cached rotation result instead of triggering reuse handling.

**Reuse handling**:
What happens when a session token older than the reuse window is presented: the session is killed and its Logto grant revoked.
_Avoid_: family kill

**Reactive revocation**:
Pushing a session's death to connected clients instantly via a Convex subscription, instead of waiting for the short bearer to expire.

**Short bearer**:
The Logto ID token handed to Convex over the WebSocket. The only credential Convex ever sees; its TTL is the hard revocation boundary.

**Federated sign-out**:
Sign-out that also ends the Logto SSO session (redirect to the end-session endpoint), so the next sign-in requires credentials. The default; non-federated sign-out leaves the SSO session alive.
