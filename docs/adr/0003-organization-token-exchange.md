# An Organization or Resource token exchange runs inside the session's refresh claim, and keeps the ID token it returns

Session mode's central invariant is that a Logto refresh token is never presented twice: Logto's reuse detection destroys the whole grant, and a grant is shared by sibling Sessions of the same Logto SSO session, so one double-presentation signs out a user everywhere. That invariant is enforced by a single claimed `refresh` grant. Adding [Organization tokens and Resource tokens](./0002-token-custody.md) asks whether the exchange is a second consumer of the refresh token — which would have to take the same claim — or something that can run beside it.

It is a second consumer, and the grant type has nothing to do with it. Logto gates rotation on a per-application toggle and then defers to oidc-provider's rule:

```js
// Logto's provider config, read out of the running image
rotateRefreshToken: (ctx) => {
  const { Client: client } = ctx.oidc.entities;
  if (!(client?.metadata().rotateRefreshToken
        ?? customClientMetadataDefault.rotateRefreshToken)) return false;
  return defaults.rotateRefreshToken(ctx);   // oidc-provider's:
},                                           //   public client            → always
                                             //   confidential, ≥70% TTL   → rotate
```

Neither half looks at what the grant was *for*, and `organization_id` and `resource` go through the one shared `refresh_token` handler that contains the rotation branch. Measuring it confirms that: on a **public** client — where the inner rule rotates unconditionally — a plain refresh, an Organization token and a Resource token each rotated the refresh token, and so did the plain refresh that followed them.

That measurement had to be arranged, and arranging it is the point. A confidential client rotates only past 70% of the refresh token's lifetime, so *every* observation against one says "no rotation" no matter what the rule is. An implementation that ran the exchange outside the claim would therefore pass every test, every staging soak and most of production, and start destroying grants only once real refresh tokens aged into their last 30%. Correctness here cannot be established by observing a fresh token; the public client is the configuration in which the question is answerable at all (`e2e/probe-org-tokens.mjs`).

Three more answers from the same run shape the surface rather than the concurrency:

- **Every `refresh_token` grant returns an `id_token`**, including the Organization and Resource variants — so an exchange also mints a fresh Short bearer, and discarding it would throw away a free refresh and leave the Session ageing faster than it needs to. The exchange persists it like any other refresh outcome.
- **Membership and organization roles need no exchange at all.** The ID token carried `organizations: ["<id>"]` and `organization_roles: ["<id>:<role>"]`, confirming what [ADR 0002](./0002-token-custody.md) assumes. Only fine-grained organization *permissions* require a token.
- **A rejected grant is not a spend.** Presenting a refresh token for an unregistered resource answers `invalid_target` and leaves the token usable — checked by replaying it immediately afterwards. This is what makes releasing the claim on a terminal token-endpoint failure safe rather than a guess.

A resource, finally, must be named by the **`resource` parameter at authorization time**. Requesting the resource's *scope* instead does not work — that combination was rejected `invalid_target`, and the `resource` parameter alone succeeded — so `resources` is a sign-in-time input, and `scopes` is a separate one: a grant that named the resource but not its scopes yields a token with no scopes at all.

## Consequences

- The exchange is not a fast path. It queues behind an in-flight refresh on the same Session, and inherits the claim's whole failure vocabulary — including "outcome unknown, keep the claim and let it age into `claim-expired`".
- `resources` must be declared before sign-in, and the scopes wanted from those resources belong in `scopes`. An app that discovers it needs a new API resource has to sign the user in again; there is no way to widen a grant in place.
- A Session's stored ID token can be replaced by an Organization token exchange. Anything reasoning about *why* the Short bearer changed must not assume a plain refresh caused it.
- Organization membership and role checks stay synchronous and free (`logtoOrganizations`, `assertOrganizationRole`). Only permission checks pay for a round trip, and the difference is worth documenting because it is invisible from the call site.
- The rotation toggle is a deployment's to set, and turning it *off* does not make the exchange safe to run outside the claim: it makes the bug invisible instead of absent.
