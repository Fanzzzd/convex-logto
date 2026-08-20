# An Organization or Resource token exchange runs inside the session's refresh claim, and keeps the ID token it returns

Session mode's central invariant is that a Logto refresh token is never presented twice: Logto's reuse detection destroys the whole grant, and a grant is shared by sibling Sessions of the same Logto SSO session, so one double-presentation signs out a user everywhere. That invariant is enforced by a single claimed `refresh` grant. Adding [Organization tokens and Resource tokens](./0002-token-custody.md) asks whether the exchange is a second consumer of the refresh token — which would have to take the same claim — or something that can run beside it.

It is a second consumer. Logto rotates on a rule that is entirely blind to what the grant was *for*:

```js
// Logto's oidc-provider defaults, read out of the running image
const rotateRefreshToken = (ctx) => {
  const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;
  if (!refreshToken || !client) return false;
  if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) return false;
  if (client.clientAuthMethod === "none" && !refreshToken.isSenderConstrained()) return true;
  return refreshToken.ttlPercentagePassed() >= 70;
};
```

and the rotation branch lives in the one shared `refresh_token` grant handler that `organization_id` and `resource` also go through. So an Organization token exchange rotates exactly when a plain refresh would: never for most of a confidential client's refresh-token lifetime, and then — past 70% of it — every time. That shape is the trap. An implementation that ran the exchange outside the claim would pass every test, every staging soak and most of production, and start destroying grants only once real refresh tokens aged into their last 30%. Correctness here cannot be established by observing a fresh token, which is why this was settled against a live deployment and against the source rather than from the observed behaviour alone (`e2e/probe-org-tokens.mjs`).

The same probe answered a second question. Every `refresh_token` grant returns an `id_token`, including the Organization and Resource variants — so an exchange also mints a fresh Short bearer, and discarding it would throw away a free refresh and leave the session ageing faster than it needs to. The exchange persists it like any other refresh outcome.

Two facts from the same run shape the surface rather than the concurrency:

- **Membership and organization roles need no exchange at all.** The ID token carried `organizations: ["<id>"]` and `organization_roles: ["<id>:<role>"]`, confirming what [ADR 0002](./0002-token-custody.md) assumes. Only fine-grained organization *permissions* require a token.
- **A Resource token must be asked for at authorization time.** Requesting `resource` on a grant that never mentioned it fails `invalid_target`, so `resources` is a sign-in-time input, not a per-call argument — which is also why `@logto/browser` takes `resources` in its config.

## Consequences

- The exchange is not a fast path. It queues behind an in-flight refresh on the same Session, and inherits the claim's whole failure vocabulary — including "outcome unknown, keep the claim and let it age into `claim-expired`".
- `resources` must be declared before sign-in. An app that discovers it needs a new API resource has to sign the user in again; there is no way to widen a grant in place.
- A Session's stored ID token can be replaced by an Organization token exchange. Anything reasoning about *why* the Short bearer changed must not assume a plain refresh caused it.
- Organization membership and role checks stay synchronous and free (`logtoOrganizations`, `assertOrganizationRole`). Only permission checks pay for a round trip, and the difference is worth documenting because it is invisible from the call site.
