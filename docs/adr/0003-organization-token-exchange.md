# An Organization or Resource token exchange runs inside the session's refresh claim, and keeps the ID token it returns

Session mode's central invariant is that a Logto refresh token is never presented twice. Logto's reuse detection destroys the whole grant, and sibling Sessions of the same Logto SSO session share a grant, so one double-presentation signs out a user everywhere. A single claimed `refresh` grant enforces that invariant. Adding [Organization tokens and Resource tokens](./0002-token-custody.md) asks whether the exchange is a second consumer of the refresh token, which would have to take the same claim, or something that can run beside it.

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

Neither half looks at what the grant was *for*, and `organization_id` and `resource` go through the one shared `refresh_token` handler that contains the rotation branch. Measuring it confirms that. On a **public** client, where the inner rule rotates unconditionally, a plain refresh, an Organization token and a Resource token each rotated the refresh token, and so did the plain refresh that followed them.

That measurement had to be arranged, and arranging it is the point. A confidential client rotates only past 70% of the refresh token's lifetime, so *every* observation against one says "no rotation" no matter what the rule is. An implementation that ran the exchange outside the claim would therefore pass every test, every staging soak and most of production, and start destroying grants only once real refresh tokens aged into their last 30%. Observing a fresh token cannot establish correctness here; the public client is the configuration in which the question is answerable at all (`e2e/probe-org-tokens.mjs`).

More answers from the same run shape the API rather than the concurrency:

- **Every `refresh_token` grant returns an `id_token`**, including the Organization and Resource variants, so an exchange also mints a fresh Short bearer, and discarding it would throw away a free refresh and leave the Session ageing faster than it needs to. The exchange persists it like any other refresh outcome.
- **Membership and organization roles need no exchange at all.** The ID token carried `organizations: ["<id>"]` and `organization_roles: ["<id>:<role>"]`, confirming what [ADR 0002](./0002-token-custody.md) assumes.
- **Organization *permissions* cannot be reached through this exchange at all.** A later measurement (2026-08-21, through the component this time rather than raw OIDC) found the minted Organization token's own `scope` claim empty, for a user holding a role that grants `e2e:manage`. Logto issues `availableScopes ∩ requestedScopes`, the user's organization permissions intersected with the request's scope set, which defaults to the *grant's* scopes:

  ```js
  const scope = params.scope ? requestParamScopes : refreshToken.scopes;
  const issuedScopes = availableScopes.filter((name) => scope.has(name)).join(" ");
  ```

  Organization permissions are not OIDC scopes. They are absent from `scopes_supported`, so oidc-provider drops them from the authorize request and they can never be in `refreshToken.scopes`. The intersection is therefore always empty, and the subset check above it refuses a token request naming one (`invalid_scope`, "refresh token missing requested scope"). Authorization on organization permissions has to come from `organization_roles`, which is free and in the ID token; the Organization token remains the right thing to *send* to a service that validates the `urn:logto:organization:<id>` audience itself. A Resource token is different, and does carry the scopes its grant named.
- **A rejected grant is not a spend.** Presenting a refresh token for an unregistered resource answers `invalid_target` and leaves the token usable, checked by replaying it right afterwards. This is what makes releasing the claim on a terminal token-endpoint failure safe rather than a guess.

A resource, finally, must be named by the **`resource` parameter at authorization time**. Requesting the resource's *scope* instead does not work; Logto rejected that combination with `invalid_target`, and the `resource` parameter alone succeeded. So `resources` is a sign-in-time input, and `scopes` is a separate one. A grant that named the resource but not its scopes yields a token with no scopes at all.

## Consequences

- The exchange is not a fast path. It queues behind an in-flight refresh on the same Session, and inherits the claim's whole failure vocabulary, including "outcome unknown, keep the claim and let it age into `claim-expired`".
- `resources` must be declared before sign-in, and the scopes wanted from those resources belong in `scopes`. An app that discovers it needs a new API resource has to sign the user in again; there is no way to widen a grant in place.
- An Organization token exchange can replace a Session's stored ID token. Anything reasoning about *why* the Short bearer changed must not assume a plain refresh caused it.
- Organization membership and role checks stay synchronous and free (`logtoOrganizations`, `assertOrganizationRole`), and they are the *only* organization authorization this library can offer, because an Organization token's scopes are always empty. Never use `getOrganizationTokenClaims(...).scopes` as a permission check; the docs say so in a warning callout.
- The rotation toggle is a deployment's to set, and turning it *off* does not make the exchange safe to run outside the claim; it makes the bug invisible instead of absent.
