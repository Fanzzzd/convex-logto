---
"convex-logto": minor
---

One `useLogtoAuth()` shape across all four entries, and organization authorization.

**Breaking.** The four entries disagreed about their own API, which mattered most for the one migration the package exists to make easy — bridge mode to session mode:

- `user` was the Logto SDK's `IdTokenClaims` in bridge mode and a bare `Record<string, unknown>` in session mode, so the same ID token produced two types and `user?.email` compiled in one mode and not the other. Both now return `LogtoUserClaims`: standard claims named, everything else still reachable through an index signature — which bridge mode's interface never had, so a custom claim was unreachable there.
- `signOut(postLogoutRedirectUri?: string)` becomes `signOut({ postLogoutRedirectUri? })` in bridge mode, matching session mode. Native's `signOut()` takes the same options object and can now pass a post-logout redirect through to `@logto/rn`.
- Native's `signIn(redirectUri?: string)` becomes `signIn({ redirectUri? })`.
- The deprecated `signIn(redirectUri: string)` overload on the web bridge is removed. A redirect URI whose path was not `callbackPath` produced a sign-in nothing handled, and warning about it afterwards was never a fix.

**New: organization authorization, with no extra round trip.** Logto maps `urn:logto:scope:organizations` to an `organizations` claim and `urn:logto:scope:organization_roles` to an `organization_roles` claim *in the ID token*, and Convex passes claims it does not recognise through to `ctx.auth.getUserIdentity()`. So membership and roles are already inside the request Convex authenticated:

```ts
import { assertOrganizationRole } from "convex-logto";

export const deleteInvoice = mutation({
  args: { organizationId: v.string(), id: v.id("invoices") },
  handler: async (ctx, { organizationId, id }) => {
    await assertOrganizationRole(ctx, organizationId, ["admin", "billing"]);
    await ctx.db.delete(id);
  },
});
```

Also exported: `logtoOrganizations`, `logtoOrganizationRoles`, `assertOrganizationMember`, `parseOrganizationRole`, `ORGANIZATIONS_SCOPE`, `ORGANIZATION_ROLES_SCOPE`. A role check matches on the organization *and* the role, so one organization's `viewer` cannot authorize another's; and a missing scope authorizes nothing rather than everything, with the scope named in the failure so a configuration gap does not read as a denial.

Organization *permissions* are not covered: Logto issues those only in an organization token, audienced `urn:logto:organization:{id}` and typed `at+jwt`, which Convex rejects. See `docs/adr/0002-token-custody.md`.
