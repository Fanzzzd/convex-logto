// Organization authorization, read straight from the ID token Convex validated.
//
// Nothing here talks to Logto. `urn:logto:scope:organizations` and
// `urn:logto:scope:organization_roles` (both requested in `auth.ts`) put an
// `organizations` and an `organization_roles` claim in the ID token, and Convex
// passes claims it does not recognise through to `getUserIdentity()` — so
// membership and roles are already inside the request, for free.
//
// The cost of "free" is that they are a *snapshot*: true when the token was
// issued and frozen until the next one is. A user removed from an organization
// keeps these claims until then. When a membership change has to bite
// immediately, keep membership in your own table and check that instead.
import { v } from "convex/values";
import {
  assertOrganizationRole,
  logtoOrganizationRoles,
  logtoOrganizations,
} from "convex-logto";
import { query } from "./_generated/server";

/** The role `adminOnly` requires. `e2e/provision.mjs` creates one with this name. */
const ADMIN_ROLE = "admin";

export const organizations = query({
  handler: async (ctx) => await logtoOrganizations(ctx),
});

export const roles = query({
  args: { organizationId: v.string() },
  handler: async (ctx, { organizationId }) =>
    await logtoOrganizationRoles(ctx, organizationId),
});

/**
 * The shape a real authorization check takes: the *function* names the role it
 * requires, and the caller only names the organization it is acting in.
 *
 * A role check matches on the organization **and** the role, so one
 * organization's `admin` cannot authorize another's.
 */
export const adminOnly = query({
  args: { organizationId: v.string() },
  handler: async (ctx, { organizationId }) => {
    await assertOrganizationRole(ctx, organizationId, ADMIN_ROLE);
    return { secret: `only ${ADMIN_ROLE}s of ${organizationId} see this` };
  },
});
