import { ConvexError } from "convex/values";
import {
  ORGANIZATIONS_SCOPE,
  ORGANIZATION_ROLES_SCOPE,
  parseOrganizationRole,
} from "./claims";

/**
 * Organization authorization, read from the ID token Convex already validated.
 *
 * Logto maps {@link ORGANIZATIONS_SCOPE} to an `organizations` claim and
 * {@link ORGANIZATION_ROLES_SCOPE} to an `organization_roles` claim, both in the
 * *ID token*, and Convex's `UserIdentity` passes claims it does not recognise
 * through. So membership and roles need no token exchange and no second round
 * trip. They are already in the request Convex authenticated.
 *
 * Organization *permissions* are the exception. Logto issues those only in an
 * organization token, audienced `urn:logto:organization:{id}` and typed
 * `at+jwt`, which Convex rejects. See `docs/adr/0002-token-custody.md`.
 *
 * **These claims are a snapshot, not a lookup.** They were true when Logto
 * issued the ID token and stay frozen until it issues the next one, which is
 * at most the token's own lifetime (Logto's default is an hour). Removing a
 * user from an organization, or taking away a role, therefore does not take
 * effect at once. Nothing here re-reads Logto, by design, because that is what
 * makes the check free. Deleting or suspending the *user* is different. The
 * webhook in `convex-logto/webhooks` revokes their sessions, which is
 * immediate.
 *
 * When a membership change has to bite immediately, do not reach for these
 * helpers. Keep the membership in your own table and check that, so the
 * authorization is a read of current state rather than of a past one.
 * Shortening the ID token's lifetime in Logto narrows the window but never
 * closes it.
 */

/** The slice of a Convex ctx these helpers need. Works in queries, mutations and actions. */
export type LogtoIdentityCtx = {
  auth: {
    getUserIdentity: () => Promise<Record<string, unknown> | null>;
  };
};

function unauthenticated(): ConvexError<{
  kind: "terminal";
  code: string;
  message: string;
}> {
  return new ConvexError({
    kind: "terminal" as const,
    code: "unauthenticated",
    message: "Not signed in.",
  });
}

function forbidden(message: string): ConvexError<{
  kind: "terminal";
  code: string;
  message: string;
}> {
  return new ConvexError({
    kind: "terminal" as const,
    code: "organization_forbidden",
    message,
  });
}

/** Read a claim that should be an array of strings, tolerating a tenant that sends something else. */
function stringArrayClaim(
  identity: Record<string, unknown>,
  claim: string,
): string[] {
  const value = identity[claim];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

/**
 * Organization ids the caller belongs to, or `[]` when the claim is absent.
 *
 * Absent and empty are deliberately the same answer. A deployment that has not
 * requested {@link ORGANIZATIONS_SCOPE} looks exactly like a user who belongs to
 * nothing, and the safe reading of both is "authorize nothing". A helper that
 * threw on a missing scope would turn a configuration gap into an outage, while
 * one that granted access would turn it into a breach.
 */
export async function logtoOrganizations(
  ctx: LogtoIdentityCtx,
): Promise<string[]> {
  const identity = await ctx.auth.getUserIdentity();
  if (identity === null) throw unauthenticated();
  return stringArrayClaim(identity, "organizations");
}

/**
 * Roles the caller holds in one organization, or `[]` when it holds none there.
 *
 * Reads the `organization_roles` claim, whose entries Logto formats
 * `{organizationId}:{roleName}`.
 */
export async function logtoOrganizationRoles(
  ctx: LogtoIdentityCtx,
  organizationId: string,
): Promise<string[]> {
  const identity = await ctx.auth.getUserIdentity();
  if (identity === null) throw unauthenticated();
  return stringArrayClaim(identity, "organization_roles").flatMap((entry) => {
    const parsed = parseOrganizationRole(entry);
    return parsed !== null && parsed.organizationId === organizationId
      ? [parsed.role]
      : [];
  });
}

/**
 * Throw unless the caller belongs to `organizationId`.
 *
 * @example
 * export const listInvoices = query({
 *   args: { organizationId: v.string() },
 *   handler: async (ctx, { organizationId }) => {
 *     await assertOrganizationMember(ctx, organizationId);
 *     // ...
 *   },
 * });
 */
export async function assertOrganizationMember(
  ctx: LogtoIdentityCtx,
  organizationId: string,
): Promise<void> {
  const organizations = await logtoOrganizations(ctx);
  if (!organizations.includes(organizationId)) {
    throw forbidden(
      "Not a member of this organization. If the user should be, check that " +
        `\`${ORGANIZATIONS_SCOPE}\` is among the requested scopes. Without it ` +
        "the claim is absent and every membership check fails.",
    );
  }
}

/**
 * Throw unless the caller holds one of `roles` in `organizationId`.
 *
 * Membership is implied. A role entry names its organization, so holding a role
 * there is stronger evidence than the membership list.
 */
export async function assertOrganizationRole(
  ctx: LogtoIdentityCtx,
  organizationId: string,
  roles: string | readonly string[],
): Promise<void> {
  const wanted = typeof roles === "string" ? [roles] : roles;
  const held = await logtoOrganizationRoles(ctx, organizationId);
  if (!wanted.some((role) => held.includes(role))) {
    throw forbidden(
      `Requires one of [${wanted.join(", ")}] in this organization. If the ` +
        `user should have it, check that \`${ORGANIZATION_ROLES_SCOPE}\` is ` +
        "among the requested scopes. Without it the claim is absent and every " +
        "role check fails.",
    );
  }
}
