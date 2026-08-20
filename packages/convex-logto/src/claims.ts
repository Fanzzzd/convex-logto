/**
 * The ID token claims this package hands back as `user`.
 *
 * One type for all four entries. Bridge mode used to return the Logto SDK's
 * `IdTokenClaims` and session mode a bare `Record<string, unknown>`, so the same
 * token produced two different types — `user?.email` compiled in one mode and
 * not the other — while the whole point of session mode is that you can move to
 * it by changing an import.
 *
 * Display only. Nothing here is verified in the browser; Convex validates the
 * token, and a Convex function reads the same claims through
 * `ctx.auth.getUserIdentity()`, which is the only place they are trustworthy.
 *
 * The named claims are the ones Logto maps from a standard scope. The index
 * signature keeps everything else reachable, because a tenant can add custom
 * claims this package has never heard of.
 */
export type LogtoUserClaims = {
  /** Logto's stable user id. Always present. */
  sub: string;
  /** Scope `email`. */
  email?: string;
  /** Scope `email`. */
  email_verified?: boolean;
  /** Scope `phone`. */
  phone_number?: string;
  /** Scope `phone`. */
  phone_number_verified?: boolean;
  /** Scope `profile`. */
  name?: string;
  /** Scope `profile`. */
  username?: string;
  /** Scope `profile`. */
  picture?: string;
  /** Scope `profile`. Seconds since the epoch. */
  updated_at?: number;
  /** Scope `custom_data`. */
  custom_data?: unknown;
  /** Scope `roles`. Tenant-wide roles, not organization roles. */
  roles?: string[];
  /**
   * Scope {@link ORGANIZATIONS_SCOPE}. Ids of the organizations this subject
   * belongs to.
   */
  organizations?: string[];
  /**
   * Scope {@link ORGANIZATION_ROLES_SCOPE}. Roles held within organizations,
   * each formatted `{organizationId}:{roleName}`.
   *
   * Roles, not permissions: Logto puts fine-grained organization permissions
   * only in an organization token, which Convex cannot accept.
   */
  organization_roles?: string[];
} & Record<string, unknown>;

/** Request organization membership in the ID token. */
export const ORGANIZATIONS_SCOPE = "urn:logto:scope:organizations";

/** Request organization roles in the ID token. Implies {@link ORGANIZATIONS_SCOPE}. */
export const ORGANIZATION_ROLES_SCOPE = "urn:logto:scope:organization_roles";

/**
 * Read a decoded payload as claims.
 *
 * A JWT payload is `Record<string, unknown>` as far as any decoder knows; this
 * is the single place that shape is narrowed, so the assumption is stated once
 * rather than cast at four call sites. `sub` is the one claim an ID token cannot
 * omit, so a payload without it is not one.
 */
export function asUserClaims(
  payload: Record<string, unknown> | null | undefined,
): LogtoUserClaims | undefined {
  if (payload === null || payload === undefined) return undefined;
  const { sub } = payload;
  // Rebuilt rather than asserted: `sub` is the only claim the type promises, so
  // proving it is the whole narrowing. The copy is shallow and happens once per
  // token, not per render.
  return typeof sub === "string" ? { ...payload, sub } : undefined;
}

/**
 * Split an `organization_roles` entry into its organization and role halves.
 *
 * Logto formats them `{organizationId}:{roleName}`. Organization ids contain no
 * colon, so the first one separates the two; a role name that contains a colon
 * survives intact.
 */
export function parseOrganizationRole(
  entry: string,
): { organizationId: string; role: string } | null {
  const separator = entry.indexOf(":");
  if (separator <= 0 || separator === entry.length - 1) return null;
  return {
    organizationId: entry.slice(0, separator),
    role: entry.slice(separator + 1),
  };
}
