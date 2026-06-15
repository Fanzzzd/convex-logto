// Authorization helpers. These are app code, not part of the package — convex-logto
// stays out of your table shape on purpose. Copy/adapt them for your own schema.
import type { QueryCtx, MutationCtx } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";

type Ctx = QueryCtx | MutationCtx;

export function userByAuthId(ctx: Ctx, authId: string) {
  return ctx.db
    .query("users")
    .withIndex("by_authId", (q) => q.eq("authId", authId))
    .unique();
}

/** The validated token identity, or throw. For "must be signed in". */
export async function requireIdentity(ctx: Ctx) {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new Error("unauthenticated");
  return identity;
}

/**
 * The current user's row IF it exists and is active, else `null`. Nullable on
 * purpose: a signed-in user may not have a row yet (first request, before the
 * form/webhook creates it), and a query should not throw mid-provisioning —
 * Convex is reactive, so the UI fills in the moment the row appears.
 */
export async function getActiveUser(ctx: Ctx): Promise<Doc<"users"> | null> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) return null;
  const user = await userByAuthId(ctx, identity.subject);
  return user?.status === "active" ? user : null;
}

/** Like {@link getActiveUser} but throws — for mutations and private data. */
export async function requireActiveUser(ctx: Ctx): Promise<Doc<"users">> {
  const user = await getActiveUser(ctx);
  if (!user) throw new Error("forbidden"); // covers "no row", suspended, and deleted
  return user;
}

/** Require an active user with a specific role. Throws "forbidden" otherwise. */
export async function requireRole(
  ctx: Ctx,
  role: Doc<"users">["role"],
): Promise<Doc<"users">> {
  const user = await requireActiveUser(ctx);
  if (user.role !== role) throw new Error("forbidden");
  return user;
}
