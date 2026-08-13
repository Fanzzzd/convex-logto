import { assertUserHasActiveSession } from "convex-logto";
import { components } from "./_generated/api";
import { query } from "./_generated/server";

export const me = query({
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;
    // identity.subject = Logto user id, plus email/name/etc. from the ID token.
    return { id: identity.subject, email: identity.email, name: identity.name };
  },
});

// Server-side revocation enforcement: an ID token stays cryptographically valid
// until it expires, so sensitive functions can additionally require a LIVE
// session — revoked users are cut off immediately, not at token expiry.
export const sensitive = query({
  handler: async (ctx) => {
    await assertUserHasActiveSession(ctx, components.logto);
    return { secret: "only holders of a live session see this" };
  },
});
