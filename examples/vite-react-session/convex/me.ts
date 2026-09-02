import { assertSubjectHasActiveSession } from "convex-logto";
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

// Subject-level revocation enforcement. An ID token stays cryptographically
// valid until it expires, so sensitive functions can also require that its
// subject still has an active component session. This is not a proof that the
// bearer came from one particular browser session.
export const sensitive = query({
  handler: async (ctx) => {
    await assertSubjectHasActiveSession(ctx, components.logto);
    return { secret: "only subjects with an active session see this" };
  },
});
