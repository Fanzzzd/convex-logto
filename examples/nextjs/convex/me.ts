import { query } from "./_generated/server";

export const me = query({
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;
    // identity.subject = Logto user id, plus email/name/etc. from the ID token.
    return { id: identity.subject, email: identity.email, name: identity.name };
  },
});
