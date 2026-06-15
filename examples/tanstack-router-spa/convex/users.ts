import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import {
  requireActiveUser,
  requireIdentity,
  requireRole,
  userByAuthId,
} from "./authz";

const roleValidator = v.union(v.literal("user"), v.literal("admin"));

// What the dashboard reads. Discriminated so the client knows which UI to show:
//   null                 -> signed out
//   { onboarded: false } -> signed in, no row yet -> show the role-picker form
//   { onboarded: true }  -> has a row -> show role/status (PII only while active)
export const myProfile = query({
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;
    const user = await userByAuthId(ctx, identity.subject);
    if (!user) return { onboarded: false as const };
    const active = user.status === "active";
    return {
      onboarded: true as const,
      role: user.role,
      status: user.status,
      // Expose identity details only for an active account — a suspended/deleted
      // row has its PII scrubbed, so don't rehydrate it from the token.
      email: active ? (user.email ?? identity.email ?? null) : null,
      name: active ? (user.name ?? identity.name ?? null) : null,
    };
  },
});

// First-login onboarding: create the caller's row, keyed by their token subject.
// Get-or-create, so calling it twice is safe (and races resolve under Convex OCC).
//
// This — NOT the webhook — is what creates rows. `User.Created` doesn't fire for a
// user who already existed in Logto, so a webhook-only approach would leave them
// permanently row-less. An authenticated mutation is the reliable creator.
//
// Trust boundary: we create the row `active` on the strength of the caller's token,
// which Convex already verified (signature + expiry). Like all JWT auth, a token
// stays valid until it expires (≤ its TTL) even if Logto suspends/deletes the user
// afterward. For someone already onboarded the webhook flips their status the moment
// Logto fires the event; a user still in this pre-onboarding window could self-
// provision an `active` row until their token lapses. Closing that residual gap
// needs short token lifetimes or a live Logto check (Management API) — out of scope
// for a demo, but the reason a webhook tombstone is the WRONG fix: it would mint a
// row for every Logto user ever suspended/deleted, even ones who never used the app.
//
// DEMO ONLY: taking `role` from the client lets you try the gate from both sides.
// A real app drops the arg, always creates `role: "user"`, and grants admin OUT OF
// BAND (a Convex dashboard mutation, an internal mutation, or an allowlist).
export const completeOnboarding = mutation({
  args: { role: roleValidator },
  handler: async (ctx, { role }) => {
    const identity = await requireIdentity(ctx);
    if (await userByAuthId(ctx, identity.subject)) return; // already onboarded
    await ctx.db.insert("users", {
      authId: identity.subject,
      email: identity.email,
      name: identity.name,
      role,
      status: "active",
    });
  },
});

// Change an EXISTING active user's role. `role` is app-owned, so writing it is
// correct; `requireActiveUser` stops a suspended/deleted user from touching it.
// (Demo switcher — a real app would gate this on `requireRole(ctx, "admin")`.)
export const setMyRole = mutation({
  args: { role: roleValidator },
  handler: async (ctx, { role }) => {
    const user = await requireActiveUser(ctx);
    await ctx.db.patch(user._id, { role });
  },
});

// The payload the /admin page shows. `requireRole` throws "forbidden" for anyone
// who isn't an active admin — enforced on the server regardless of the client UI.
export const adminStats = query({
  handler: async (ctx) => {
    await requireRole(ctx, "admin");
    const all = await ctx.db.query("users").collect();
    return {
      total: all.length,
      admins: all.filter((u) => u.role === "admin").length,
      users: all.filter((u) => u.role === "user").length,
      active: all.filter((u) => u.status === "active").length,
    };
  },
});
