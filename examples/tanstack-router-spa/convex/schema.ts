import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

// One row per Logto user. Fields by OWNER — this split is the whole point:
//   - Logto-owned (email, name, status): the webhook in `logto.ts` keeps these in
//     sync. `status` is the Logto lifecycle — active / suspended, plus "deleted"
//     written as a tombstone on User.Deleted.
//   - App-owned (role): only your own mutations set this; the webhook never touches
//     it, so editing a Logto profile can't reset someone's role.
export default defineSchema({
  users: defineTable({
    authId: v.string(), // == identity.subject (the Logto user id)
    email: v.optional(v.string()), // Logto-owned
    name: v.optional(v.string()), // Logto-owned
    role: v.union(v.literal("user"), v.literal("admin")), // app-owned (RBAC)
    status: v.union(
      v.literal("active"),
      v.literal("suspended"),
      v.literal("deleted"),
    ), // Logto-owned lifecycle ("deleted" is a tombstone, not a row removal)
  }).index("by_authId", ["authId"]),
});
