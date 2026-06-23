// Type-level coverage for `logtoSync`. Named `.test-d.ts` so `tsc --noEmit`
// (the `check-types` script) type-checks it, while `vitest run` and the tsup
// build both ignore it. The point: the `ctx as GenericMutationCtx<DataModel>`
// cast inside logtoSync must keep `ctx.db` typed to the caller's DataModel —
// a refactor that degrades it to `any` makes the @ts-expect-error below unused,
// and `tsc` then fails.
import { defineSchema, defineTable } from "convex/server";
import type { DataModelFromSchemaDefinition } from "convex/server";
import { v } from "convex/values";
import { expectTypeOf } from "vitest";
import { logtoSync } from "./webhooks";
import type { LogtoUserEntity, LogtoWebhookPayload } from "./webhooks";

// A concrete DataModel, shaped like a user's generated `convex/_generated/dataModel`.
const schema = defineSchema({
  users: defineTable({ authId: v.string() }).index("by_authId", ["authId"]),
});
type DataModel = DataModelFromSchemaDefinition<typeof schema>;

logtoSync<DataModel>({
  "User.Data.Updated": async (ctx, user, payload) => {
    // A table in the DataModel is queryable...
    void ctx.db.query("users");
    // ...and one that isn't is a type error. If `ctx.db` ever degrades to `any`,
    // this stops erroring and the directive goes unused → `tsc` fails.
    // @ts-expect-error — "posts" is not a table in this DataModel
    void ctx.db.query("posts");

    expectTypeOf(user).toEqualTypeOf<LogtoUserEntity>();
    expectTypeOf(payload).toEqualTypeOf<LogtoWebhookPayload>();
  },
});
