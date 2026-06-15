// Two things live here:
//   1. `config` — serves the public { endpoint, appId } to the frontend (the
//      `configQuery` prop on <ConvexLogtoProvider>).
//   2. `sync`   — the Logto → Convex user mirror (the "C" pattern). Registered as
//      a webhook in `http.ts`. One-way and read-only; it never writes to Logto.
import {
  logtoConfigQuery,
  logtoSync,
  type LogtoSyncHandler,
} from "convex-logto";
import type { DataModel } from "./_generated/dataModel";
import { userByAuthId } from "./authz";

export const config = logtoConfigQuery();

// THE RULE: webhooks may write only Logto-owned fields — email, name, and the
// `status` lifecycle (active/suspended). They must never touch `role`, which is
// app-owned; otherwise a Logto profile edit (`User.Data.Updated`) would reset
// everyone's role to the default.
//
// Mirror only the fields the event actually carries: present → set it (a `null`
// clears it), absent → leave it. So a profile edit can clear an email, while a
// suspension event (which carries only id + isSuspended) won't wipe name/email.
const syncedFields = (u: {
  primaryEmail?: string | null;
  name?: string | null;
  isSuspended?: boolean;
}) => ({
  ...(u.primaryEmail !== undefined ? { email: u.primaryEmail ?? undefined } : {}),
  ...(u.name !== undefined ? { name: u.name ?? undefined } : {}),
  ...(u.isSuspended !== undefined
    ? { status: u.isSuspended ? ("suspended" as const) : ("active" as const) }
    : {}),
});

// The webhook only SYNCS rows that already exist — it never creates them. Rows are
// created by an authenticated mutation (`completeOnboarding` in users.ts), because
// `User.Created` doesn't fire for users who already existed in Logto, and a
// webhook-created row would have to invent the app-owned `role`. No row yet → there's
// nothing to sync; the user's next authenticated visit creates it.
const syncRow: LogtoSyncHandler<DataModel> = async (ctx, u) => {
  const row = await userByAuthId(ctx, u.id);
  if (!row || row.status === "deleted") return; // nothing to sync / don't resurrect a tombstone
  await ctx.db.patch(row._id, syncedFields(u)); // Logto-owned fields only; role untouched
};

// Soft delete: scrub the synced PII but keep the row (status "deleted") so authz
// stays fail-closed and rows that reference this user by id don't dangle. Logto's
// `User.Deleted` carries no entity (just the id in the route params), so `u` here
// is the minimal `{ id }` the package normalizes it to.
const tombstone: LogtoSyncHandler<DataModel> = async (ctx, u) => {
  const row = await userByAuthId(ctx, u.id);
  if (row) {
    await ctx.db.patch(row._id, {
      status: "deleted",
      email: undefined,
      name: undefined,
    });
  }
};

// Subscribe to changes, not creation: the token seeds a new user's email/name at
// onboarding, and these keep them fresh afterward. (A `User.Created` delivery, if
// Logto sends one, simply no-ops — there's no row to sync yet.)
export const { sync } = logtoSync<DataModel>({
  "User.Data.Updated": syncRow,
  "User.SuspensionStatus.Updated": syncRow,
  "User.Deleted": tombstone,
});
