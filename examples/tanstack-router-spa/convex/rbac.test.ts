/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import schema from "./schema";
import { api, internal } from "./_generated/api";

// convex-test needs every convex module so function references resolve in-process.
const modules = import.meta.glob("./**/*.*s");
const makeT = () => convexTest(schema, modules);
type TestT = ReturnType<typeof makeT>;

// A token identity for someone who already exists in Logto. `subject` is the
// stable Logto user id (== what `getUserIdentity().subject` returns).
const ALICE = { subject: "logto|alice", email: "alice@example.com", name: "Alice" };

// A Logto webhook delivery for the user-sync mutation (`internal.logto.sync`).
// `data` is the User entity for create/update/suspension, but `null` for
// `User.Deleted` — there the id rides in the Management API route `params`, passed
// via `extra`.
const hook = (
  event: string,
  data: Record<string, unknown> | null,
  extra: Record<string, unknown> = {},
) => ({
  payload: {
    hookId: "h",
    event,
    createdAt: "2026-01-01T00:00:00.000Z",
    data,
    ...extra,
  },
});

const rowFor = (t: TestT, authId: string) =>
  t.run((ctx) =>
    ctx.db
      .query("users")
      .withIndex("by_authId", (q) => q.eq("authId", authId))
      .unique(),
  );

describe("RBAC example", () => {
  test("a user who already exists in Logto still gets a row on first sign-in", async () => {
    const t = makeT();
    const asAlice = t.withIdentity(ALICE);

    // Signed in (valid token) but brand new to THIS app: no row yet.
    expect(await asAlice.query(api.users.myProfile)).toEqual({ onboarded: false });

    // The onboarding mutation creates the row FROM THE LOGGED-IN STATE — it never
    // waits on a `User.Created` webhook (which won't fire for a pre-existing user).
    await asAlice.mutation(api.users.completeOnboarding, { role: "user" });

    expect(await asAlice.query(api.users.myProfile)).toMatchObject({
      onboarded: true,
      role: "user",
      status: "active",
    });
  });

  test("non-admins are denied admin-only data; admins are allowed", async () => {
    const t = makeT();
    const asAlice = t.withIdentity(ALICE);

    await asAlice.mutation(api.users.completeOnboarding, { role: "user" });
    await expect(asAlice.query(api.users.adminStats)).rejects.toThrow("forbidden");

    await asAlice.mutation(api.users.setMyRole, { role: "admin" });
    expect(await asAlice.query(api.users.adminStats)).toMatchObject({ admins: 1 });
  });

  test("a signed-in user with no row is denied admin data", async () => {
    const t = makeT();
    await expect(
      t.withIdentity({ subject: "logto|nobody" }).query(api.users.adminStats),
    ).rejects.toThrow("forbidden");
  });

  test("the webhook never creates a row — only an authenticated mutation does", async () => {
    const t = makeT();

    // A sync event for a user who hasn't onboarded: nothing to sync, no row created.
    await t.mutation(
      internal.logto.sync,
      hook("User.Data.Updated", {
        id: ALICE.subject,
        primaryEmail: ALICE.email,
        name: ALICE.name,
      }),
    );
    expect(await rowFor(t, ALICE.subject)).toBeNull();

    // Onboarding (authenticated) is the sole creator.
    await t
      .withIdentity(ALICE)
      .mutation(api.users.completeOnboarding, { role: "user" });
    expect(await rowFor(t, ALICE.subject)).toMatchObject({
      role: "user",
      status: "active",
    });
  });

  test("a Logto profile edit (webhook) never resets an app-owned role", async () => {
    const t = makeT();
    const asAlice = t.withIdentity(ALICE);
    await asAlice.mutation(api.users.completeOnboarding, { role: "admin" });

    await t.mutation(
      internal.logto.sync,
      hook("User.Data.Updated", {
        id: ALICE.subject,
        name: "Alice Renamed",
        primaryEmail: ALICE.email,
      }),
    );

    expect(await asAlice.query(api.users.myProfile)).toMatchObject({
      onboarded: true,
      role: "admin", // still admin — the webhook only wrote name/email
      name: "Alice Renamed",
    });
  });

  test("suspension flips status: admin denied, profile hides PII (but row keeps it)", async () => {
    const t = makeT();
    const asAlice = t.withIdentity(ALICE);
    await asAlice.mutation(api.users.completeOnboarding, { role: "admin" });

    // Suspension events carry only id + isSuspended — name/email must survive.
    await t.mutation(
      internal.logto.sync,
      hook("User.SuspensionStatus.Updated", {
        id: ALICE.subject,
        isSuspended: true,
      }),
    );

    await expect(asAlice.query(api.users.adminStats)).rejects.toThrow("forbidden");
    expect(await asAlice.query(api.users.myProfile)).toMatchObject({
      onboarded: true,
      status: "suspended",
      email: null, // hidden from an inactive account…
      name: null,
    });
    expect(await rowFor(t, ALICE.subject)).toMatchObject({
      email: ALICE.email, // …but suspension doesn't scrub the row (only deletion does)
    });
  });

  test("deletion tombstones the row: PII scrubbed, authz fails closed", async () => {
    const t = makeT();
    const asAlice = t.withIdentity(ALICE);
    await asAlice.mutation(api.users.completeOnboarding, { role: "admin" });

    // Real `User.Deleted` shape: `data` is null; the id is in the route params
    // (`DELETE /users/:userId`), NOT in `data.id`.
    await t.mutation(
      internal.logto.sync,
      hook("User.Deleted", null, { params: { userId: ALICE.subject } }),
    );

    const row = await rowFor(t, ALICE.subject);
    expect(row?.status).toBe("deleted");
    expect(row?.email).toBeUndefined();
    expect(row?.name).toBeUndefined();

    await expect(asAlice.query(api.users.adminStats)).rejects.toThrow("forbidden");
  });

  test("a webhook that pins down no user id is rejected", async () => {
    const t = makeT();
    // `User.Deleted` with neither `data` nor a `params.userId` can't name a user.
    await expect(
      t.mutation(internal.logto.sync, hook("User.Deleted", null)),
    ).rejects.toThrow();
  });

  test("a delete resolves its user from params even if data is a stray {}", async () => {
    const t = makeT();
    const asAlice = t.withIdentity(ALICE);
    await asAlice.mutation(api.users.completeOnboarding, { role: "user" });

    // Defensive: a malformed delete with an id-less `data: {}` must still tombstone
    // via `params.userId`, never dispatch an id-less user that silently no-ops.
    await t.mutation(
      internal.logto.sync,
      hook("User.Deleted", {}, { params: { userId: ALICE.subject } }),
    );
    expect((await rowFor(t, ALICE.subject))?.status).toBe("deleted");
  });
});
